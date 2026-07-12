import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  FabricStore,
  FileRawStore,
  MemoryCatalog,
  MemoryRawStore,
  SqliteCatalog
} from '../src/fabric-store.mjs';

const fixedClock = () => new Date('2026-07-11T12:00:00.000Z');

test('memory fabric queues idempotently and rejects a reused key with different content', async () => {
  let id = 0;
  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore, catalog, clock: fixedClock, idFactory: () => `id-${++id}` });
  const input = {
    actor: 'vitae',
    scope: 'room:test',
    text: 'Francesco has an appointment.',
    metadata: { source: 'telegram' },
    infer: true,
    source: 'test',
    idempotencyKey: 'evt-1'
  };

  const first = await store.propose(input);
  const duplicate = await store.propose(input);

  assert.equal(first.status, 'queued');
  assert.equal(first.duplicate, false);
  assert.equal(duplicate.id, first.id);
  assert.equal(duplicate.duplicate, true);
  assert.equal(catalog.proposals.size, 1);

  await assert.rejects(
    store.propose({ ...input, text: 'Different fact' }),
    error => error.message === 'idempotency_key_conflict' && error.status === 409
  );
  assert.equal(rawStore.blobs.size, 1, 'idempotency conflicts must not orphan RAW objects');
});

test('parallel duplicate proposals create one catalog record and one RAW object', async () => {
  const rawStore = new MemoryRawStore();
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore, catalog });
  const input = { actor: 'vitae', scope: 'shared', text: 'one fact', idempotencyKey: 'parallel-1' };
  const results = await Promise.all(Array.from({ length: 20 }, () => store.propose(input)));
  assert.equal(new Set(results.map(result => result.id)).size, 1);
  assert.equal(results.filter(result => !result.duplicate).length, 1);
  assert.equal(catalog.proposals.size, 1);
  assert.equal(rawStore.blobs.size, 1);
});

test('failed creator never deletes content-addressed RAW referenced by another writer', async () => {
  let firstEntered;
  let releaseFirst;
  const firstAtCatalog = new Promise(resolve => { firstEntered = resolve; });
  const secondCommitted = new Promise(resolve => { releaseFirst = resolve; });
  class CoordinatedCatalog extends MemoryCatalog {
    calls = 0;
    async enqueueProposalWithRaw(record, rawRecord) {
      this.calls += 1;
      if (this.calls === 1) {
        firstEntered();
        await secondCommitted;
        throw new Error('first_writer_rolled_back');
      }
      const result = super.enqueueProposalWithRaw(record, rawRecord);
      releaseFirst();
      return result;
    }
  }

  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  const catalog = new CoordinatedCatalog();
  const firstStore = new FabricStore({ rawStore, catalog });
  const secondStore = new FabricStore({ rawStore, catalog });
  const base = { actor: 'vitae', scope: 'shared', text: 'same content across writers' };
  const failed = firstStore.propose({ ...base, idempotencyKey: 'writer-one' });
  await firstAtCatalog;
  const accepted = await secondStore.propose({ ...base, idempotencyKey: 'writer-two' });
  await assert.rejects(failed, /catalog_unavailable/);

  const catalogStillReferences = catalog.getProposal(accepted.id)?.contentId === accepted.contentId;
  const rawExists = rawStore.getEncryptedEnvelope(accepted.contentId) !== null;
  assert.equal(catalogStillReferences, true);
  assert.equal(rawExists, true);
  assert.equal((await secondStore.readProposal(accepted.id)).payload.text, base.text);
});

test('filesystem RAW store is content-addressed, encrypted at rest and decryptable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-'));
  const secret = 'a'.repeat(64);
  const payload = { type: 'memory-proposal', text: 'private appointment detail' };
  try {
    const rawStore = new FileRawStore({ rootPath: dir, encryptionKey: secret, keyId: 'test-key' });
    const first = await rawStore.put(payload);
    const duplicate = await rawStore.put(payload);
    const storedPath = path.join(dir, first.storageRef);
    const storedText = fs.readFileSync(storedPath, 'utf8');

    assert.match(first.contentId, /^[a-f0-9]{64}$/);
    assert.equal(first.contentId, duplicate.contentId);
    assert.equal(first.created, true);
    assert.equal(duplicate.created, false);
    assert.equal(storedText.includes(payload.text), false);
    assert.deepEqual(await rawStore.get(first.contentId), payload);

    const envelope = JSON.parse(storedText);
    envelope.keyId = 'unknown-key';
    fs.writeFileSync(storedPath, JSON.stringify(envelope));
    await assert.rejects(rawStore.get(first.contentId), /raw_key_unavailable/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('key ring rotation reads old blobs, writes with the current key, and authenticates AAD', async () => {
  const rawStore = new MemoryRawStore({
    keyRing: {
      currentKeyId: 'old',
      keys: { old: '1'.repeat(64), current: '2'.repeat(64) }
    }
  });
  const old = await rawStore.put({ text: 'old payload' });
  rawStore.keyRing.currentKeyId = 'current';
  const current = await rawStore.put({ text: 'new payload' });
  assert.equal(rawStore.getEncryptedEnvelope(old.contentId).keyId, 'old');
  assert.equal(rawStore.getEncryptedEnvelope(current.contentId).keyId, 'current');
  assert.deepEqual(await rawStore.get(old.contentId), { text: 'old payload' });

  rawStore.getEncryptedEnvelope(current.contentId).contentId = old.contentId;
  await assert.rejects(rawStore.get(current.contentId), /raw_content_id_mismatch/);
});

test('key ring rejects unsafe current and historical key ids before storage starts', () => {
  assert.throws(
    () => new MemoryRawStore({ keyRing: { currentKeyId: 'prod:v2', keys: { 'prod:v2': '1'.repeat(64) } } }),
    error => error.message === 'raw_key_id_invalid' && error.status === 500
  );
  assert.throws(
    () => new MemoryRawStore({ keyRing: { currentKeyId: 'current', keys: { current: '1'.repeat(64), 'old:v1': '2'.repeat(64) } } }),
    error => error.message === 'raw_key_id_invalid' && error.status === 500
  );
  assert.throws(
    () => new MemoryRawStore({ encryptionKey: '1'.repeat(64), keyId: 'prod:v2' }),
    error => error.message === 'raw_key_id_invalid' && error.status === 500
  );
});

test('RAW keys accept only canonical 32-byte hex or padded base64 encodings', () => {
  const bytes = crypto.randomBytes(32);
  assert.doesNotThrow(() => new MemoryRawStore({ encryptionKey: bytes.toString('hex') }));
  assert.doesNotThrow(() => new MemoryRawStore({ encryptionKey: bytes.toString('base64') }));
  for (const invalid of [
    bytes.toString('base64').replace(/=$/, ''),
    `${bytes.toString('base64')}=`,
    bytes.toString('base64url'),
    ` ${bytes.toString('base64')} trailing`,
    'a'.repeat(43) + '!'
  ]) {
    assert.throws(() => new MemoryRawStore({ encryptionKey: invalid }), /raw_encryption_key_invalid/);
  }
});

test('proposal idempotency remains stable when the active key rotates', async () => {
  const rawStore = new MemoryRawStore({ keyRing: { currentKeyId: 'old', keys: { old: '3'.repeat(64), current: '4'.repeat(64) } } });
  const store = new FabricStore({ rawStore, catalog: new MemoryCatalog() });
  const input = { actor: 'vitae', scope: 'shared', text: 'stable fact', idempotencyKey: 'rotation-event' };
  const first = await store.propose(input);
  rawStore.keyRing.currentKeyId = 'current';
  const duplicate = await store.propose(input);
  assert.equal(duplicate.id, first.id);
  assert.equal(duplicate.contentId, first.contentId);
  assert.equal(duplicate.duplicate, true);
  await assert.rejects(store.propose({ ...input, text: 'changed fact' }), /idempotency_key_conflict/);
});

test('proposal ownership cannot bypass current scope policy and denial happens before decrypt', async () => {
  const rawStore = new MemoryRawStore();
  const store = new FabricStore({ rawStore, catalog: new MemoryCatalog() });
  const proposal = await store.propose({ actor: 'vitae', scope: 'room:test', text: 'private fact', idempotencyKey: 'policy-event' });
  let decryptions = 0;
  const originalGet = rawStore.get.bind(rawStore);
  rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };

  await assert.rejects(
    store.readProposalAuthorized(proposal.id, { actor: 'vitae', allowedScopes: [], allowAll: false }),
    error => error.message === 'memory_not_found' && error.status === 404
  );
  await assert.rejects(
    store.getProposalStatusAuthorized(proposal.id, { actor: 'vitae', allowedScopes: [], allowAll: false }),
    error => error.message === 'memory_not_found' && error.status === 404
  );
  assert.equal(decryptions, 0);
});

test('sqlite catalog persists RAW metadata, proposals and audit without plaintext payloads', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-catalog-'));
  const databasePath = path.join(dir, 'catalog.sqlite');
  const rawStore = new FileRawStore({ rootPath: path.join(dir, 'raw'), encryptionKey: 'b'.repeat(64), keyId: 'test-key' });
  const catalog = new SqliteCatalog({ databasePath });
  const store = new FabricStore({ rawStore, catalog, clock: fixedClock, idFactory: () => crypto.randomUUID() });
  try {
    const proposal = await store.propose({
      actor: 'vitae',
      scope: 'person:francesco',
      text: 'plaintext must not enter catalog',
      idempotencyKey: 'evt-sqlite',
      source: 'test'
    });
    await store.audit({ actor: 'vitae', action: 'memory_propose', outcome: 'queued', targetId: proposal.id, scope: proposal.scope });

    assert.equal(catalog.status().rawObjects, 1);
    assert.equal(catalog.status().queuedProposals, 1);
    assert.equal(catalog.status().auditEvents, 1);
    const databaseBytes = fs.readFileSync(databasePath);
    for (const secret of ['plaintext must not enter catalog', 'vitae', 'person:francesco', 'evt-sqlite', 'test']) {
      assert.equal(databaseBytes.includes(Buffer.from(secret)), false, `${secret} leaked into catalog`);
    }
    assert.equal((await store.readProposal(proposal.id)).payload.text, 'plaintext must not enter catalog');
  } finally {
    catalog.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
