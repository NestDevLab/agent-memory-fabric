import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, MemoryCatalog, MemoryRawStore, SqliteCatalog, createFabricStoreFromEnv, identityPairLockKey } from '../src/fabric-store.mjs';
import { addCalendarYears, retentionDeadline } from '../src/identity-retention.mjs';

const proofByType = {
  verified_account: marker => ({ provider: 'test-idp', accountId: `account-${marker}`, verificationId: `verify-${marker}` }),
  cryptographic_binding: marker => ({ algorithm: 'ed25519', keyFingerprint: `fingerprint-${marker}`, challengeHash: `challenge-${marker}`, signature: `signature-${marker}` }),
  operator_attestation: marker => ({ ticketId: `ticket-${marker}`, assertion: `assertion-${marker}` }),
  weak_observation: marker => ({ observation: `observation-${marker}` })
};
const evidence = (type = 'operator_attestation', marker = 'same') => ({ type, issuer: 'test-operator', observedAt: '2026-07-11T12:00:00.000Z', claims: proofByType[type](marker) });

function fixture(options = {}) {
  let id = 0;
  const catalog = options.catalog || new MemoryCatalog();
  const rawStore = new MemoryRawStore({ encryptionKey: '9'.repeat(64) });
  const store = new FabricStore({
    rawStore,
    catalog,
    clock: options.clock || (() => new Date('2026-07-11T12:00:00.000Z')),
    idFactory: () => `amf-${++id}`,
    identityPolicy: options.identityPolicy,
    retentionPolicy: options.retentionPolicy
  });
  return { store, catalog, rawStore };
}

async function create(store, externalKey, scope = 'person:test', idempotencyKey = `create-${externalKey}`) {
  return store.createIdentity({ actor: 'curator', kind: 'person', externalKey, scope, evidence: evidence(), idempotencyKey });
}

test('identity creation and evidence replay are versioned, opaque and idempotent', async () => {
  const { store, catalog, rawStore } = fixture();
  const first = await create(store, 'email:alice@example.test');
  const replay = await create(store, 'email:alice@example.test');
  assert.equal(first.revision, 1);
  assert.equal(replay.id, first.id);
  assert.equal(replay.duplicate, true);
  assert.equal(catalog.identityEvents.length, 1);
  assert.equal(rawStore.blobs.size, 1);
  assert.equal(JSON.stringify([...catalog.identities.values()]).includes('alice@example.test'), false);
  assert.equal(JSON.stringify(catalog.identityEvents).includes('test-operator'), false);
  await assert.rejects(
    store.createIdentity({ actor: 'curator', kind: 'person', externalKey: 'other', scope: 'person:test', evidence: evidence('operator_attestation', 'changed'), idempotencyKey: 'create-email:alice@example.test' }),
    error => error.message === 'idempotency_key_conflict' && error.status === 409
  );
});

test('evidence schemas are finite per type and caller cannot declare strength', async () => {
  const { store } = fixture({ identityPolicy: { allowAutomaticStrongMerge: true } });
  await assert.rejects(store.createIdentity({ actor: 'curator', kind: 'person', externalKey: 'bad-type', scope: 'person:test', evidence: { ...evidence(), type: 'magic_match' }, idempotencyKey: 'bad-type' }), /identity_evidence_type_invalid/);
  await assert.rejects(store.createIdentity({ actor: 'curator', kind: 'person', externalKey: 'missing-proof', scope: 'person:test', evidence: { ...evidence(), claims: { ticketId: 'only-one' } }, idempotencyKey: 'missing-proof' }), /identity_evidence_invalid/);
  const source = await create(store, 'strength-source');
  const target = await create(store, 'strength-target');
  await assert.rejects(store.mergeIdentity(source.id, { actor: 'curator', scope: 'person:test', targetId: target.id, expectedRevision: 1, evidence: evidence('verified_account'), automatic: true, strongEvidence: true, idempotencyKey: 'forged-strength' }), /identity_merge_invalid/);
});

test('automatic merge requires both strong evidence and explicit policy, and never crosses scopes', async () => {
  const disabled = fixture();
  const a = await create(disabled.store, 'a');
  const b = await create(disabled.store, 'b');
  await assert.rejects(disabled.store.mergeIdentity(a.id, {
    actor: 'curator', scope: 'person:test', targetId: b.id, expectedRevision: 1, evidence: evidence('verified_account'), automatic: true, idempotencyKey: 'merge-disabled'
  }), /identity_auto_merge_forbidden/);

  const enabled = fixture({ identityPolicy: { allowAutomaticStrongMerge: true } });
  const source = await create(enabled.store, 'source');
  const target = await create(enabled.store, 'target');
  await assert.rejects(enabled.store.mergeIdentity(source.id, {
    actor: 'curator', scope: 'person:test', targetId: target.id, expectedRevision: 1, evidence: evidence('weak_observation'), automatic: true, idempotencyKey: 'merge-weak'
  }), /identity_auto_merge_forbidden/);
  const otherScope = await create(enabled.store, 'other', 'person:other');
  await assert.rejects(enabled.store.mergeIdentity(source.id, {
    actor: 'curator', scope: 'person:test', targetId: otherScope.id, expectedRevision: 1, evidence: evidence(), automatic: false, idempotencyKey: 'merge-cross-scope'
  }), error => error.message === 'identity_not_found' && error.status === 404);
});

test('merge and split are reversible, append-only, replay-safe and revision-race safe', async () => {
  const { store, catalog } = fixture({ identityPolicy: { allowAutomaticStrongMerge: true } });
  const source = await create(store, 'source');
  const target = await create(store, 'target');
  const mergeInput = { actor: 'curator', scope: 'person:test', targetId: target.id, expectedRevision: 1, evidence: evidence('cryptographic_binding'), automatic: true, idempotencyKey: 'merge-1' };
  const merged = await store.mergeIdentity(source.id, mergeInput);
  const replay = await store.mergeIdentity(source.id, mergeInput);
  assert.equal(merged.status, 'merged');
  assert.equal(merged.canonicalIdentityId, target.id);
  assert.equal(merged.revision, 2);
  assert.equal(replay.duplicate, true);

  const splitInput = { actor: 'curator', scope: 'person:test', expectedRevision: 2, evidence: evidence(), idempotencyKey: 'split-1' };
  const split = await store.splitIdentity(source.id, splitInput);
  assert.equal(split.status, 'active');
  assert.equal(split.canonicalIdentityId, null);
  assert.equal(split.revision, 3);
  assert.deepEqual(catalog.identityEvents.map(row => row.operation), ['create', 'create', 'merge', 'split']);
  const oldReplay = await store.mergeIdentity(source.id, mergeInput);
  assert.deepEqual(
    { status: oldReplay.status, canonicalIdentityId: oldReplay.canonicalIdentityId, revision: oldReplay.revision },
    { status: 'merged', canonicalIdentityId: target.id, revision: 2 },
    'replay returns the immutable original event response, not current identity state'
  );

  const races = await Promise.allSettled([
    store.mergeIdentity(source.id, { ...mergeInput, expectedRevision: 3, automatic: false, idempotencyKey: 'race-a' }),
    store.mergeIdentity(source.id, { ...mergeInput, expectedRevision: 3, automatic: false, idempotencyKey: 'race-b' })
  ]);
  assert.equal(races.filter(row => row.status === 'fulfilled').length, 1);
  assert.equal(races.filter(row => row.status === 'rejected' && row.reason.message === 'revision_conflict').length, 1);
});

test('merge rejects cross-kind targets and reciprocal lock keys are direction-independent', async () => {
  const { store } = fixture();
  const source = await create(store, 'kind-source');
  const target = await store.createIdentity({ actor: 'curator', kind: 'agent', externalKey: 'kind-target', scope: 'person:test', evidence: evidence(), idempotencyKey: 'kind-target' });
  await assert.rejects(store.mergeIdentity(source.id, { actor: 'curator', scope: 'person:test', targetId: target.id, expectedRevision: 1, evidence: evidence(), automatic: false, idempotencyKey: 'cross-kind' }), error => error.message === 'identity_not_found' && error.status === 404);
  const forward = identityPairLockKey(source.id, target.id);
  assert.equal(forward, identityPairLockKey(target.id, source.id));
  assert.match(forward, /^[a-f0-9]{64}$/, 'pair lock key must be canonical PostgreSQL-safe text');
  assert.equal(forward.includes('\u0000'), false);
});

test('identity reads hide cross-scope existence', async () => {
  const { store } = fixture();
  const identity = await create(store, 'private', 'person:private');
  await assert.rejects(store.readIdentityAuthorized(identity.id, { allowedScopes: ['person:other'] }), error => error.message === 'identity_not_found' && error.status === 404);
  assert.equal((await store.readIdentityAuthorized(identity.id, { allowedScopes: ['person:private'] })).revision, 1);
});

test('three-year retention uses calendar boundaries including leap day and supports scope overrides', () => {
  assert.equal(addCalendarYears('2024-02-29T10:30:00.000Z', 3), '2027-02-28T10:30:00.000Z');
  assert.equal(retentionDeadline('2026-07-11T12:00:00.000Z', 'shared'), '2029-07-11T12:00:00.000Z');
  assert.equal(retentionDeadline('2026-07-11T12:00:00.000Z', 'room:short', { scopeDays: { 'room:short': 30 } }), '2026-08-10T12:00:00.000Z');
});

test('timestamps require real RFC3339 UTC values and reject Date.parse coercions', async () => {
  const { store } = fixture();
  for (const observedAt of ['0', '2026-07-11T12:00:00+00:00', '2026-02-30T12:00:00Z']) {
    await assert.rejects(store.createIdentity({ actor: 'curator', kind: 'person', externalKey: observedAt, scope: 'person:test', evidence: { ...evidence(), observedAt }, idempotencyKey: `bad-${observedAt}` }), /identity_evidence_timestamp_invalid/);
  }
  await assert.rejects(store.propose({ actor: 'vitae', scope: 'shared', text: 'bad timestamp', metadata: { originalTimestamp: '0' }, idempotencyKey: 'bad-original' }), /original_timestamp_invalid/);
  await assert.rejects(store.planRetention({ asOf: '0', limit: 10 }, { allowedScopes: ['shared'] }), /retention_as_of_invalid/);
});

test('retention plans at the exact boundary and apply preserves tombstone without physical deletion', async () => {
  const { store, catalog, rawStore } = fixture();
  const proposal = await store.propose({ actor: 'vitae', scope: 'room:test', text: 'expiring', metadata: { originalTimestamp: '2023-07-11T12:00:00.000Z', nativePointer: 'native://session/1' }, idempotencyKey: 'retention-1' });
  assert.equal((await store.planRetention({ asOf: '2026-07-11T11:59:59.999Z', limit: 10 }, { allowedScopes: ['room:test'] })).candidates.length, 0);
  const plan = await store.planRetention({ asOf: '2026-07-11T12:00:00.000Z', limit: 10 }, { allowedScopes: ['room:test'] });
  assert.equal(plan.candidates.length, 1);
  const applied = await store.applyRetention({ actor: 'curator', idempotencyKey: 'expire-1', candidateIds: [proposal.contentId], expectedPlanAsOf: plan.asOf, reason: 'retention_expired' }, { allowedScopes: ['room:test'] });
  assert.equal(applied.physicalDeletionPerformed, false);
  assert.equal(applied.results[0].gcCandidate, true, 'transaction retires matching references before proving candidacy');
  assert.equal(rawStore.blobs.has(proposal.contentId), true);
  await assert.rejects(store.readProposal(proposal.id), /memory_not_found/);
  const tombstone = [...catalog.retentionTombstones.values()][0];
  assert.equal(tombstone.contentChecksum, proposal.contentId);
  assert.ok(tombstone.sourcePointerTag);
  assert.equal(JSON.stringify(tombstone).includes('native://session/1'), false);
  rawStore.keyRing.keys.set('rotated', Buffer.from('8'.repeat(64), 'hex'));
  rawStore.keyRing.currentKeyId = 'rotated';
  const replay = await store.applyRetention({ actor: 'curator', idempotencyKey: 'expire-1', candidateIds: [proposal.contentId], expectedPlanAsOf: plan.asOf, reason: 'retention_expired' }, { allowedScopes: ['room:test'] });
  assert.deepEqual(replay, applied, 'retention retry remains byte-equivalent across key rotation');
  await assert.rejects(store.applyRetention({ actor: 'curator', idempotencyKey: 'expire-1', candidateIds: [proposal.contentId], expectedPlanAsOf: plan.asOf, reason: 'revoked' }, { allowedScopes: ['room:test'] }), /idempotency_key_conflict/);
});

test('retention reconciles an ambiguous commit using its immutable operation record', async () => {
  class AmbiguousCatalog extends MemoryCatalog {
    applyRetention(input) {
      const result = super.applyRetention(input);
      const error = new Error('catalog_unavailable');
      error.status = 503;
      error.catalogTransactionOutcome = 'ambiguous_commit';
      throw error;
    }
  }
  const { store } = fixture({ catalog: new AmbiguousCatalog() });
  const proposal = await store.propose({ actor: 'vitae', scope: 'shared', text: 'ambiguous', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' }, idempotencyKey: 'ambiguous-source' });
  const input = { actor: 'curator', idempotencyKey: 'ambiguous-retention', candidateIds: [proposal.contentId], expectedPlanAsOf: '2026-07-11T12:00:00.000Z', reason: 'retention_expired' };
  const reconciled = await store.applyRetention(input, { allowedScopes: ['shared'] });
  assert.equal(reconciled.results.length, 1);
  assert.deepEqual(await store.applyRetention(input, { allowedScopes: ['shared'] }), reconciled);
});

test('post-backend recall defense removes revoked, merged and unknown explicit references', async () => {
  const { store } = fixture();
  const proposal = await store.propose({ actor: 'vitae', scope: 'shared', text: 'revoked secret', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' }, idempotencyKey: 'recall-proposal' });
  const source = await create(store, 'recall-source', 'shared');
  const target = await create(store, 'recall-target', 'shared');
  await store.mergeIdentity(source.id, { actor: 'curator', scope: 'shared', targetId: target.id, expectedRevision: 1, evidence: evidence(), automatic: false, idempotencyKey: 'recall-merge' });
  await store.applyRetention({ actor: 'curator', idempotencyKey: 'recall-revoke', candidateIds: [proposal.contentId], expectedPlanAsOf: '2026-07-11T12:00:00.000Z', reason: 'revoked' }, { allowedScopes: ['shared'] });
  const safe = { id: 'legacy-safe', memory: 'safe legacy' };
  const visible = await store.filterRecallItems([
    safe,
    { id: 'leak-proposal', memory: 'secret proposal', proposalId: proposal.id },
    { id: 'leak-content', memory: 'secret content', metadata: { contentId: proposal.contentId } },
    { id: 'leak-identity', memory: 'merged identity', identityId: source.id },
    { id: 'active-identity', memory: 'active identity', identityId: target.id },
    { id: 'unknown', memory: 'unknown reference', proposalId: 'unknown' }
  ], { allowedScopes: ['shared'] });
  assert.deepEqual(visible.map(item => item.id), ['legacy-safe', 'active-identity']);
});

test('shared content references and scope isolation prevent unsafe GC candidates', async () => {
  const { store, catalog } = fixture();
  const base = { actor: 'vitae', scope: 'shared', text: 'same raw', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' } };
  const first = await store.propose({ ...base, idempotencyKey: 'shared-a' });
  const second = await store.propose({ ...base, idempotencyKey: 'shared-b' });
  assert.equal(first.contentId, second.contentId);
  const denied = await store.applyRetention({ actor: 'curator', idempotencyKey: 'forget-denied', candidateIds: [first.contentId], expectedPlanAsOf: '2030-01-01T00:00:00.000Z', reason: 'forgotten' }, { allowedScopes: ['room:other'] });
  assert.equal(denied.results.length, 0);
  // Model a defensive cross-scope shared reference: applying one scope may not
  // retire a reference owned by another opaque scope.
  catalog.proposals.get(second.id).scopeTag = store.rawStore.opaqueTag('scope', 'room:other');
  const applied = await store.applyRetention({ actor: 'curator', idempotencyKey: 'forget-shared', candidateIds: [first.contentId], expectedPlanAsOf: '2030-01-01T00:00:00.000Z', reason: 'forgotten' }, { allowedScopes: ['shared'] });
  assert.equal(catalog.proposals.get(first.id).status, 'revoked');
  assert.equal(catalog.proposals.get(second.id).status, 'queued');
  assert.equal(applied.results[0].gcCandidate, false, 'cross-scope active reference blocks candidate');
});

test('catalog outage rolls back retention metadata and never deletes RAW', async () => {
  class OutageCatalog extends MemoryCatalog {
    applyRetention() { throw new Error('database_offline'); }
  }
  const { store, catalog, rawStore } = fixture({ catalog: new OutageCatalog() });
  const proposal = await store.propose({ actor: 'vitae', scope: 'shared', text: 'outage', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' }, idempotencyKey: 'outage' });
  await assert.rejects(store.applyRetention({ actor: 'curator', idempotencyKey: 'outage-retention', candidateIds: [proposal.contentId], expectedPlanAsOf: '2026-07-11T12:00:00.000Z', reason: 'retention_expired' }, { allowedScopes: ['shared'] }), /catalog_unavailable/);
  assert.equal(catalog.retention.get(proposal.contentId).lifecycle, 'active');
  assert.equal(rawStore.blobs.has(proposal.contentId), true);
});

test('SQLite preserves identity and retention semantics without plaintext catalog leakage', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-identity-sqlite-'));
  const databasePath = path.join(dir, 'catalog.sqlite');
  const catalog = new SqliteCatalog({ databasePath });
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: '7'.repeat(64) }), catalog, clock: () => new Date('2026-07-11T12:00:00.000Z') });
  try {
    const source = await store.createIdentity({ actor: 'curator-private', kind: 'person', externalKey: 'alice-private@example.test', scope: 'person:private', evidence: evidence(), idempotencyKey: 'sqlite-source' });
    const target = await store.createIdentity({ actor: 'curator-private', kind: 'person', externalKey: 'alice-second@example.test', scope: 'person:private', evidence: evidence(), idempotencyKey: 'sqlite-target' });
    const merged = await store.mergeIdentity(source.id, { actor: 'curator-private', scope: 'person:private', targetId: target.id, expectedRevision: 1, evidence: evidence(), automatic: false, idempotencyKey: 'sqlite-merge' });
    assert.equal(merged.revision, 2);
    const split = await store.splitIdentity(source.id, { actor: 'curator-private', scope: 'person:private', expectedRevision: 2, evidence: evidence(), idempotencyKey: 'sqlite-split' });
    assert.equal(split.status, 'active');

    const proposal = await store.propose({ actor: 'curator-private', scope: 'person:private', text: 'private raw', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z', nativePointer: 'native://private' }, idempotencyKey: 'sqlite-retention' });
    const applied = await store.applyRetention({ actor: 'curator-private', idempotencyKey: 'sqlite-revoke', candidateIds: [proposal.contentId], expectedPlanAsOf: '2030-01-01T00:00:00.000Z', reason: 'revoked' }, { allowedScopes: ['person:private'] });
    assert.equal(applied.results.length, 1);
    const database = fs.readFileSync(databasePath);
    for (const secret of ['alice-private@example.test', 'alice-second@example.test', 'curator-private', 'person:private', 'native://private', 'private raw']) {
      assert.equal(database.includes(Buffer.from(secret)), false, `${secret} leaked to SQLite`);
    }
  } finally {
    catalog.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lifecycle policy configuration is explicit, strict and defaults auto-merge off', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-lifecycle-policy-'));
  const policyPath = path.join(dir, 'retention.json');
  fs.writeFileSync(policyPath, JSON.stringify({ defaultYears: 4, scopeDays: { 'room:short': 7 } }));
  const base = { AMF_RAW_ENCRYPTION_KEY: '6'.repeat(64), AMF_DATA_PATH: 'data', AMF_CATALOG_KIND: 'sqlite', AMF_RETENTION_POLICY_PATH: policyPath };
  const store = createFabricStoreFromEnv({ rootPath: dir, env: base });
  try {
    assert.deepEqual(store.retentionPolicy, { defaultYears: 4, scopeDays: { 'room:short': 7 } });
    assert.equal(store.identityPolicy.allowAutomaticStrongMerge, false);
  } finally { await store.close(); }
  assert.throws(() => createFabricStoreFromEnv({ rootPath: dir, env: { ...base, AMF_IDENTITY_AUTO_MERGE_STRONG: 'sometimes' } }), /identity_policy_invalid/);
  fs.writeFileSync(policyPath, JSON.stringify({ defaultYears: 0, scopeDays: {} }));
  assert.throws(() => createFabricStoreFromEnv({ rootPath: dir, env: base }), /retention_policy_invalid/);
  fs.rmSync(dir, { recursive: true, force: true });
});
