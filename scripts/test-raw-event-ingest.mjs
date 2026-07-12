import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, FileRawStore, MemoryCatalog, MemoryRawStore, SqliteCatalog } from '../src/fabric-store.mjs';
import { ciphertextContentId } from '../src/ingest/raw-event-contract.mjs';
import { HttpRawEventSink } from '../src/ingest/http-raw-event-sink.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { parseClaudeRecord } from '../src/ingest/transcripts/claude.mjs';
import { createAgentMemoryFabricServer } from '../src/server.mjs';

const KEY = crypto.createHash('sha256').update('synthetic-ingest-key').digest('hex');
const KEY2 = crypto.createHash('sha256').update('synthetic-ingest-key-rotated').digest('hex');
const KEY_RING = { keys: { 'client-v1': KEY, 'client-v2': KEY2 }, digestKey: KEY, authorizations: {
  'client-v1': { actors: ['raw-owner'], sourceInstances: ['synthetic-host', 'other-host'] },
  'client-v2': { actors: ['raw-owner'], sourceInstances: ['synthetic-host'] }
} };
const RAW_OUTBOX = { encryptionKey: KEY, digestKey: KEY, sourceInstanceId: 'synthetic-host', actorId: 'raw-owner', keyId: 'client-v1' };

function syntheticItem(secret = 'SYNTHETIC_RAW_PRIVATE_TEXT') {
  const value = { type: 'user', uuid: 'raw-http-event', sessionId: 'raw-http-session', timestamp: '2026-07-12T00:00:00Z', message: { role: 'user', content: secret } };
  return parseClaudeRecord({ value, rawBytes: Buffer.from(JSON.stringify(value)), lineEnding: 'lf' });
}

async function withRawServer(run, { bodyReadTimeoutMs } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-server-'));
  const registryPath = path.join(root, 'auth.json');
  fs.writeFileSync(registryPath, JSON.stringify({ rows: [
    { token: 'ingest-token', active: true, actor: 'raw-owner', mode: 'allow_all', allowedScopes: '*', permissions: 'raw:ingest,sessions:read,raw:decrypt' },
    { token: 'reader-token', active: true, actor: 'raw-owner', mode: 'allow_all', allowedScopes: '*', permissions: 'sessions:read' },
    { token: 'denied-token', active: true, actor: 'raw-owner', mode: 'allow_all', allowedScopes: '*', permissions: 'sessions:read' },
    { token: 'attacker-token', active: true, actor: 'other-owner', mode: 'allow_all', allowedScopes: '*', permissions: 'raw:ingest' },
    { token: 'attacker-reader-token', active: true, actor: 'other-owner', mode: 'allow_all', allowedScopes: '*', permissions: 'sessions:read,raw:decrypt' }
  ] }));
  const previous = process.env.MEM0_AUTH_REGISTRY_PATH;
  process.env.MEM0_AUTH_REGISTRY_PATH = registryPath;
  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') });
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore, catalog, ingestKeyRing: KEY_RING });
  const server = createAgentMemoryFabricServer({ fabricStore: store, policyPath: '', bodyReadTimeoutMs });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const api = async (pathname, { token = 'ingest-token', ...options } = {}) => {
    const response = await fetch(`${baseUrl}${pathname}`, { ...options, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(options.headers || {}) } });
    const text = await response.text();
    return { response, body: text ? JSON.parse(text) : null };
  };
  try { await run({ root, baseUrl, api, store, rawStore, catalog }); }
  finally {
    await new Promise(resolve => server.close(resolve));
    if (previous === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH; else process.env.MEM0_AUTH_REGISTRY_PATH = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('HTTP ciphertext sink stores idempotently without sending RAW plaintext', async () => {
  await withRawServer(async ({ root, baseUrl, api, rawStore, catalog }) => {
    const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
    const item = syntheticItem();
    outbox.enqueue(item);
    const sink = new HttpRawEventSink({ endpoint: `${baseUrl}/v2/ingest/raw-events`, token: 'ingest-token', sourceInstanceId: 'synthetic-host', actorId: 'raw-owner', allowInsecureTest: true });
    const ack = await outbox.deliver(item.event.eventId, sink);
    assert.equal(ack.state, 'acknowledged');
    assert.equal(catalog.rawEvents.size, 1);
    assert.equal(rawStore.clientBlobs.size, 1);
    assert.equal(JSON.stringify([...catalog.rawEvents.values()]).includes('SYNTHETIC_RAW_PRIVATE_TEXT'), false);

    const reencrypter = new EncryptedOutbox({ rootPath: path.join(root, 'reencrypted'), ...RAW_OUTBOX });
    const body = { sourceInstanceId: 'synthetic-host', projection: item.projection, envelope: reencrypter.encrypt(item) };
    const duplicate = await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(body) });
    assert.equal(duplicate.response.status, 200);
    assert.equal(duplicate.body.data.status, 'duplicate');
    assert.equal(duplicate.body.data.idempotencyKey, item.event.eventId);
    assert.equal(catalog.auditEvents.filter(event => event.action === 'raw_event_ingest').length, 2);
    const rotated = new EncryptedOutbox({ rootPath: path.join(root, 'rotated'), encryptionKey: KEY2, digestKey: KEY, sourceInstanceId: 'synthetic-host', actorId: 'raw-owner', keyId: 'client-v2' });
    const rotationDuplicate = await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify({ ...body, envelope: rotated.encrypt(item) }) });
    assert.equal(rotationDuplicate.body.data.status, 'duplicate', 'stable digest survives encryption-key rotation');
  });
});

test('raw ingest rejects permission, projection/AAD drift, unavailable keys and event conflicts', async () => {
  await withRawServer(async ({ root, api, rawStore }) => {
    const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
    const item = syntheticItem();
    const envelope = outbox.encrypt(item);
    const body = { sourceInstanceId: 'synthetic-host', projection: item.projection, envelope };
    const denied = await api('/v2/ingest/raw-events', { token: 'denied-token', method: 'POST', body: JSON.stringify(body) });
    assert.equal(denied.response.status, 403);
    const stored = await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(body) });
    assert.equal(stored.response.status, 201);
    const stolen = await api('/v2/ingest/raw-events', { token: 'attacker-token', method: 'POST', body: JSON.stringify(body) });
    assert.equal(stolen.body.error.code, 'raw_envelope_binding_invalid');

    const extra = structuredClone(body); extra.projection.text = 'must-not-enter';
    assert.equal((await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(extra) })).body.error.code, 'raw_projection_invalid');
    const drift = structuredClone(body); drift.projection.role = 'assistant';
    assert.equal((await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(drift) })).body.error.code, 'raw_envelope_binding_invalid');
    const unknown = structuredClone(body); unknown.envelope.keyId = 'unknown';
    assert.equal((await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(unknown) })).body.error.code, 'raw_ingest_key_unavailable');
    const covert = structuredClone(body); covert.projection.subtype = 'private-secret-channel';
    assert.equal((await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(covert) })).body.error.code, 'raw_projection_invalid');
    const corrupted = structuredClone(body);
    const tag = Buffer.from(corrupted.envelope.tag, 'base64'); tag[0] ^= 1; corrupted.envelope.tag = tag.toString('base64');
    assert.equal((await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(corrupted) })).body.error.code, 'raw_envelope_authentication_failed');

    const changed = structuredClone(item);
    changed.event.raw.line = Buffer.from('{"changed":"SYNTHETIC_OTHER_PRIVATE"}').toString('base64');
    const conflict = await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify({ ...body, envelope: outbox.encrypt(changed) }) });
    assert.equal(conflict.response.status, 409);
    assert.equal(conflict.body.error.code, 'raw_event_conflict');

    const otherValue = { type: 'assistant', uuid: 'raw-http-event-other', sessionId: 'raw-http-session', message: { role: 'assistant', content: 'SYNTHETIC_SESSION_HIJACK' } };
    const otherItem = parseClaudeRecord({ value: otherValue, rawBytes: Buffer.from(JSON.stringify(otherValue)), lineEnding: 'lf' });
    const otherSource = new EncryptedOutbox({ rootPath: path.join(root, 'other-source'), encryptionKey: KEY, digestKey: KEY, sourceInstanceId: 'other-host', actorId: 'raw-owner', keyId: 'client-v1' });
    const blobsBeforeHijack = rawStore.clientBlobs.size;
    const hijack = await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify({ sourceInstanceId: 'other-host', projection: otherItem.projection, envelope: otherSource.encrypt(otherItem) }) });
    assert.equal(hijack.response.status, 409);
    assert.equal(hijack.body.error.code, 'raw_session_binding_conflict');
    assert.equal(rawStore.clientBlobs.size, blobsBeforeHijack, 'known session conflicts must be rejected before ciphertext commit');
  });
});

test('catalog session reader returns placeholders/redaction and decrypts original only after server permission', async () => {
  await withRawServer(async ({ root, api, catalog }) => {
    const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
    const item = syntheticItem();
    const body = { sourceInstanceId: 'synthetic-host', projection: item.projection, envelope: outbox.encrypt(item) };
    await api('/v2/ingest/raw-events', { method: 'POST', body: JSON.stringify(body) });

    const search = await api('/v2/sessions/search', { token: 'reader-token', method: 'POST', body: JSON.stringify({ query: 'claude', purpose: 'conversation_recall' }) });
    assert.equal(search.response.status, 200);
    assert.equal(search.body.data.items[0].title, 'claude session');
    const sessionId = item.projection.sessionId;
    const redacted = await api(`/v2/sessions/${sessionId}/transcript?purpose=conversation_recall`, { token: 'reader-token' });
    assert.equal(redacted.body.data.messages[0].content.redacted, true);
    assert.equal(JSON.stringify(redacted.body).includes('SYNTHETIC_RAW_PRIVATE_TEXT'), false);
    const forbidden = await api(`/v2/sessions/${sessionId}/transcript?view=original&purpose=incident_debug`, { token: 'reader-token' });
    assert.equal(forbidden.body.error.code, 'raw_decrypt_forbidden');
    const original = await api(`/v2/sessions/${sessionId}/transcript?view=original&purpose=incident_debug`);
    assert.equal(Buffer.from(original.body.data.messages[0].raw.line, 'base64').toString('utf8').includes('SYNTHETIC_RAW_PRIVATE_TEXT'), true);
    const attackerSearch = await api('/v2/sessions/search', { token: 'attacker-reader-token', method: 'POST', body: JSON.stringify({ query: '', purpose: 'conversation_recall' }) });
    assert.deepEqual(attackerSearch.body.data.items, []);
    const attackerGet = await api(`/v2/sessions/${sessionId}?purpose=incident_debug`, { token: 'attacker-reader-token' });
    assert.equal(attackerGet.response.status, 404);
    const attackerOriginal = await api(`/v2/sessions/${sessionId}/transcript?view=original&purpose=incident_debug`, { token: 'attacker-reader-token' });
    assert.equal(attackerOriginal.response.status, 404);
    assert.ok(catalog.auditEvents.some(event => event.action === 'session_transcript' && event.outcome === 'denied'));
    assert.ok(catalog.auditEvents.some(event => event.action === 'session_transcript' && event.outcome === 'allowed'));
  });
});

test('SQLite catalog stores only ciphertext and safe projection metadata', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-sqlite-'));
  const catalog = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  const store = new FabricStore({ rawStore: new MemoryRawStore(), catalog, ingestKeyRing: KEY_RING });
  const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
  const item = syntheticItem('SYNTHETIC_SQLITE_PRIVATE');
  try {
    await store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'synthetic-host', projection: item.projection, envelope: outbox.encrypt(item) });
    const bytes = fs.readFileSync(path.join(root, 'catalog.sqlite'));
    assert.equal(bytes.includes(Buffer.from('SYNTHETIC_SQLITE_PRIVATE')), false);
    assert.equal(bytes.includes(Buffer.from('raw-owner')), false);
    assert.equal(bytes.includes(Buffer.from('synthetic-host')), false);
    const sessions = await store.createSessionReader().search({ actor: 'raw-owner', query: '', limit: 10 });
    assert.equal(sessions.items.length, 1);
    assert.equal(JSON.stringify(sessions).includes('raw-owner'), false);
    assert.equal(JSON.stringify(sessions).includes('synthetic-host'), false);
  } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('HTTP sink is fail-closed unless endpoint, token and source instance are explicit', async () => {
  const sink = new HttpRawEventSink();
  await assert.rejects(sink.deliverCiphertext({}, { idempotencyKey: 'x' }), /raw_event_http_sink_unconfigured/);
  assert.throws(() => new HttpRawEventSink({ endpoint: 'http://example.test/v2/ingest/raw-events', token: 'x', sourceInstanceId: 'host', actorId: 'actor' }), /raw_event_http_endpoint_invalid/);
});

test('HTTP sink bounds and times out the complete streaming response body', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-http-response-'));
  const outbox = new EncryptedOutbox({ rootPath: root, ...RAW_OUTBOX });
  const item = syntheticItem();
  const payload = { projection: item.projection, envelope: outbox.encrypt(item) };
  try {
    const oversized = new HttpRawEventSink({
      endpoint: 'https://fabric.example.test/v2/ingest/raw-events', token: 'token', sourceInstanceId: 'synthetic-host', actorId: 'raw-owner', maxResponseBytes: 256,
      fetchImpl: async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(Buffer.from(`{"ok":true,"padding":"${'x'.repeat(300)}"}`)); controller.close(); } }), { status: 200 })
    });
    await assert.rejects(oversized.deliverCiphertext(payload, { idempotencyKey: item.projection.eventId }), error => error.message === 'raw_event_http_delivery_failed' && error.cause?.message === 'raw_event_http_response_too_large');

    const stalled = new HttpRawEventSink({
      endpoint: 'https://fabric.example.test/v2/ingest/raw-events', token: 'token', sourceInstanceId: 'synthetic-host', actorId: 'raw-owner', timeoutMs: 100,
      fetchImpl: async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(Buffer.from('{"ok":')); } }), { status: 200 })
    });
    const started = Date.now();
    await assert.rejects(stalled.deliverCiphertext(payload, { idempotencyKey: item.projection.eventId }), error => error.message === 'raw_event_http_delivery_failed' && error.cause?.message === 'raw_event_http_timeout');
    assert.ok(Date.now() - started < 1000);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('ingest event and durable audit roll back together on an audit constraint failure', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-atomic-'));
  const catalog = new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') });
  const collision = 'audit-collision';
  catalog.appendAudit({ id: collision, ts: '2026-07-12T00:00:00Z', actorTag: 'actor', action: 'seed', outcome: 'stored', details: {} });
  const store = new FabricStore({ rawStore: new MemoryRawStore(), catalog, ingestKeyRing: KEY_RING, idFactory: () => collision });
  const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
  const item = syntheticItem('SYNTHETIC_ATOMIC_PRIVATE');
  try {
    await assert.rejects(store.ingestRawEvent({ actor: 'raw-owner', sourceInstanceId: 'synthetic-host', projection: item.projection, envelope: outbox.encrypt(item) }), /catalog_unavailable/);
    assert.equal(catalog.getRawEvent(item.event.eventId), null);
    assert.equal(catalog.getSession(item.event.sessionId), null);
    assert.equal(catalog.status().auditEvents, 1);
  } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('central client ciphertext writes are durable, exclusive and verify EEXIST content', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-central-ciphertext-'));
  const rawStore = new FileRawStore({ rootPath: root, encryptionKey: crypto.randomBytes(32).toString('base64') });
  const outbox = new EncryptedOutbox({ rootPath: path.join(root, 'outbox'), ...RAW_OUTBOX });
  const envelope = outbox.encrypt(syntheticItem());
  const contentId = ciphertextContentId(envelope);
  try {
    assert.equal((await rawStore.commitClientCiphertext(contentId, envelope)).created, true);
    assert.equal((await rawStore.commitClientCiphertext(contentId, envelope)).created, false);
    const changed = { ...envelope, tag: Buffer.alloc(16, 9).toString('base64') };
    await assert.rejects(rawStore.commitClientCiphertext(contentId, changed), /raw_object_conflict/);
    const names = [];
    const walk = dir => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) entry.isDirectory() ? walk(path.join(dir, entry.name)) : names.push(entry.name); };
    walk(root);
    assert.equal(names.some(name => name.endsWith('.tmp')), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FileRawStore rejects symlinked root and nested parents without escaping', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-raw-symlink-'));
  const real = path.join(base, 'real');
  const external = path.join(base, 'external');
  fs.mkdirSync(real); fs.mkdirSync(external);
  const linkedRoot = path.join(base, 'linked-root');
  fs.symlinkSync(real, linkedRoot);
  try {
    assert.throws(() => new FileRawStore({ rootPath: path.join(linkedRoot, 'raw'), encryptionKey: KEY }), /raw_object_unsafe/);
    assert.equal(fs.existsSync(path.join(real, 'raw')), false);

    const storeRoot = path.join(base, 'store');
    const store = new FileRawStore({ rootPath: storeRoot, encryptionKey: KEY });
    fs.symlinkSync(external, path.join(storeRoot, 'client-events'));
    const outbox = new EncryptedOutbox({ rootPath: path.join(base, 'outbox'), ...RAW_OUTBOX });
    const envelope = outbox.encrypt(syntheticItem());
    await assert.rejects(store.commitClientCiphertext(ciphertextContentId(envelope), envelope), /raw_object_unsafe/);
    assert.deepEqual(fs.readdirSync(external), []);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('raw ingest request body times out before an incomplete JSON body can hold a worker', async () => {
  await withRawServer(async ({ baseUrl }) => {
    const url = new URL('/v2/ingest/raw-events', baseUrl);
    const result = await new Promise((resolve, reject) => {
      const request = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: 'POST', headers: { authorization: 'Bearer ingest-token', 'content-type': 'application/json', 'content-length': '1000' } }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => { request.destroy(); resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); });
      });
      request.on('error', reject);
      request.write('{"sourceInstanceId":"synthetic-host"');
    });
    assert.equal(result.status, 408);
    assert.equal(result.body.error.code, 'body_read_timeout');
  }, { bodyReadTimeoutMs: 100 });
});

test('Memory and SQLite normalize first/last timestamps, literal LIKE and search ordering', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-semantics-'));
  const catalogs = [new MemoryCatalog(), new SqliteCatalog({ databasePath: path.join(root, 'catalog.sqlite') })];
  const projection = (eventId, sessionId, occurredAt) => ({ schema: 'amf.raw-event-projection/v1', eventId, sessionId, runtime: 'claude', subtype: 'user', occurredAt, role: 'user', contentType: 'text', contentParts: 1, hasContent: true });
  try {
    for (const catalog of catalogs) {
      const events = [
        [`evt_${'1'.repeat(64)}`, `ses_${'a'.repeat(64)}`, '2026-07-12T12:00:00Z'],
        [`evt_${'2'.repeat(64)}`, `ses_${'a'.repeat(64)}`, '2026-07-12T10:00:00Z'],
        [`evt_${'3'.repeat(64)}`, `ses_${'b'.repeat(64)}`, '2026-07-12T13:00:00Z']
      ];
      events.forEach(([eventId, sessionId, occurredAt], index) => {
        const p = projection(eventId, sessionId, occurredAt);
        catalog.ingestRawEvent({ eventId, sessionId, contentId: String(index + 1).repeat(64), payloadDigest: `hmac-sha256:v1:${String(index + 4).repeat(64)}`, projection: p, ownerTag: 'owner-tag', sourceTag: 'source-tag', createdAt: `2026-07-12T0${index}:00:00Z` }, { contentId: String(index + 1).repeat(64), mediaType: 'cipher', byteLength: 1, storageRef: `${index}`, createdAt: `2026-07-12T0${index}:00:00Z` }, { id: `audit-${index}-${catalog.constructor.name}`, ts: occurredAt, actorTag: 'tag', action: 'raw_event_ingest', outcome: 'stored', targetId: eventId, details: {} });
      });
      const sessionA = catalog.getSession(`ses_${'a'.repeat(64)}`);
      assert.equal(sessionA.firstOccurredAt, '2026-07-12T10:00:00Z');
      assert.equal(sessionA.lastOccurredAt, '2026-07-12T12:00:00Z');
      assert.equal(catalog.searchSessions({ ownerTags: ['owner-tag'], query: '%_', limit: 10 }).length, 0);
      assert.equal(catalog.searchSessions({ ownerTags: ['owner-tag'], query: '', limit: 10 })[0].id, `ses_${'b'.repeat(64)}`);
    }
  } finally { catalogs[1].close(); fs.rmSync(root, { recursive: true, force: true }); }
});
