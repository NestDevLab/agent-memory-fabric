import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';

import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { createConversationEventV3IngestHandler } from '../src/ingest/http-conversation-event-v3-endpoint.mjs';
import { ConversationEventV3HttpRequestVerifier, ConversationEventV3ReplayVerifier, HttpConversationEventV3Sink } from '../src/ingest/http-conversation-event-v3-sink.mjs';
import { createAgentMemoryFabricServer } from '../src/server.mjs';
import { FabricStore, MemoryCatalog, MemoryRawStore } from '../src/fabric-store.mjs';

const KEY = Buffer.alloc(32, 4);
const TAG = `hmac-sha256:test:${'1'.repeat(64)}`;
const NOW = Date.parse('2026-01-02T03:04:07Z');
const openRequests = new Set();

function active({ nonce = 'endpoint_nonce_01', sentAt = '2026-01-02T03:04:06Z' } = {}) {
  return createConversationEvent({ eventId: 'cevt_endpoint0001', conversationId: 'ccon_endpoint0001', sourceInstanceId: 'src_endpoint0001', role: 'user', visibleText: 'synthetic visible text', sourceOccurredAt: '2026-01-02T03:04:05Z', occurredAt: '2026-01-02T03:04:05Z', ordering: { sourceSequence: 1 }, direction: 'inbound', conversationKind: 'session', authorizationContextTags: { conversation: [TAG] }, state: 'active', revision: 1 }, { keyId: 'test', key: KEY, sentAt, nonce });
}

function tombstone() {
  return createConversationEvent({ eventId: 'cevt_tombstone001', conversationId: 'ccon_endpoint0001', sourceInstanceId: 'src_endpoint0001', role: 'user', sourceOccurredAt: '2026-01-02T03:04:06Z', occurredAt: '2026-01-02T03:04:06Z', ordering: { sourceSequence: 2 }, direction: 'inbound', conversationKind: 'session', authorizationContextTags: { conversation: [TAG] }, state: 'tombstone', revision: 1, tombstonesEventId: 'cevt_endpoint0001' }, { keyId: 'test', key: KEY, sentAt: '2026-01-02T03:04:07Z', nonce: 'tombstone_nonce01' });
}

function noLeaks(response, value) {
  const serialized = JSON.stringify(response);
  for (const hidden of [value.visibleText, value.integrity.signature, value.integrity.nonce, 'cai_endpoint0001']) assert.equal(serialized.includes(hidden), false, hidden);
}

function handler({ archive, replayVerifier, requestHmacVerifier, authorizeSource = async () => true, maxBodyBytes = 1024, bodyTimeoutMs = 100 } = {}) {
  return createConversationEventV3IngestHandler({
    archive: archive || { async append() { return { outcome: 'stored' }; }, async tombstone() { return { outcome: 'stored' }; } },
    replayVerifier: replayVerifier || { async verify(value) { return value; } },
    requestHmacVerifier,
    authorizeSource,
    maxBodyBytes,
    bodyTimeoutMs
  });
}

async function call(ingest, body, headers = {}, { method = 'POST', query = '' } = {}) {
  const req = Readable.from([Buffer.from(body)]);
  req.method = method;
  req.headers = { 'content-type': 'application/json', ...headers };
  const response = {};
  const res = { writeHead(status) { response.status = status; }, end(value) { response.body = JSON.parse(value); } };
  await ingest(req, res, new URL(`http://test.invalid/v3/ingest/conversation-events${query}`), { actor: 'synthetic-actor' });
  return response;
}

async function stalledCall(ingest, headers = {}) {
  const req = new PassThrough();
  req.method = 'POST';
  req.headers = { 'content-type': 'application/json', ...headers };
  const response = {};
  const res = { writeHead(status) { response.status = status; }, end(value) { response.body = JSON.parse(value); } };
  await within(ingest(req, res, new URL('http://test.invalid/v3/ingest/conversation-events'), { actor: 'synthetic-actor' }), 500, 'endpoint_timeout');
  req.destroy();
  return response;
}

async function erroredCall(ingest, headers = {}) {
  const req = new PassThrough();
  req.method = 'POST';
  req.headers = { 'content-type': 'application/json', ...headers };
  const response = {};
  const res = { writeHead(status) { response.status = status; }, end(value) { response.body = JSON.parse(value); } };
  const done = ingest(req, res, new URL('http://test.invalid/v3/ingest/conversation-events'), { actor: 'synthetic-actor' });
  req.destroy(new Error('synthetic body stream failure'));
  await within(done, 500, 'endpoint_error_timeout');
  return response;
}

function nonceStore({ throwing = false } = {}) {
  const values = new Set();
  return async item => {
    if (throwing) throw new Error('store');
    if (values.has(item.nonce)) return false;
    values.add(item.nonce);
    return true;
  };
}

async function signedRequest(value, sentAt = '2026-01-02T03:04:07Z') {
  const captured = {};
  const sink = new HttpConversationEventV3Sink({
    endpoint: 'https://fabric.example.test/v3/ingest/conversation-events',
    requestHmac: { keyId: 'http-test', key: KEY },
    resolveIntegrityKey: id => id === 'test' ? KEY : null,
    allowTestFetch: true,
    clock: () => Date.parse(sentAt),
    nonceFactory: () => 'request_nonce_0001',
    testFetchImpl: async (_, options) => {
      captured.headers = options.headers; captured.body = options.body;
      return new Response(JSON.stringify({ acknowledged: true, eventId: value.eventId, payloadDigest: value.integrity.payloadDigest, status: 'stored' }), { status: 201 });
    }
  });
  await sink.deliver(value, { idempotencyKey: value.eventId, payloadDigest: value.integrity.payloadDigest });
  return captured;
}

function requestVerifier(consumeNonce, clock = () => NOW) {
  return new ConversationEventV3HttpRequestVerifier({ expectedAuthority: 'fabric.example.test', resolveRequestHmacKey: id => id === 'http-test' ? KEY : null, consumeNonce, clock });
}
function eventVerifier(consumeNonce, clock = () => NOW) {
  return new ConversationEventV3ReplayVerifier({ resolveIntegrityKey: id => id === 'test' ? KEY : null, consumeNonce, clock });
}

function assertNoArchiveWrite(response, value, writes) {
  assert.equal(writes.count, 0);
  noLeaks(response, value);
}

function within(promise, timeoutMs, code) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(code)), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
}

function responseForOpenRequest(url, headers = {}) {
  const request = http.request(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers } });
  openRequests.add(request);
  request.once('close', () => openRequests.delete(request));
  const response = new Promise((resolve, reject) => {
    request.once('response', res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    request.once('error', reject);
  });
  request.flushHeaders();
  return { request, response: within(response, 1000, 'http_timeout') };
}

async function closeServer(server) {
  for (const request of openRequests) request.destroy();
  server.closeIdleConnections?.();
  server.closeAllConnections?.();
  await within(new Promise(resolve => server.close(() => resolve())), 1000, 'server_close_timeout');
}

function requestResponse(url, { headers = {}, body } = {}) {
  const opened = responseForOpenRequest(url, headers);
  if (body !== undefined) opened.request.end(body);
  return opened.response;
}

async function withServer(run, { configured = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-v3-endpoint-'));
  const registry = path.join(root, 'auth.json');
  fs.writeFileSync(registry, JSON.stringify({ rows: [
    { token: 'allowed', active: true, actor: 'actor', mode: 'allow_all', allowedScopes: '*', permissions: 'conversation:ingest' },
    { token: 'denied', active: true, actor: 'actor', mode: 'allow_all', allowedScopes: '*', permissions: 'memory:search' }
  ] }));
  const previous = process.env.MEM0_AUTH_REGISTRY_PATH;
  process.env.MEM0_AUTH_REGISTRY_PATH = registry;
  const writes = { count: 0, handler: 0 };
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: KEY.toString('base64') }), catalog: new MemoryCatalog() });
  const endpoint = handler({ archive: { async append() { writes.count += 1; return { outcome: 'stored' }; }, async tombstone() { writes.count += 1; return { outcome: 'stored' }; } } });
  const ingest = async (...args) => { writes.handler += 1; return endpoint(...args); };
  const server = createAgentMemoryFabricServer({ fabricStore: store, policyPath: '', bodyReadTimeoutMs: 100, conversationEventIngest: configured ? ingest : null });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run({ url: `http://127.0.0.1:${server.address().port}/v3/ingest/conversation-events`, writes }); }
  finally {
    await closeServer(server);
    await store.close();
    if (previous === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH;
    else process.env.MEM0_AUTH_REGISTRY_PATH = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('factory rejects missing dependencies', () => {
  assert.throws(() => createConversationEventV3IngestHandler(), /unconfigured/);
});

test('factory rejects unsafe body limits', () => {
  assert.throws(() => handler({ maxBodyBytes: 1023 }), /config_invalid/);
  assert.throws(() => handler({ maxBodyBytes: 16 * 1024 * 1024 + 1 }), /config_invalid/);
  assert.throws(() => handler({ bodyTimeoutMs: 99 }), /config_invalid/);
  assert.throws(() => handler({ bodyTimeoutMs: 120001 }), /config_invalid/);
});

test('real request verifier maps tamper, stale, future, replay and store failures', async () => {
  const value = active();
  const signed = await signedRequest(value);
  let writes = 0;
  const accepted = await call(handler({
    requestHmacVerifier: requestVerifier(nonceStore()),
    replayVerifier: eventVerifier(nonceStore()),
    archive: { async append() { writes += 1; return { outcome: 'stored' }; }, async tombstone() {} }
  }), signed.body, signed.headers);
  assert.deepEqual(accepted, { status: 201, body: { acknowledged: true, eventId: value.eventId, payloadDigest: value.integrity.payloadDigest, status: 'stored' } });
  assert.equal(writes, 1);
  const cases = [
    ['unsigned', requestVerifier(nonceStore()), { body: signed.body, headers: { 'idempotency-key': value.eventId } }, 401],
    ['tamper', requestVerifier(nonceStore()), { ...signed, body: `${signed.body} ` }, 401],
    ['replay', requestVerifier(nonceStore()), signed, 401],
    ['stale', requestVerifier(nonceStore(), () => NOW + 10 * 60_000), signed, 401],
    ['future', requestVerifier(nonceStore(), () => NOW - 10 * 60_000), signed, 401],
    ['store', requestVerifier(nonceStore({ throwing: true })), signed, 503]
  ];
  for (const [name, verifier, request, status] of cases) {
    let writes = 0;
    if (name === 'replay') await verifier.verify({ method: 'POST', path: '/v3/ingest/conversation-events', headers: signed.headers, body: signed.body });
    const response = await call(handler({ requestHmacVerifier: verifier, archive: { async append() { writes += 1; return { outcome: 'stored' }; }, async tombstone() {} } }), request.body, request.headers);
    assert.equal(response.status, status, name); assert.equal(writes, 0); noLeaks(response, value);
  }
});

test('real event verifier maps tamper, stale, future, replay and store failures', async () => {
  const value = active();
  const cases = [
    ['tamper', { ...value, integrity: { ...value.integrity, signature: `${value.integrity.signature.slice(0, -1)}A` } }, eventVerifier(nonceStore()), 401],
    ['stale', active({ nonce: 'event_stale_nonce', sentAt: '2026-01-02T02:00:00Z' }), eventVerifier(nonceStore()), 401],
    ['future', active({ nonce: 'event_future_nonce', sentAt: '2026-01-02T04:00:00Z' }), eventVerifier(nonceStore()), 401],
    ['replay', value, eventVerifier(nonceStore()), 401],
    ['store', value, eventVerifier(nonceStore({ throwing: true })), 503]
  ];
  for (const [name, candidate, verifier, status] of cases) {
    let writes = 0;
    if (name === 'replay') await verifier.verify(value);
    const response = await call(handler({ replayVerifier: verifier, archive: { async append() { writes += 1; return { outcome: 'stored' }; }, async tombstone() {} } }), JSON.stringify(candidate), { 'idempotency-key': candidate.eventId });
    assert.equal(response.status, status, name); assert.equal(writes, 0); noLeaks(response, candidate);
  }
});

test('signed tombstone dispatches and conflict metadata is bounded', async () => {
  const base = active(); const removal = tombstone(); const eventNonces = nonceStore(); const dispatched = [];
  await eventVerifier(eventNonces).verify(base);
  const response = await call(handler({ replayVerifier: eventVerifier(eventNonces), archive: { async append() { throw new Error('unexpected'); }, async tombstone(_, keyId) { dispatched.push(keyId); return { outcome: 'stored' }; } } }), JSON.stringify(removal), { 'idempotency-key': removal.eventId });
  assert.equal(response.status, 201); assert.deepEqual(dispatched, ['cai_tombstone001']);
  const valid = { eventId: base.eventId, logicalDigest: base.logicalDigest, existingPayloadDigest: base.integrity.payloadDigest, receivedPayloadDigest: removal.integrity.payloadDigest };
  for (const broken of [{}, { ...valid, eventId: 'bad' }, { ...valid, logicalDigest: 'bad' }, { ...valid, existingPayloadDigest: 'bad' }, { ...valid, receivedPayloadDigest: 'bad' }]) {
    const result = await call(handler({ archive: { async append() { return { outcome: 'conflict_visible', conflict: broken }; }, async tombstone() {} } }), JSON.stringify(base), { 'idempotency-key': base.eventId });
    assert.deepEqual(result, { status: 503, body: { error: 'transaction_rolled_back' } }); noLeaks(result, base);
  }
  const conflict = await call(handler({ archive: { async append() { return { outcome: 'conflict_visible', conflict: valid }; }, async tombstone() {} } }), JSON.stringify(base), { 'idempotency-key': base.eventId });
  assert.deepEqual(conflict, { status: 409, body: { error: 'conflict_visible', conflict: valid } }); noLeaks(conflict, base);
});

test('stored and duplicate acknowledgements map cevt keys to private archive keys', async () => {
  const value = active();
  const keys = [];
  const ingest = handler({ archive: {
    async append(_event, idempotencyKey) { keys.push(idempotencyKey); return { outcome: keys.length === 1 ? 'stored' : 'duplicate' }; },
    async tombstone() { throw new Error('unexpected'); }
  } });
  const stored = await call(ingest, JSON.stringify(value), { 'idempotency-key': value.eventId });
  const duplicate = await call(ingest, JSON.stringify(value), { 'idempotency-key': value.eventId });
  const expected = { acknowledged: true, eventId: value.eventId, payloadDigest: value.integrity.payloadDigest };
  assert.deepEqual(stored, { status: 201, body: { ...expected, status: 'stored' } });
  assert.deepEqual(duplicate, { status: 200, body: { ...expected, status: 'duplicate' } });
  assert.deepEqual(keys, ['cai_endpoint0001', 'cai_endpoint0001']);
  assert.equal(JSON.stringify([stored, duplicate]).includes('cai_endpoint0001'), false);
});

test('real SQLite archive accepts a freshly signed retry as an exact duplicate', async () => {
  const eventNonces = nonceStore();
  const archive = new SqliteConversationArchive({
    resolveIntegrityKey: id => id === 'test' ? KEY : null,
    resolveExpiresAt: () => '2026-02-01T00:00:00Z',
    cursorKey: Buffer.alloc(32, 9)
  });
  const ingest = handler({
    archive,
    replayVerifier: eventVerifier(eventNonces)
  });
  const first = active();
  const refreshed = active({ nonce: 'endpoint_nonce_02', sentAt: '2026-01-02T03:04:07Z' });
  try {
    const stored = await call(ingest, JSON.stringify(first), { 'idempotency-key': first.eventId });
    const duplicate = await call(ingest, JSON.stringify(refreshed), { 'idempotency-key': refreshed.eventId });
    assert.equal(stored.status, 201);
    assert.deepEqual(duplicate, {
      status: 200,
      body: {
        acknowledged: true,
        eventId: refreshed.eventId,
        payloadDigest: refreshed.integrity.payloadDigest,
        status: 'duplicate'
      }
    });
    const listed = archive.list(first.conversationId, 10, false);
    assert.equal(listed.items.length, 1);
    assert.equal(listed.items[0].eventId, first.eventId);
  } finally {
    archive.close();
  }
});

test('idempotency mismatch rejects before archive mutation without leakage', async () => {
  const value = active();
  const writes = { count: 0 };
  const response = await call(handler({ archive: {
    async append() { writes.count += 1; return { outcome: 'stored' }; }, async tombstone() { writes.count += 1; return { outcome: 'stored' }; }
  } }), JSON.stringify(value), { 'idempotency-key': 'cevt_endpoint0002' });
  assert.deepEqual(response, { status: 400, body: { error: 'invalid_request' } });
  assertNoArchiveWrite(response, value, writes);
});

test('source authorization and stray request authentication fail closed before archive', async () => {
  const value = active();
  const cases = [
    ['denied', async () => false, {}, 403, 'forbidden'],
    ['unavailable', async () => { throw new Error('synthetic'); }, {}, 503, 'source_auth_unavailable'],
    ['stray_header', async () => true, { 'x-amf-auth-key-id': 'unexpected' }, 401, 'unauthorized']
  ];
  for (const [name, authorizeSource, headers, status, error] of cases) {
    const writes = { count: 0 };
    const response = await call(handler({ authorizeSource, archive: {
      async append() { writes.count += 1; return { outcome: 'stored' }; }, async tombstone() { writes.count += 1; return { outcome: 'stored' }; }
    } }), JSON.stringify(value), { 'idempotency-key': value.eventId, ...headers });
    assert.deepEqual(response, { status, body: { error } }, name);
    assertNoArchiveWrite(response, value, writes);
  }
});

test('archive failures and malformed JSON are content-free service or request errors', async () => {
  const value = active();
  const invalid = await call(handler({ archive: {
    async append() { return { outcome: 'request_invalid' }; }, async tombstone() { return { outcome: 'request_invalid' }; }
  } }), JSON.stringify(value), { 'idempotency-key': value.eventId });
  assert.deepEqual(invalid, { status: 400, body: { error: 'invalid_request' } });
  noLeaks(invalid, value);
  for (const outcome of ['audit_unavailable', 'transaction_rolled_back', 'archive_unconfigured', 'unknown_outcome']) {
    const writes = { count: 0 };
    const response = await call(handler({ archive: {
      async append() { writes.count += 1; return { outcome }; }, async tombstone() { return { outcome }; }
    } }), JSON.stringify(value), { 'idempotency-key': value.eventId });
    assert.deepEqual(response, { status: 503, body: { error: outcome === 'audit_unavailable' || outcome === 'archive_unconfigured' ? outcome : 'transaction_rolled_back' } });
    assert.equal(writes.count, 1); noLeaks(response, value);
  }
  const thrown = await call(handler({ archive: { async append() { throw new Error('synthetic'); }, async tombstone() {} } }), JSON.stringify(value), { 'idempotency-key': value.eventId });
  assert.deepEqual(thrown, { status: 503, body: { error: 'transaction_rolled_back' } }); noLeaks(thrown, value);
  const malformed = await call(handler(), '{', { 'idempotency-key': value.eventId });
  assert.deepEqual(malformed, { status: 400, body: { error: 'invalid_request' } }); noLeaks(malformed, value);
});

test('endpoint route and body bounds return deterministic HTTP errors', async () => {
  const value = active();
  const ingest = handler();
  const cases = [
    ['method', JSON.stringify(value), {}, { method: 'GET' }, 400, 'invalid_request'],
    ['query', JSON.stringify(value), {}, { query: '?unexpected=1' }, 400, 'invalid_request'],
    ['content_type', JSON.stringify(value), { 'content-type': 'text/plain' }, {}, 415, 'invalid_content_type'],
    ['content_length', JSON.stringify(value), { 'content-length': 'broken' }, {}, 400, 'invalid_request'],
    ['declared_oversize', JSON.stringify(value), { 'content-length': '1025' }, {}, 413, 'body_too_large'],
    ['streamed_oversize', 'x'.repeat(1025), {}, {}, 413, 'body_too_large']
  ];
  for (const [name, body, headers, options, status, error] of cases) {
    const response = await call(ingest, body, headers, options);
    assert.deepEqual(response, { status, body: { error } }, name);
    noLeaks(response, value);
  }
  const timeout = await stalledCall(ingest, { 'idempotency-key': value.eventId });
  assert.deepEqual(timeout, { status: 408, body: { error: 'body_timeout' } });
  noLeaks(timeout, value);
  const bodyInvalid = await erroredCall(ingest, { 'idempotency-key': value.eventId });
  assert.deepEqual(bodyInvalid, { status: 400, body: { error: 'invalid_request' } });
  noLeaks(bodyInvalid, value);
});

test('real server authenticates and authorizes open bodies before endpoint body reading', async () => {
  await withServer(async ({ url, writes }) => {
    const denied = [
      ['missing', {}, 401, 'missing_token'],
      ['invalid', { authorization: 'Bearer invalid' }, 401, 'invalid_token'],
      ['permission', { authorization: 'Bearer denied' }, 403, 'forbidden']
    ];
    for (const [name, headers, status, error] of denied) {
      const opened = responseForOpenRequest(url, headers);
      opened.request.write('{');
      const response = await opened.response;
      assert.deepEqual(response, { status, body: { error } }, name);
      opened.request.destroy();
    }
    const authorized = responseForOpenRequest(url, { authorization: 'Bearer allowed', 'idempotency-key': active().eventId });
    authorized.request.write('{');
    const response = await authorized.response;
    assert.deepEqual(response, { status: 408, body: { error: 'body_timeout' } });
    authorized.request.destroy();
    assert.deepEqual(writes, { count: 0, handler: 1 });
  });
});

test('real server returns 413 for declared and streamed excess bodies', async () => {
  await withServer(async ({ url, writes }) => {
    const declared = responseForOpenRequest(url, {
      authorization: 'Bearer allowed', 'idempotency-key': active().eventId, 'content-length': '1025'
    });
    const declaredResponse = await declared.response;
    assert.deepEqual(declaredResponse, { status: 413, body: { error: 'body_too_large' } });
    declared.request.destroy();
    const streamed = responseForOpenRequest(url, { authorization: 'Bearer allowed', 'idempotency-key': active().eventId });
    streamed.request.write('x'.repeat(1025));
    const streamedResponse = await streamed.response;
    assert.deepEqual(streamedResponse, { status: 413, body: { error: 'body_too_large' } });
    streamed.request.destroy();
    assert.deepEqual(writes, { count: 0, handler: 2 });
  });
});

test('real server hides handler configuration until permission succeeds', async () => {
  await withServer(async ({ url, writes }) => {
    const unauthorized = await requestResponse(url, { headers: { authorization: 'Bearer denied' }, body: '{}' });
    assert.deepEqual(unauthorized, { status: 403, body: { error: 'forbidden' } });
    const authorized = await requestResponse(url, { headers: { authorization: 'Bearer allowed' }, body: '{}' });
    assert.deepEqual(authorized, { status: 503, body: { error: 'archive_unconfigured' } });
    assert.deepEqual(writes, { count: 0, handler: 0 });
  }, { configured: false });
  await withServer(async ({ url, writes }) => {
    const value = active();
    const response = await requestResponse(url, {
      headers: { authorization: 'Bearer allowed', 'idempotency-key': value.eventId },
      body: JSON.stringify(value)
    });
    assert.equal(response.status, 201);
    assert.equal(writes.handler, 1);
    assert.equal(writes.count, 1);
  });
});
