import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import {
  ConversationEventV3HttpRequestVerifier,
  ConversationEventV3ReplayVerifier,
  HttpConversationEventV3Sink
} from '../src/ingest/http-conversation-event-v3-sink.mjs';

const KEY = Buffer.alloc(32, 7);
const OTHER_KEY = Buffer.alloc(32, 9);
const KEY_ID = 'synthetic-v3';
const NOW = Date.parse('2026-07-21T12:00:00.000Z');
const ENDPOINT = 'https://fabric.example.test/v3/ingest/conversation-events';
const resolveEventKey = keyId => keyId === KEY_ID ? KEY : null;

function nonceConsumer(onConsume = () => {}) {
  const records = new Set();
  return async record => {
    onConsume(record);
    const key = `${record.namespace}\0${record.keyId}\0${record.nonce}`;
    if (records.has(key)) return false;
    records.add(key);
    return true;
  };
}

function payload(id = 'cevt_event0001', text = 'Synthetic visible message') {
  return {
    eventId: id,
    conversationId: 'ccon_synthetic01',
    sourceInstanceId: 'src_synthetic001',
    role: 'user',
    visibleText: text,
    sourceOccurredAt: '2026-07-21T11:59:00Z',
    occurredAt: '2026-07-21T11:59:01Z',
    ordering: { sourceSequence: 1 },
    direction: 'inbound',
    conversationKind: 'session',
    authorizationContextTags: {
      conversation: [`hmac-sha256:synthetic:${'a'.repeat(64)}`]
    },
    state: 'active',
    revision: 1
  };
}

let nonceCounter = 0;
function event(options = {}) {
  const sentAt = options.sentAt ?? new Date(NOW).toISOString();
  const nonce = options.nonce ?? `syntheticnonce${String(++nonceCounter).padStart(8, '0')}`;
  return createConversationEvent(payload(options.id, options.text), {
    keyId: options.keyId ?? KEY_ID,
    key: options.key ?? KEY,
    sentAt,
    nonce
  });
}

function tempRoot(label) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `amf-v3-${label}-`));
  return { base, root: path.join(base, 'outbox'), cleanup: () => fs.rmSync(base, { recursive: true, force: true }) };
}

function outbox(root, options = {}) {
  return new ConversationEventPlaintextOutbox({
    rootPath: root,
    resolveIntegrityKey: resolveEventKey,
    clock: () => NOW,
    nonceFactory: () => `deliverynonce${String(++nonceCounter).padStart(8, '0')}`,
    ...options
  });
}

function ackFor(delivered, status = 'stored') {
  return {
    acknowledged: true,
    eventId: delivered.eventId,
    payloadDigest: delivered.integrity.payloadDigest,
    status
  };
}

test('plaintext outbox creates owner-only directories and durable plaintext records', () => {
  const tree = tempRoot('modes');
  try {
    const box = outbox(tree.root);
    const queued = event();
    box.enqueue(queued);
    for (const directory of [tree.root, box.pendingPath, box.ackPath, box.conflictPath]) {
      assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
    }
    const file = box.pendingFile(queued.eventId);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const disk = fs.readFileSync(file, 'utf8');
    assert.match(disk, /Synthetic visible message/);
    assert.match(disk, /"integrity"/);
    assert.equal(disk.includes(KEY.toString('hex')), false);
  } finally { tree.cleanup(); }
});

test('outbox validates complete event HMAC and emits content-free errors', () => {
  const tree = tempRoot('auth');
  const sentinel = 'SYNTHETIC_SECRET_SENTINEL';
  try {
    const box = outbox(tree.root);
    const tampered = event({ text: sentinel });
    tampered.visibleText = `${sentinel}-changed`;
    assert.throws(() => box.enqueue(tampered), error => {
      assert.equal(error.message, 'conversation_outbox_event_invalid');
      assert.equal(error.message.includes(sentinel), false);
      return true;
    });
    assert.throws(() => box.enqueue(event({ key: OTHER_KEY })), /conversation_outbox_event_invalid/);
  } finally { tree.cleanup(); }
});

test('exact retry is idempotent while changed payload is durably preserved as conflict', () => {
  const tree = tempRoot('conflict');
  try {
    const box = outbox(tree.root);
    const first = event({ text: 'Synthetic first version' });
    const exact = event({ text: 'Synthetic first version' });
    const changed = event({ text: 'Synthetic competing version' });
    assert.equal(box.enqueue(first).duplicate, false);
    assert.deepEqual(box.enqueue(exact), {
      eventId: first.eventId,
      payloadDigest: first.integrity.payloadDigest,
      state: 'pending',
      duplicate: true
    });
    const conflict = box.enqueue(changed);
    assert.equal(conflict.state, 'conflict');
    assert.equal(box.read(first.eventId).visibleText, 'Synthetic first version');
    assert.equal(box.readConflict(changed.eventId, changed.integrity.payloadDigest).visibleText, 'Synthetic competing version');
    assert.equal(fs.readdirSync(box.conflictPath).length, 1);
  } finally { tree.cleanup(); }
});

test('pending survives delivery errors and wrong ACKs', async () => {
  const tree = tempRoot('pending');
  try {
    const box = outbox(tree.root);
    const queued = event();
    box.enqueue(queued);
    await assert.rejects(box.deliver(queued.eventId, { async deliver() { throw new Error('SYNTHETIC_SECRET_SENTINEL'); } }), error => {
      assert.equal(error.message, 'conversation_outbox_delivery_failed');
      assert.equal(error.message.includes('SYNTHETIC_SECRET_SENTINEL'), false);
      return true;
    });
    assert.deepEqual(box.pendingIds(), [queued.eventId]);
    await assert.rejects(box.deliver(queued.eventId, { async deliver(delivered) { return { ...ackFor(delivered), payloadDigest: `sha256:${'0'.repeat(64)}` }; } }), /conversation_outbox_ack_invalid/);
    assert.deepEqual(box.pendingIds(), [queued.eventId]);
  } finally { tree.cleanup(); }
});

test('bounded replay continues after a poisoned item and drains later valid items', async () => {
  const tree = tempRoot('replay-head-of-line');
  try {
    const box = outbox(tree.root, { maxPendingCount: 2 });
    const poisoned = event({ id: 'cevt_event0001' });
    const valid = event({ id: 'cevt_event0002' });
    box.enqueue(poisoned);
    box.enqueue(valid);
    const results = await box.replay({
      async deliver(delivered) {
        if (delivered.eventId === poisoned.eventId) throw new Error('SYNTHETIC_PRIVATE_FAILURE');
        return ackFor(delivered);
      }
    }, { limit: 2 });
    assert.deepEqual(results[0], {
      eventId: poisoned.eventId,
      state: 'pending',
      outcome: 'failed',
      errorCode: 'conversation_outbox_delivery_failed'
    });
    assert.equal(results[1].eventId, valid.eventId);
    assert.equal(results[1].outcome, 'acknowledged');
    assert.deepEqual(box.pendingIds(), [poisoned.eventId]);
    await assert.rejects(box.replay({}, { limit: 3 }), /conversation_outbox_replay_limit_invalid/);
  } finally { tree.cleanup(); }
});

test('accepted mutation plus lost ACK replays with a fresh nonce and drains as duplicate', async () => {
  const tree = tempRoot('lost-ack');
  const consumeReplayNonce = nonceConsumer();
  const makeVerifier = () => new ConversationEventV3ReplayVerifier({
    resolveIntegrityKey: resolveEventKey, consumeNonce: consumeReplayNonce, clock: () => NOW
  });
  let verifier = makeVerifier();
  const archive = new Map();
  const nonces = [];
  let loseAck = true;
  const receiver = {
    async deliver(delivered) {
      const verified = await verifier.verify(delivered);
      nonces.push(verified.integrity.nonce);
      const prior = archive.get(verified.eventId);
      const status = prior === undefined ? 'stored' : 'duplicate';
      assert.ok(prior === undefined || prior === verified.integrity.payloadDigest);
      archive.set(verified.eventId, verified.integrity.payloadDigest);
      if (loseAck) {
        loseAck = false;
        throw new Error('synthetic_ack_lost');
      }
      return ackFor(verified, status);
    }
  };
  try {
    const firstProcess = outbox(tree.root);
    const queued = event();
    firstProcess.enqueue(queued);
    await assert.rejects(firstProcess.deliver(queued.eventId, receiver), /conversation_outbox_delivery_failed/);
    assert.deepEqual(firstProcess.pendingIds(), [queued.eventId]);
    verifier = makeVerifier();
    const restarted = outbox(tree.root);
    const result = await restarted.replay(receiver);
    assert.equal(result[0].duplicate, true);
    assert.deepEqual(restarted.pendingIds(), []);
    assert.equal(new Set(nonces).size, 2, 'delivery retry must refresh the replay nonce');
  } finally { tree.cleanup(); }
});

test('restart removes safe leftover temp files and reconciles durable ACK before pending deletion', async () => {
  const tree = tempRoot('recovery');
  try {
    const first = outbox(tree.root);
    const queued = event();
    first.enqueue(queued);
    const temp = path.join(first.pendingPath, `.amf-${crypto.randomUUID()}.tmp`);
    fs.writeFileSync(temp, 'synthetic', { mode: 0o600 });
    const ack = {
      schema: 'amf.conversation-event-plaintext-ack/v1',
      eventId: queued.eventId,
      payloadDigest: queued.integrity.payloadDigest
    };
    fs.writeFileSync(first.ackFile(queued.eventId), JSON.stringify(ack), { mode: 0o600, flag: 'wx' });
    const restarted = outbox(tree.root);
    assert.equal(fs.existsSync(temp), false);
    const result = await restarted.deliver(queued.eventId, { async deliver() { assert.fail('must not deliver'); } });
    assert.deepEqual(result, {
      eventId: queued.eventId,
      payloadDigest: queued.integrity.payloadDigest,
      state: 'acknowledged',
      duplicate: true
    });
    assert.deepEqual(restarted.pendingIds(), []);
  } finally { tree.cleanup(); }
});

test('enqueue fails closed when durable ACK and pending payload digests disagree', () => {
  const tree = tempRoot('ack-pending-conflict');
  try {
    const box = outbox(tree.root);
    const pending = event({ text: 'Synthetic pending variant' });
    const different = event({ text: 'Synthetic acknowledged variant' });
    box.enqueue(pending);
    fs.writeFileSync(box.ackFile(pending.eventId), JSON.stringify({
      schema: 'amf.conversation-event-plaintext-ack/v1',
      eventId: pending.eventId,
      payloadDigest: different.integrity.payloadDigest
    }), { mode: 0o600, flag: 'wx' });
    assert.throws(() => box.enqueue(pending), /conversation_outbox_event_id_conflict/);
    assert.equal(box.read(pending.eventId).integrity.payloadDigest, pending.integrity.payloadDigest);
    assert.equal(fs.existsSync(box.ackFile(pending.eventId)), true);
  } finally { tree.cleanup(); }
});

test('unsafe IDs, modes, symlinks and replacement races fail closed', () => {
  const tree = tempRoot('unsafe');
  try {
    const box = outbox(tree.root);
    assert.throws(() => box.read('../escape'), /conversation_outbox_event_id_invalid/);
    const queued = event();
    box.enqueue(queued);
    fs.chmodSync(box.pendingFile(queued.eventId), 0o644);
    assert.throws(() => box.read(queued.eventId), /conversation_outbox_file_mode_unsafe/);
    fs.chmodSync(box.pendingFile(queued.eventId), 0o600);
    const external = path.join(tree.base, 'external');
    fs.writeFileSync(external, 'synthetic', { mode: 0o600 });
    fs.unlinkSync(box.pendingFile(queued.eventId));
    fs.symlinkSync(external, box.pendingFile(queued.eventId));
    assert.throws(() => box.read(queued.eventId), /conversation_outbox_file_unsafe/);
    fs.unlinkSync(box.pendingFile(queued.eventId));
    fs.mkdirSync(box.pendingFile(queued.eventId), { mode: 0o700 });
    assert.throws(() => box.read(queued.eventId), /conversation_outbox_file_unsafe/);
  } finally { tree.cleanup(); }

  const linked = tempRoot('linked');
  try {
    fs.mkdirSync(linked.root, { mode: 0o700 });
    const external = path.join(linked.base, 'external-dir');
    fs.mkdirSync(external, { mode: 0o700 });
    fs.symlinkSync(external, path.join(linked.root, 'pending'));
    assert.throws(() => outbox(linked.root), /conversation_outbox_path_unsafe/);
  } finally { linked.cleanup(); }

  const unsafeMode = tempRoot('unsafe-root-mode');
  try {
    fs.mkdirSync(unsafeMode.root, { mode: 0o700 });
    fs.chmodSync(unsafeMode.root, 0o755);
    assert.throws(() => outbox(unsafeMode.root), /conversation_outbox_directory_mode_unsafe/);
  } finally { unsafeMode.cleanup(); }
});

test('filesystem failures expose deterministic content-free errors', () => {
  const tree = tempRoot('SYNTHETIC_PATH_SENTINEL');
  try {
    const box = outbox(tree.root);
    fs.renameSync(box.pendingPath, `${box.pendingPath}-moved`);
    assert.throws(() => box.pendingIds(), error => {
      assert.equal(error.message, 'conversation_outbox_directory_unsafe');
      assert.equal(error.message.includes(tree.root), false);
      assert.equal(error.message.includes('SYNTHETIC_PATH_SENTINEL'), false);
      return true;
    });
  } finally { tree.cleanup(); }
});

test('queue enforces per-event, count and total pending byte limits', () => {
  const oversized = tempRoot('event-limit');
  try {
    const box = outbox(oversized.root, { maxEventBytes: 1024, maxPendingBytes: 4096 });
    assert.throws(() => box.enqueue(event({ text: 'x'.repeat(4000) })), /conversation_outbox_event_too_large/);
  } finally { oversized.cleanup(); }

  const counted = tempRoot('count-limit');
  try {
    const box = outbox(counted.root, { maxPendingCount: 1 });
    box.enqueue(event({ id: 'cevt_event0001' }));
    assert.throws(() => box.enqueue(event({ id: 'cevt_event0002' })), /conversation_outbox_count_limit_exceeded/);
  } finally { counted.cleanup(); }

  const measured = tempRoot('measure-bytes');
  let recordBytes;
  try {
    const box = outbox(measured.root);
    box.enqueue(event({ id: 'cevt_event0011' }));
    recordBytes = box.stats().bytes;
  } finally { measured.cleanup(); }
  const bounded = tempRoot('bytes-limit');
  try {
    const box = outbox(bounded.root, { maxEventBytes: recordBytes + 32, maxPendingBytes: recordBytes * 2 - 1 });
    box.enqueue(event({ id: 'cevt_event0011' }));
    assert.throws(() => box.enqueue(event({ id: 'cevt_event0012' })), /conversation_outbox_bytes_limit_exceeded/);
  } finally { bounded.cleanup(); }
});

test('replay verifier rejects tamper, wrong key, stale, future and duplicate nonce through a caller store', async () => {
  const verifier = (consumeNonce = nonceConsumer()) => new ConversationEventV3ReplayVerifier({
    resolveIntegrityKey: resolveEventKey,
    consumeNonce,
    clock: () => NOW,
    maxPastMs: 60_000,
    maxFutureMs: 10_000
  });
  const valid = event();
  const tampered = structuredClone(valid);
  tampered.visibleText = 'Synthetic tamper';
  await assert.rejects(verifier().verify(tampered), /conversation_event_receiver_auth_invalid/);
  await assert.rejects(verifier().verify(event({ key: OTHER_KEY })), /conversation_event_receiver_auth_invalid/);
  await assert.rejects(verifier().verify(event({ sentAt: new Date(NOW - 61_000).toISOString() })), /conversation_event_receiver_stale/);
  await assert.rejects(verifier().verify(event({ sentAt: new Date(NOW + 11_000).toISOString() })), /conversation_event_receiver_future/);
  const sharedNonceStore = nonceConsumer();
  const replay = verifier(sharedNonceStore);
  await replay.verify(valid);
  await assert.rejects(verifier(sharedNonceStore).verify(valid), /conversation_event_receiver_nonce_replay/);
  const exactNewNonce = event({ text: valid.visibleText });
  assert.equal(exactNewNonce.integrity.payloadDigest, valid.integrity.payloadDigest);
  await assert.doesNotReject(replay.verify(exactNewNonce));

  let boundaryRecord;
  const boundaryVerifier = verifier(nonceConsumer(record => { boundaryRecord = record; }));
  await boundaryVerifier.verify(event({ sentAt: new Date(NOW - 60_000).toISOString() }));
  assert.equal(boundaryRecord.expiresAt, NOW + 1, 'nonce survives one millisecond past the inclusive stale boundary');
});

test('HTTPS sink requires exact secure URL and explicit authentication', () => {
  for (const endpoint of [
    'http://fabric.example.test/v3/ingest/conversation-events',
    'https://user@fabric.example.test/v3/ingest/conversation-events',
    'https://fabric.example.test/v3/ingest/conversation-events?x=1',
    'https://fabric.example.test/v3/ingest/conversation-events?',
    'https://fabric.example.test/v3/ingest/conversation-events#x',
    'https://fabric.example.test/v3/ingest/conversation-events#',
    'https://fabric.example.test/v3/ingest/conversation-events/'
  ]) assert.throws(() => new HttpConversationEventV3Sink({ endpoint, bearerToken: 'token' }), /conversation_event_http_endpoint_invalid/);
  assert.throws(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, bearerToken: 'token' }), /conversation_event_http_integrity_key_required/);
  assert.throws(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, resolveIntegrityKey: resolveEventKey }), /conversation_event_http_auth_required/);
  assert.throws(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, bearerToken: 'x'.repeat(4097), resolveIntegrityKey: resolveEventKey }), /conversation_event_http_auth_invalid/);
  assert.throws(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, bearerToken: 'token', resolveIntegrityKey: resolveEventKey, mtlsDispatcher: {} }), /conversation_event_http_auth_invalid/);
  assert.throws(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, bearerToken: 'token', resolveIntegrityKey: resolveEventKey, testFetchImpl: async () => {} }), /conversation_event_http_test_fetch_forbidden/);
  assert.doesNotThrow(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, resolveIntegrityKey: resolveEventKey, requestHmac: { keyId: 'request-v1', key: OTHER_KEY } }));
  assert.doesNotThrow(() => new HttpConversationEventV3Sink({ endpoint: ENDPOINT, resolveIntegrityKey: resolveEventKey, mtlsDispatcher: { dispatch() {} } }));
});

test('HTTPS sink independently rejects tampered and wrong-key events before fetch', async () => {
  let calls = 0;
  const sink = new HttpConversationEventV3Sink({
    endpoint: ENDPOINT,
    bearerToken: 'token',
    resolveIntegrityKey: resolveEventKey,
    allowTestFetch: true,
    testFetchImpl: async () => { calls += 1; throw new Error('must_not_run'); }
  });
  const tampered = event();
  tampered.visibleText = 'Synthetic tampered direct call';
  await assert.rejects(sink.deliver(tampered, {
    idempotencyKey: tampered.eventId,
    payloadDigest: tampered.integrity.payloadDigest
  }), /conversation_event_http_event_invalid/);
  const wrongKey = event({ key: OTHER_KEY });
  await assert.rejects(sink.deliver(wrongKey, {
    idempotencyKey: wrongKey.eventId,
    payloadDigest: wrongKey.integrity.payloadDigest
  }), /conversation_event_http_event_invalid/);
  assert.equal(calls, 0);
});

test('HTTPS sink sends bounded authenticated plaintext and accepts only exact ACK', async () => {
  const delivered = event();
  const requests = [];
  const sink = new HttpConversationEventV3Sink({
    endpoint: ENDPOINT,
    bearerToken: 'synthetic-token',
    resolveIntegrityKey: resolveEventKey,
    requestHmac: { keyId: 'request-v1', key: OTHER_KEY },
    clock: () => NOW,
    nonceFactory: () => 'requestnonce00000001',
    allowTestFetch: true,
    testFetchImpl: async (endpoint, options) => {
      requests.push({ endpoint, options });
      return new Response(JSON.stringify(ackFor(delivered)), { status: 200, headers: { 'content-type': 'application/json' } });
    }
  });
  assert.deepEqual(await sink.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), ackFor(delivered));
  assert.equal(requests[0].endpoint, ENDPOINT);
  assert.equal(requests[0].options.redirect, 'error');
  assert.equal(requests[0].options.headers.authorization, 'Bearer synthetic-token');
  assert.equal(requests[0].options.headers['x-amf-payload-digest'], undefined);
  assert.match(requests[0].options.headers['x-amf-auth-signature'], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.parse(requests[0].options.body).visibleText, delivered.visibleText);
});

test('request-HMAC verifier binds request fields, key, time and caller-owned nonce replay state', async () => {
  const delivered = event();
  async function signedRequest({ requestKey = OTHER_KEY, sentAt = NOW, nonce = 'requestnonce00000002' } = {}) {
    let request;
    const sink = new HttpConversationEventV3Sink({
      endpoint: ENDPOINT,
      resolveIntegrityKey: resolveEventKey,
      requestHmac: { keyId: 'request-v1', key: requestKey },
      clock: () => sentAt,
      nonceFactory: () => nonce,
      allowTestFetch: true,
      testFetchImpl: async (_endpoint, options) => {
        request = { method: options.method, path: '/v3/ingest/conversation-events', headers: options.headers, body: options.body };
        return new Response(JSON.stringify(ackFor(delivered)), { status: 200 });
      }
    });
    await sink.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest });
    return request;
  }
  const verifier = ({ key = OTHER_KEY, now = NOW, consumeNonce = nonceConsumer(), expectedAuthority = 'fabric.example.test' } = {}) =>
    new ConversationEventV3HttpRequestVerifier({
      expectedAuthority,
      resolveRequestHmacKey: keyId => keyId === 'request-v1' ? key : null,
      consumeNonce,
      clock: () => now,
      maxPastMs: 60_000,
      maxFutureMs: 10_000
    });

  const valid = await signedRequest();
  assert.equal((await verifier().verify(valid)).idempotencyKey, delivered.eventId);
  await assert.rejects(verifier().verify({ ...valid, body: `${valid.body} ` }), /conversation_event_http_request_auth_invalid/);
  await assert.rejects(verifier({ key: KEY }).verify(valid), /conversation_event_http_request_auth_invalid/);
  await assert.rejects(verifier({ now: NOW + 61_000 }).verify(valid), /conversation_event_http_request_stale/);
  await assert.rejects(verifier({ now: NOW - 11_000 }).verify(valid), /conversation_event_http_request_future/);
  await assert.rejects(verifier().verify({ ...valid, method: 'GET' }), /conversation_event_http_request_auth_invalid/);
  await assert.rejects(verifier().verify({ ...valid, path: '/v3/ingest/other' }), /conversation_event_http_request_auth_invalid/);
  await assert.rejects(verifier({ expectedAuthority: 'other.example.test' }).verify(valid), /conversation_event_http_request_auth_invalid/);
  await assert.rejects(verifier().verify({ ...valid, headers: { ...valid.headers, 'idempotency-key': 'cevt_event9999' } }), /conversation_event_http_request_auth_invalid/);

  const sharedNonceStore = nonceConsumer();
  const replayVerifier = verifier({ consumeNonce: sharedNonceStore });
  await replayVerifier.verify(valid);
  await assert.rejects(verifier({ consumeNonce: sharedNonceStore }).verify(valid), /conversation_event_http_request_nonce_replay/);

  let boundaryRecord;
  const boundary = await signedRequest({ sentAt: NOW - 60_000, nonce: 'requestnonce00000003' });
  await verifier({ consumeNonce: nonceConsumer(record => { boundaryRecord = record; }) }).verify(boundary);
  assert.equal(boundaryRecord.expiresAt, NOW + 1, 'request nonce survives one millisecond past the inclusive stale boundary');
});

test('HTTPS sink rejects timeout, status, redirect, oversized bodies and wrong ACK', async () => {
  const delivered = event({ text: 'x'.repeat(3000) });
  const options = { endpoint: ENDPOINT, bearerToken: 'token', resolveIntegrityKey: resolveEventKey, allowTestFetch: true };
  let called = false;
  const tooLargeRequest = new HttpConversationEventV3Sink({ ...options, maxRequestBytes: 1024, testFetchImpl: async () => { called = true; } });
  await assert.rejects(tooLargeRequest.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_request_too_large/);
  assert.equal(called, false);

  const timeout = new HttpConversationEventV3Sink({ ...options, timeoutMs: 50, testFetchImpl: async () => new Promise(() => {}) });
  await assert.rejects(timeout.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_timeout/);

  const status = new HttpConversationEventV3Sink({ ...options, testFetchImpl: async () => new Response('{}', { status: 503 }) });
  await assert.rejects(status.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_status_error/);

  const redirect = new HttpConversationEventV3Sink({ ...options, testFetchImpl: async () => ({ ok: true, status: 200, redirected: true }) });
  await assert.rejects(redirect.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_redirect_invalid/);

  const oversized = new HttpConversationEventV3Sink({ ...options, maxResponseBytes: 128, testFetchImpl: async () => new Response('x'.repeat(129), { status: 200 }) });
  await assert.rejects(oversized.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_response_too_large/);

  const wrongAck = new HttpConversationEventV3Sink({ ...options, testFetchImpl: async () => new Response(JSON.stringify({ ...ackFor(delivered), extra: true }), { status: 200 }) });
  await assert.rejects(wrongAck.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_ack_invalid/);

  const nonStreaming = new HttpConversationEventV3Sink({ ...options, testFetchImpl: async () => ({ ok: true, status: 200, redirected: false, text: async () => JSON.stringify(ackFor(delivered)) }) });
  await assert.rejects(nonStreaming.deliver(delivered, { idempotencyKey: delivered.eventId, payloadDigest: delivered.integrity.payloadDigest }), /conversation_event_http_ack_invalid/);
});
