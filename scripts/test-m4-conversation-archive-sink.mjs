import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import { M4ConversationArchiveSink } from '../src/migration/m4-conversation-archive-sink.mjs';

const KEY = Buffer.alloc(32, 7);
const KEY_ID = 'm4-test-key';
const resolveIntegrityKey = keyId => keyId === KEY_ID ? KEY : null;
let nonce = 0;

function event({ id, state = 'active', text = `visible ${id}`, sequence = 1, replacesEventId, tombstonesEventId, conflictsWithEventIds } = {}) {
  const payload = {
    eventId: id, conversationId: 'ccon_m4archive001', sourceInstanceId: 'src_m4archive001', role: 'user',
    sourceOccurredAt: `2026-07-21T12:00:${String(sequence).padStart(2, '0')}Z`,
    occurredAt: `2026-07-21T12:00:${String(sequence).padStart(2, '0')}Z`, ordering: { sourceSequence: sequence },
    direction: 'inbound', conversationKind: 'session',
    authorizationContextTags: { conversation: [`hmac-sha256:m4-test:${'a'.repeat(64)}`] }, state, revision: state === 'edited' ? 2 : 1,
  };
  if (state !== 'tombstone') payload.visibleText = text;
  if (replacesEventId) payload.replacesEventId = replacesEventId;
  if (tombstonesEventId) payload.tombstonesEventId = tombstonesEventId;
  if (conflictsWithEventIds) payload.conflictsWithEventIds = conflictsWithEventIds;
  return createConversationEvent(payload, { keyId: KEY_ID, key: KEY, sentAt: '2026-07-21T12:01:00Z', nonce: `m4nonce${String(++nonce).padStart(12, '0')}` });
}

function archive() {
  return new SqliteConversationArchive({ filename: ':memory:', resolveIntegrityKey, resolveExpiresAt: () => '2027-07-21T12:00:00Z', cursorKey: Buffer.alloc(32, 9) });
}
function outbox(root) {
  return new ConversationEventPlaintextOutbox({ rootPath: root, resolveIntegrityKey,
    clock: () => Date.parse('2026-07-21T12:02:00Z'), nonceFactory: () => `deliverynonce${String(++nonce).padStart(9, '0')}` });
}
function temporary(label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `amf-m4-sink-${label}-`));
  return { root, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
function exactError(action, code) { return assert.rejects(action, error => error?.code === code && error.message === code); }
function input(value) { return { idempotencyKey: value.eventId, payloadDigest: value.integrity.payloadDigest }; }
function stored() { return { outcome: 'stored', stateChanged: true, items: [], nextCursor: null }; }

test('real SQLite archive receives active, edit, conflict, tombstone, and duplicate deliveries through the real outbox', async () => {
  const temp = temporary('real'); const target = archive(); const sink = new M4ConversationArchiveSink({ archive: target, resolveIntegrityKey });
  try {
    const first = event({ id: 'cevt_active0001', sequence: 1 });
    const edited = event({ id: 'cevt_edited0001', state: 'edited', sequence: 2, replacesEventId: first.eventId });
    const conflict = event({ id: 'cevt_conflict001', state: 'conflict', sequence: 3, conflictsWithEventIds: [first.eventId] });
    const tombstone = event({ id: 'cevt_tombstone01', state: 'tombstone', sequence: 4, tombstonesEventId: edited.eventId });
    for (const value of [first, edited, conflict, tombstone]) {
      const box = outbox(path.join(temp.root, value.eventId));
      assert.deepEqual(box.enqueue(value).state, 'pending');
      assert.deepEqual(await box.deliver(value.eventId, sink), {
        eventId: value.eventId, payloadDigest: value.integrity.payloadDigest, state: 'acknowledged', duplicate: false,
      });
    }
    const repeat = outbox(path.join(temp.root, 'repeat'));
    repeat.enqueue(first);
    assert.deepEqual(await repeat.deliver(first.eventId, sink), {
      eventId: first.eventId, payloadDigest: first.integrity.payloadDigest, state: 'acknowledged', duplicate: true,
    });
    const listed = target.list(first.conversationId, 20, true);
    assert.equal(listed.items.some(row => row.eventId === tombstone.eventId), true);
  } finally { target.close(); temp.cleanup(); }
});

test('changed payload conflicts and audit outages fail closed without coordinator-style acknowledgement', async () => {
  const target = archive(); const sink = new M4ConversationArchiveSink({ archive: target, resolveIntegrityKey });
  try {
    const original = event({ id: 'cevt_changed0001', text: 'visible original' });
    await sink.deliver(original, input(original));
    const changed = event({ id: original.eventId, text: 'visible changed' });
    await exactError(() => sink.deliver(changed, input(changed)), 'm4_archive_sink_outcome_invalid');
    const outage = event({ id: 'cevt_outage0001' }); target.fault = { audit: true };
    await exactError(() => sink.deliver(outage, input(outage)), 'm4_archive_sink_outcome_invalid');
    target.fault = null;
    assert.equal(target.list(outage.conversationId, 20, true).items.some(row => row.eventId === outage.eventId), false);
  } finally { target.close(); }
});

test('a committed archive write with a lost local ACK retries as a duplicate and drains the outbox', async () => {
  const temp = temporary('lost-ack'); const target = archive(); const sink = new M4ConversationArchiveSink({ archive: target, resolveIntegrityKey });
  try {
    const value = event({ id: 'cevt_lostack0001' }); const box = outbox(path.join(temp.root, 'outbox'));
    box.enqueue(value);
    let calls = 0;
    const lostAck = { async deliver(delivered, inputValue) {
      const acknowledgement = await sink.deliver(delivered, inputValue);
      calls += 1;
      if (calls === 1) throw new Error('local acknowledgement lost');
      return acknowledgement;
    } };
    await assert.rejects(() => box.deliver(value.eventId, lostAck), { code: 'conversation_outbox_delivery_failed' });
    assert.notEqual(box.read(value.eventId), null);
    assert.equal(fs.existsSync(box.ackFile(value.eventId)), false);
    assert.deepEqual(await box.deliver(value.eventId, lostAck), {
      eventId: value.eventId, payloadDigest: value.integrity.payloadDigest, state: 'acknowledged', duplicate: true,
    });
    assert.equal(calls, 2);
    assert.equal(box.read(value.eventId), null);
    assert.equal(fs.existsSync(box.ackFile(value.eventId)), true);
  } finally { target.close(); temp.cleanup(); }
});

test('validation and binding failures occur before archive mutation and errors stay content-free', async () => {
  const calls = [];
  const fake = { async append() { calls.push('append'); return stored(); }, async tombstone() { calls.push('tombstone'); return stored(); } };
  const sink = new M4ConversationArchiveSink({ archive: fake, resolveIntegrityKey });
  const sentinel = 'SYNTHETIC_PRIVATE_TEXT'; const invalid = event({ id: 'cevt_invalid0001', text: sentinel }); invalid.visibleText = `${sentinel}-tampered`;
  await assert.rejects(() => sink.deliver(invalid, input(invalid)), error => error?.code === 'm4_archive_sink_event_invalid' && !error.message.includes(sentinel));
  const valid = event({ id: 'cevt_binding0001' });
  const unknown = structuredClone(valid); unknown.state = 'unknown';
  await exactError(() => sink.deliver(unknown, input(valid)), 'm4_archive_sink_event_invalid');
  await exactError(() => sink.deliver(valid, { ...input(valid), payloadDigest: `sha256:${'b'.repeat(64)}` }), 'm4_archive_sink_idempotency_invalid');
  await exactError(() => sink.deliver(valid, { ...input(valid), idempotencyKey: 'cevt_wrong000001' }), 'm4_archive_sink_idempotency_invalid');
  await exactError(() => sink.deliver(valid, { ...input(valid), extra: true }), 'm4_archive_sink_request_invalid');
  assert.deepEqual(calls, []);
});

test('routing preserves event fields, derives the archive key, and rejects malformed or exceptional adapters', async () => {
  const calls = [];
  const fake = {
    async append(value, key) { calls.push(['append', structuredClone(value), key]); value.visibleText = 'mutated'; return stored(); },
    async tombstone(value, key) { calls.push(['tombstone', structuredClone(value), key]); return stored(); },
  };
  const sink = new M4ConversationArchiveSink({ archive: fake, resolveIntegrityKey });
  const active = event({ id: 'cevt_routeactive1' });
  const tombstone = event({ id: 'cevt_routetomb01', state: 'tombstone', tombstonesEventId: active.eventId, sequence: 2 });
  assert.deepEqual(await sink.deliver(active, input(active)), { acknowledged: true, eventId: active.eventId, payloadDigest: active.integrity.payloadDigest, status: 'stored' });
  assert.deepEqual(await sink.deliver(tombstone, input(tombstone)), { acknowledged: true, eventId: tombstone.eventId, payloadDigest: tombstone.integrity.payloadDigest, status: 'stored' });
  assert.deepEqual(calls.map(call => [call[0], call[2]]), [['append', 'cai_routeactive1'], ['tombstone', 'cai_routetomb01']]);
  assert.equal(active.visibleText, 'visible cevt_routeactive1');
  assert.equal(calls[0][1].replacesEventId, undefined);
  const malformed = new M4ConversationArchiveSink({ archive: { async append() { return { outcome: 'stored' }; }, async tombstone() { return stored(); } }, resolveIntegrityKey });
  await exactError(() => malformed.deliver(active, input(active)), 'm4_archive_sink_outcome_invalid');
  for (const result of [
    { ...stored(), stateChanged: false },
    { outcome: 'duplicate', stateChanged: true, items: [], nextCursor: null },
    { ...stored(), extra: true },
  ]) {
    const invalidResult = new M4ConversationArchiveSink({ archive: { async append() { return result; }, async tombstone() { return result; } }, resolveIntegrityKey });
    await exactError(() => invalidResult.deliver(active, input(active)), 'm4_archive_sink_outcome_invalid');
  }
  const throwing = new M4ConversationArchiveSink({ archive: { async append() { throw new Error('private detail'); }, async tombstone() { throw new Error('private detail'); } }, resolveIntegrityKey });
  await exactError(() => throwing.deliver(active, input(active)), 'm4_archive_sink_delivery_failed');
});

test('dependency validation rejects incomplete archive adapters', () => {
  assert.throws(() => new M4ConversationArchiveSink({}), { code: 'm4_archive_sink_dependency_invalid' });
  assert.throws(() => new M4ConversationArchiveSink({ archive: { append() {}, tombstone() {} } }), { code: 'm4_archive_sink_dependency_invalid' });
});
