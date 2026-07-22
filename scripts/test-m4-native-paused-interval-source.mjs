import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { M4_NATIVE_PAUSED_MAX_VISITED_RECORDS, createM4NativePausedIntervalSource } from '../src/migration/m4-native-paused-interval-source.mjs';

const key = Buffer.alloc(32, 3); const digest = character => `sha256:${character.repeat(64)}`;
const evidence = { manifestId: 'pause-manifest-001', digest: digest('a'), signature: 'a'.repeat(43) };
const sourceCheckpoint = { id: 'source-checkpoint-001', digest: digest('b') }; const nativeAuthority = { id: 'native-source-001', digest: digest('c') };
const chain = { id: 'native-chain-001', digest: digest('d') };
function hmac(domain, values) { return crypto.createHmac('sha256', key).update(canonicalJson([domain, ...values]), 'utf8').digest('hex'); }
const sourceBinding = `hmac-sha256:source-v1:${hmac('amf.m4-native-paused/tag/source-v1/v1', ['codex', 'source-one'])}`;
const authority = { schema: 'amf.m4-native-paused-interval-authority/v1', pauseEvidence: evidence, source: nativeAuthority, sourceBinding,
  interval: { startExclusive: 10, endInclusive: 20, chain }, initialCheckpoint: sourceCheckpoint };
const verification = { pauseEvidence: evidence, nativeTranscriptAuthority: nativeAuthority, sourceCheckpoint };
const integrity = async ({ eventId }, sentAt = '2026-07-22T00:00:00Z', nonce = 'a'.repeat(22)) => ({ keyId: 'test-k1', key: Buffer.alloc(32, 7), sentAt, nonce: `${nonce.slice(0, 16)}${eventId.slice(5, 11)}` });
function codex(position, id, text = 'hello', timestamp = `2026-07-22T00:00:${String(position).padStart(2, '0')}Z`) { return { native: { runtime: 'codex', sourceId: 'source-one', conversationId: 'session-one', threadId: null, messageId: id, position, sourceOccurredAt: timestamp }, sessionHint: 'session-one', value: { type: 'response_item', session_id: 'session-one', id, timestamp, payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text }] } } }; }
function wrapper(records, { source = nativeAuthority, interval = authority.interval, runtime = 'codex', sourceId = 'source-one', completion = { schema: 'amf.m4-native-paused-completion/v1', source: nativeAuthority, endInclusive: 20, chain } } = {}) {
  return { schema: 'amf.m4-native-paused-reader/v1', source, interval, runtime, sourceId, records, completion: async () => completion };
}
function build({ records = [], verify = async () => verification, reader = null, integrityFor = input => integrity(input) } = {}) {
  return createM4NativePausedIntervalSource({ authority, derivationKey: key, derivationKeyId: 'native-test-k1', verifyPauseEvidence: verify,
    reader: reader ?? { async open() { return wrapper((async function* () { yield* records; })()); } }, integrityFor });
}
async function rows(value, request = { runId: 'm4-run-001', phase: 'paused-native', after: sourceCheckpoint, afterSequence: 0, maxEvents: 10 }) { const output = []; for await (const row of value.open(request)) output.push(row); return output; }
async function rejects(action, code) { await assert.rejects(action, error => error?.code === code && error.message === code); }

test('binds signed pause authority, reader attestation, slice, and completion before accepting rows', async () => {
  const input = [codex(11, 'message-one'), codex(20, 'message-two')]; const output = await rows(build({ records: input })); assert.equal(output.length, 2);
  for (const changed of [
    { ...verification, nativeTranscriptAuthority: { ...nativeAuthority, digest: digest('e') } },
    { ...verification, sourceCheckpoint: { ...sourceCheckpoint, digest: digest('e') } }
  ]) await rejects(async () => rows(build({ verify: async () => changed })), 'm4_native_paused_pause_mismatch');
  for (const options of [ { source: { ...nativeAuthority, digest: digest('e') } }, { sourceId: 'other-source' }, { interval: { ...authority.interval, chain: { ...chain, digest: digest('e') } } }, { interval: { ...authority.interval, startExclusive: 9 } }, { interval: { ...authority.interval, endInclusive: 19 } } ]) {
    await rejects(async () => rows(build({ reader: { async open() { return wrapper((async function* () {})(), options); } } })), 'm4_native_paused_reader_attestation_mismatch');
  }
  await rejects(async () => rows(build({ reader: { async open() { return wrapper((async function* () {})(), { completion: { schema: 'amf.m4-native-paused-completion/v1', source: nativeAuthority, endInclusive: 19, chain } }); } } })), 'm4_native_paused_completion_mismatch');
});

test('is repeat-stable despite integrity envelope time/nonce and resumes exactly', async () => {
  const input = [codex(11, 'message-one'), codex(12, 'message-two'), codex(20, 'message-three')];
  const first = await rows(build({ records: input, integrityFor: input => integrity(input, '2026-07-22T01:00:00Z', 'a'.repeat(22)) }));
  const second = await rows(build({ records: input, integrityFor: input => integrity(input, '2026-07-23T02:00:00Z', 'b'.repeat(22)) }));
  assert.deepEqual(second.map(row => [row.event.eventId, row.event.logicalDigest, row.event.integrity.payloadDigest]), first.map(row => [row.event.eventId, row.event.logicalDigest, row.event.integrity.payloadDigest]));
  const resumed = await rows(build({ records: input }), { runId: 'm4-run-001', phase: 'paused-native', after: first[0].checkpoint, afterSequence: 1, maxEvents: 10 });
  assert.deepEqual(resumed.map(row => row.sequence), [2, 3]);
  await rejects(async () => rows(build({ records: input }), { runId: 'm4-run-001', phase: 'paused-native', after: { id: `m4np-${'a'.repeat(64)}`, digest: digest('f') }, afterSequence: 1, maxEvents: 1 }), 'm4_native_paused_checkpoint_drift');
});

test('binds native metadata, filters non-conversation records, and fails closed on duplicates', async () => {
  const bad = codex(11, 'message-one'); bad.native.messageId = 'relabelled'; await rejects(async () => rows(build({ records: [bad] })), 'm4_native_paused_native_binding_invalid');
  const tool = codex(11, 'tool-message'); tool.value.payload.type = 'function_call'; let integrityCalls = 0;
  const accepted = await rows(build({ records: [tool], integrityFor: async () => { integrityCalls += 1; throw new Error('should not run'); } })); assert.equal(accepted.length, 0); assert.equal(integrityCalls, 0);
  const eventMessage = codex(12, 'unused'); eventMessage.value = { type: 'event_msg', payload: { private: true } }; eventMessage.sessionHint = null;
  assert.equal((await rows(build({ records: [eventMessage], integrityFor: async () => { throw new Error('should not run'); } }))).length, 0);
  const hinted = codex(12, 'hinted'); delete hinted.value.session_id; const hintRows = await rows(build({ records: [hinted] })); assert.equal(hintRows.length, 1);
  const claudeTimestamp = '2026-07-22T00:00:13Z'; const claude = { native: { runtime: 'claude', sourceId: 'source-one', conversationId: 'claude-session', threadId: null, messageId: 'claude-one', position: 13, sourceOccurredAt: claudeTimestamp }, sessionHint: 'fallback', value: { type: 'assistant', sessionId: 'claude-session', uuid: 'claude-one', timestamp: claudeTimestamp, message: { role: 'assistant', content: [{ type: 'text', text: 'answer' }] } } };
  const claudeAuthority = { ...authority, sourceBinding: `hmac-sha256:source-v1:${hmac('amf.m4-native-paused/tag/source-v1/v1', ['claude', 'source-one'])}` };
  const claudeSource = createM4NativePausedIntervalSource({ authority: claudeAuthority, derivationKey: key, derivationKeyId: 'native-test-k1', verifyPauseEvidence: async () => verification, reader: { async open() { return wrapper((async function* () { yield claude; })(), { runtime: 'claude' }); } }, integrityFor: input => integrity(input) }); assert.equal((await rows(claudeSource)).length, 1);
  const system = { native: { runtime: 'claude', sourceId: 'source-one', conversationId: 'not-used', threadId: null, messageId: 'not-used', position: 14, sourceOccurredAt: claudeTimestamp }, sessionHint: null, value: { type: 'system', payload: {} } };
  const systemSource = createM4NativePausedIntervalSource({ authority: claudeAuthority, derivationKey: key, derivationKeyId: 'native-test-k1', verifyPauseEvidence: async () => verification, reader: { async open() { return wrapper((async function* () { yield system; })(), { runtime: 'claude' }); } }, integrityFor: async () => { throw new Error('should not run'); } }); assert.equal((await rows(systemSource)).length, 0);
  const repeated = [codex(14, 'same', 'same text', '2026-07-22T00:00:14Z'), codex(15, 'same', 'same text', '2026-07-22T00:00:14Z')]; assert.equal((await rows(build({ records: repeated }))).length, 1);
  await rejects(async () => rows(build({ records: [codex(16, 'same', 'one', '2026-07-22T00:00:16Z'), codex(17, 'same', 'two', '2026-07-22T00:00:16Z')] })), 'm4_native_paused_duplicate_conflict');
  await rejects(async () => rows(build({ records: [codex(18, 'same', 'one', '2026-07-22T00:00:18Z'), codex(19, 'same', 'one', '2026-07-22T00:00:19Z')] })), 'm4_native_paused_duplicate_conflict');
});

test('snapshots hostile getters once and closes on early bound', async () => {
  let nativeGets = 0; const hostile = codex(11, 'hostile'); const original = hostile.native; Object.defineProperty(hostile, 'native', { enumerable: true, get() { nativeGets += 1; return original; } });
  await rows(build({ records: [hostile] })); assert.equal(nativeGets, 1);
  let closed = false; const records = (async function* () { try { yield codex(11, 'one'); yield codex(12, 'two'); yield codex(13, 'three'); } finally { closed = true; } })();
  const output = await rows(build({ reader: { async open() { return wrapper(records); } } }), { runId: 'm4-run-001', phase: 'paused-native', after: sourceCheckpoint, afterSequence: 0, maxEvents: 1 });
  assert.equal(output.length, 2); assert.equal(closed, true); assert.equal(M4_NATIVE_PAUSED_MAX_VISITED_RECORDS, 10_000);
});

test('snapshots dependency, authority, verification, and iterator result getters once', async () => {
  const counts = { dependency: 0, authority: 0, verification: 0, next: 0, nextMethod: 0, returnMethod: 0 };
  const getterObject = (base, count) => Object.defineProperties({}, Object.fromEntries(Object.entries(base).map(([name, value]) => [name, { enumerable: true, get() { counts[count] += 1; return value; } }])));
  const wrappedAuthority = getterObject(authority, 'authority');
  const wrappedVerification = getterObject(verification, 'verification');
  const item = codex(11, 'getter-message'); let yielded = false;
  const iterator = {};
  Object.defineProperties(iterator, {
    next: { get() { counts.nextMethod += 1; return async () => { if (yielded) return { value: undefined, done: true }; yielded = true; return getterObject({ value: item, done: false }, 'next'); }; } },
    return: { get() { counts.returnMethod += 1; return async () => ({ value: undefined, done: true }); } }
  });
  const records = { [Symbol.asyncIterator]() { return iterator; } };
  const dependency = getterObject({ authority: wrappedAuthority, derivationKey: key, derivationKeyId: 'native-test-k1', verifyPauseEvidence: async () => wrappedVerification,
    reader: { async open() { return wrapper(records); } }, integrityFor: input => integrity(input) }, 'dependency');
  await rows(createM4NativePausedIntervalSource(dependency));
  assert.deepEqual(counts, { dependency: 6, authority: 6, verification: 3, next: 2, nextMethod: 1, returnMethod: 1 });
});

test('fails closed after the public excluded-record scan limit', async () => {
  const wideAuthority = { ...authority, interval: { startExclusive: 0, endInclusive: M4_NATIVE_PAUSED_MAX_VISITED_RECORDS + 2, chain } };
  const records = Array.from({ length: M4_NATIVE_PAUSED_MAX_VISITED_RECORDS + 1 }, (_, index) => { const item = codex(index + 1, `tool-${index}`, 'ignored', '2026-07-22T00:00:00Z'); item.value.payload.type = 'function_call'; return item; });
  const source = createM4NativePausedIntervalSource({ authority: wideAuthority, derivationKey: key, derivationKeyId: 'native-test-k1', verifyPauseEvidence: async () => verification,
    reader: { async open() { return wrapper((async function* () { yield* records; })(), { interval: wideAuthority.interval }); } }, integrityFor: input => integrity(input) });
  await rejects(async () => rows(source, { runId: 'm4-run-001', phase: 'paused-native', after: sourceCheckpoint, afterSequence: 0, maxEvents: 1 }), 'm4_native_paused_scan_limit');
});

test('reports reader close failure only when it is the primary source failure', async () => {
  const disguised = new Error('private open content'); disguised.code = 'm4_native_paused_private_content';
  await rejects(async () => rows(build({ reader: { async open() { throw disguised; } } })), 'm4_native_paused_reader_open_failed');
  const closeFailing = values => ({ [Symbol.asyncIterator]() { let index = 0; return { async next() { return index < values.length ? { value: values[index++], done: false } : { value: undefined, done: true }; }, async return() { throw new Error('private close error'); } }; } });
  await rejects(async () => rows(build({ reader: { async open() { return wrapper(closeFailing([])); } } })), 'm4_native_paused_reader_close_failed');
  await rejects(async () => rows(build({ reader: { async open() { return wrapper(closeFailing([codex(11, 'one'), codex(12, 'two')])); } } }), { runId: 'm4-run-001', phase: 'paused-native', after: sourceCheckpoint, afterSequence: 0, maxEvents: 1 }), 'm4_native_paused_reader_close_failed');
  const primary = { [Symbol.asyncIterator]() { return { async next() { throw new Error('private read error'); }, async return() { throw new Error('private close error'); } }; } };
  await rejects(async () => rows(build({ reader: { async open() { return wrapper(primary); } } })), 'm4_native_paused_reader_read_failed');
});
