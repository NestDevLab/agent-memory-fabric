import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';

import {
  M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_MAX_TOTAL_ENTRIES,
  createM4CrossPhaseIdentityInMemoryAccumulator,
} from '../src/migration/m4-cross-phase-identity-in-memory-accumulator.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from '../src/migration/m4-v2-conversation-projector.mjs';

const SECRET = Buffer.alloc(32, 9);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const opaque = value => `hmac-sha256:test-v1:${hash(value)}`;
const sourceTag = value => `test-v1:${hash(value)}`;
const digest = value => `sha256:${hash(value)}`;
const session = value => `ses_${hash(`session:${value}`)}`;
const event = value => `evt_${hash(`event:${value}`)}`;
const compactId = (kind, index) => `${kind}_aa${index.toString(16).padStart(62, '0')}`;
const binding = () => ({ completionDigest: digest('backfill-complete'), catalogRevisionDigest: digest('catalog') });
const completion = acceptedGroupCount => ({ complete: true, acceptedGroupCount, excludedGroupCount: 2, traversalDigest: digest(`scan:${acceptedGroupCount}`) });

function block(label, options = {}) {
  const legacySessionId = options.legacySessionId ?? session(`session:${label}`);
  const legacyEventId = options.legacyEventId ?? event(`event:${label}`);
  const tags = options.sourceTags ?? [sourceTag('one')];
  const conversationId = deriveM4V3ConversationIdFromLegacySessionId(legacySessionId);
  const context = { sender: [opaque(`sender:${label}`)], conversation: [opaque(`conversation:${legacySessionId}`)], room: [opaque(`room:${legacySessionId}`)] };
  const entry = {
    legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId,
    sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, tags), sourceTags: tags,
    conversationKind: 'dm', authorizationContextTags: context, role: 'user', direction: 'inbound',
    state: 'active', revision: 1, replacesLegacyEventId: null, tombstonesLegacyEventId: null,
    conflictsWithLegacyEventIds: [],
  };
  return { schema: 'amf.m4-cross-phase-projector-identity-block/v1',
    session: { legacySessionId, conversationId, conversationKind: 'dm',
      sessionContextTags: { conversation: context.conversation, room: context.room } }, events: [entry] };
}

function accumulator(options = {}) { return createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret: SECRET, ...options }); }
function expectedCompletionDigest(value) {
  const body = { ...value, digest: null };
  return `sha256:${crypto.createHash('sha256').update(canonicalJson([
    'amf.m4-cross-phase-identity-in-memory-accumulator-completion/v1/digest', body,
  ]), 'utf8').digest('hex')}`;
}

test('accumulates accepted projector blocks independent of group arrival and exact replay', () => {
  const left = block('left'); const right = block('right');
  const first = accumulator(); first.accept(right); first.accept(left); first.accept(left);
  const one = first.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(2) });
  const second = accumulator(); second.accept(left); second.accept(right);
  const two = second.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(2) });
  assert.deepEqual(one.registry, two.registry);
  assert.deepEqual(one.completion, two.completion);
  assert.equal(one.completion.coverage.sessionCount, 2);
  assert.equal(one.completion.coverage.eventCount, 2);
  assert.equal(one.completion.digest, expectedCompletionDigest(one.completion));
  assert.doesNotMatch(JSON.stringify(one), /visibleText|ciphertext|normalizedPayloadDigest|logicalMessageId|nativeEventId|nativeSessionId|integrity|attachment/i);
});

test('canonicalizes event order for replay and copies its registry secret', () => {
  const ordered = block('ordered');
  const secondLegacyEventId = event('ordered-second');
  ordered.events.push({ ...structuredClone(ordered.events[0]), legacyEventId: secondLegacyEventId,
    eventId: deriveM4V3EventIdFromLegacyEventId(secondLegacyEventId) });
  const reversed = structuredClone(ordered); reversed.events.reverse();
  const order = accumulator(); const first = order.accept(ordered); const replay = order.accept(reversed);
  assert.equal(first.blockDigest, replay.blockDigest);
  assert.equal(replay.accepted, false);
  assert.equal(order.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) }).registry.authority.coverage.eventCount, 2);

  const mutableSecret = Buffer.alloc(32, 12); const copied = createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret: mutableSecret });
  mutableSecret.fill(99); copied.accept(block('copied-secret'));
  const copiedResult = copied.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  const baseline = createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret: Buffer.alloc(32, 12) }); baseline.accept(block('copied-secret'));
  const baselineResult = baseline.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  assert.deepEqual(copiedResult, baselineResult);
});

test('binds completion to the exact authority and cutoff', () => {
  const left = accumulator(); left.accept(block('cutoff'));
  const first = left.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  const right = accumulator(); right.accept(block('cutoff'));
  const second = right.seal({ coveredThrough: '2026-07-23T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  assert.equal(first.completion.coveredThrough, '2026-07-22T00:00:00Z');
  assert.equal(first.completion.registryAuthorityDigest, `sha256:${crypto.createHash('sha256').update(canonicalJson(first.registry.authority), 'utf8').digest('hex')}`);
  assert.notEqual(first.completion.registryAuthorityDigest, second.completion.registryAuthorityDigest);
  assert.notEqual(first.completion.digest, second.completion.digest);
  assert.equal(first.completion.digest, expectedCompletionDigest(first.completion));
  assert.equal(second.completion.digest, expectedCompletionDigest(second.completion));
});

test('rejects session, event, reference, completion, and post-seal drift', () => {
  const original = block('drift'); const alteredSession = structuredClone(original);
  alteredSession.session.sessionContextTags.room = [opaque('other-room')];
  alteredSession.events[0].authorizationContextTags.room = [opaque('other-room')];
  const one = accumulator(); one.accept(original);
  assert.throws(() => one.accept(alteredSession), { code: 'm4_cross_phase_identity_in_memory_accumulator_session_drift' });
  const alteredEvent = structuredClone(original); alteredEvent.events[0].role = 'assistant'; alteredEvent.events[0].direction = 'outbound';
  const two = accumulator(); two.accept(original);
  assert.throws(() => two.accept(alteredEvent), { code: 'm4_cross_phase_identity_in_memory_accumulator_event_drift' });
  const badReference = structuredClone(original); badReference.events[0].state = 'edited'; badReference.events[0].revision = 2;
  badReference.events[0].replacesLegacyEventId = event('not-present');
  assert.throws(() => accumulator().accept(badReference), { code: 'm4_cross_phase_identity_in_memory_accumulator_reference_invalid' });
  assert.throws(() => one.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: { ...completion(1), complete: false } }),
    { code: 'm4_cross_phase_identity_in_memory_accumulator_scan_incomplete' });
  assert.throws(() => one.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(3) }),
    { code: 'm4_cross_phase_identity_in_memory_accumulator_scan_mismatch' });
  const sealed = one.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  assert.equal(sealed.registry.authority.coverage.eventCount, 1);
  assert.throws(() => one.accept(original), { code: 'm4_cross_phase_identity_in_memory_accumulator_sealed' });
  assert.throws(() => one.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) }),
    { code: 'm4_cross_phase_identity_in_memory_accumulator_sealed' });
});

test('enforces global entry bounds before mutating state', () => {
  const value = accumulator({ maxEntries: 2 }); value.accept(block('one'));
  assert.throws(() => value.accept(block('two')), { code: 'm4_cross_phase_identity_in_memory_accumulator_bounds_exceeded' });
  const sealed = value.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(1) });
  assert.equal(sealed.registry.authority.coverage.eventCount, 1);
});

test('splits deterministic registry pages at the entry boundary', () => {
  const value = accumulator(); const sharedSession = compactId('ses', 1); const tags = [sourceTag('boundary')];
  for (let index = 0; index < 10_001; index += 1) {
    value.accept(block(`boundary:${index}`, { legacySessionId: sharedSession, legacyEventId: compactId('evt', index), sourceTags: tags }));
  }
  const sealed = value.seal({ coveredThrough: '2026-07-22T00:00:00Z', backfillBinding: binding(), scanCompletion: completion(10_001) });
  const eventPages = sealed.registry.pages.filter(page => page.entryKind === 'event');
  assert.deepEqual(eventPages.map(page => page.events.length), [10_000, 1]);
  assert.equal(sealed.completion.coverage.pages.length, sealed.registry.authority.pages.length);
});

test('rejects an in-memory cap above the hard operational limit', () => {
  assert.throws(() => accumulator({ maxEntries: M4_CROSS_PHASE_IDENTITY_IN_MEMORY_ACCUMULATOR_MAX_TOTAL_ENTRIES + 1 }),
    { code: 'm4_cross_phase_identity_in_memory_accumulator_request_invalid' });
});
