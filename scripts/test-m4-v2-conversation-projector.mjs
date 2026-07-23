import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { validateConversationEvent } from '../src/conversation-event-v3.mjs';
import { selectLogicalMessage } from '../src/ingest/raw-projection-v2.mjs';
import {
  deriveM4V3EventIdFromLegacyEventId,
  projectM4V2LogicalGroup,
} from '../src/migration/m4-v2-conversation-projector.mjs';
import { createM4CrossPhaseIdentityInMemoryAccumulator } from '../src/migration/m4-cross-phase-identity-in-memory-accumulator.mjs';

const fixture = JSON.parse(fs.readFileSync(
  new URL('./fixtures/m4-v2-conversation-projector.synthetic.json', import.meta.url),
  'utf8',
));
const KEY = Buffer.alloc(32, 7);
const opaque = char => `hmac-sha256:synthetic-k1:${char.repeat(64)}`;
const sourceTag = char => `synthetic-k1:${char.repeat(64)}`;
const v2EventId = char => `evt_${char.repeat(64)}`;
const sessionId = char => `ses_${char.repeat(64)}`;
const logicalId = char => `lmsg_${char.repeat(64)}`;
const normalizedDigest = char => `hmac-sha256:normalized-k1:${char.repeat(64)}`;

function projection(char, options = {}) {
  const role = options.role ?? 'user';
  const deletion = options.authoritativeDeletion ?? false;
  return {
    schema: 'amf.raw-event-projection/v2',
    eventId: options.eventId ?? v2EventId(char),
    sessionId: options.sessionId ?? sessionId('b'),
    logicalMessageId: options.logicalMessageId ?? logicalId('c'),
    logicalMessageAliases: [],
    derivationVersion: 'amf-logical-message/v1',
    keyVersion: 'synthetic-k1',
    sourceKind: options.sourceKind ?? 'codex',
    observationClass: options.observationClass ?? 'native',
    direction: options.direction ?? (role === 'assistant' ? 'outbound' : 'inbound'),
    conversationKind: options.conversationKind ?? 'dm',
    contextTags: options.contextTags ?? {
      sender: [opaque('d')], conversation: [opaque('e')], actor: [opaque('f')],
    },
    subtype: deletion ? 'message.deleted' : 'message',
    occurredAt: Object.hasOwn(options, 'occurredAt')
      ? options.occurredAt
      : `2026-01-01T00:00:0${options.sequence ?? 1}Z`,
    editedAt: options.editedAt ?? null,
    nativeRevision: Object.hasOwn(options, 'nativeRevision') ? options.nativeRevision : 1,
    sourceSequence: options.sourceSequence ?? options.sequence ?? 1,
    authoritativeDeletion: deletion,
    role,
    contentType: options.contentType ?? (deletion ? 'none' : 'text'),
    contentParts: options.contentParts ?? (deletion ? 0 : 1),
    hasContent: options.hasContent ?? !deletion,
    normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: options.normalizedPayloadDigest ?? normalizedDigest(char),
  };
}

function observation(char, options = {}) {
  const item = projection(char, options);
  return {
    eventId: item.eventId,
    sessionId: item.sessionId,
    sourceTag: options.sourceTag ?? sourceTag('a'),
    migrationSequence: options.migrationSequence ?? options.sequence ?? 1,
    projection: item,
    visibleText: options.visibleText ?? (item.authoritativeDeletion ? null : `synthetic text ${char}`),
  };
}

function logical(observations) {
  const selection = selectLogicalMessage(observations.map(item => ({
    eventId: item.eventId,
    projection: item.projection,
  })));
  return { ...selection, eventIds: observations.map(item => item.eventId).sort() };
}

function integrityRecorder() {
  const calls = [];
  return {
    calls,
    integrityFor: async input => {
      calls.push(structuredClone(input));
      return {
        keyId: 'synthetic-k1',
        key: KEY,
        sentAt: '2026-01-01T00:10:00Z',
        nonce: `nonce${String(calls.length).padStart(11, '0')}`,
      };
    },
  };
}

async function project(observations, options = {}) {
  const recorder = options.recorder ?? integrityRecorder();
  const result = await projectM4V2LogicalGroup({
    logical: options.logical ?? logical(observations),
    observations,
    integrityFor: options.integrityFor ?? recorder.integrityFor,
    identityCollector: options.identityCollector ?? null,
  });
  return { result, recorder };
}

test('projects an active event through production validation and fixture stays executable', async () => {
  const active = observation('1');
  const { result, recorder } = await project([active]);
  assert.equal(result.outcome, 'projected');
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].state, 'active');
  assert.equal(result.evidence.states.replacement, 0);
  assert.deepEqual(recorder.calls.map(call => Object.keys(call).sort()), [[
    'eventId', 'legacyEventId', 'revision', 'state',
  ]]);
  assert.equal(validateConversationEvent(result.events[0], {
    resolveIntegrityKey: keyId => keyId === 'synthetic-k1' ? KEY : null,
  }).eventId, result.events[0].eventId);

  assert.equal(fixture.schema, 'amf.m4-v2-conversation-projector-fixture/v1');
  const fixtureResult = await project(fixture.observations);
  assert.equal(fixtureResult.result.outcome, 'projected');
});

test('normalizes offset timestamps to canonical UTC without losing nine-digit fractions', async () => {
  const offset = observation('a', {
    occurredAt: '2026-01-02T00:15:16.123456789+02:30',
    migrationSequence: 1,
  });
  const { result } = await project([offset]);
  assert.equal(result.events[0].sourceOccurredAt, '2026-01-01T21:45:16.123456789Z');
  assert.equal(result.events[0].occurredAt, '2026-01-01T21:45:16.123456789Z');
  assert.equal(validateConversationEvent(result.events[0], {
    resolveIntegrityKey: () => KEY,
  }).sourceOccurredAt, '2026-01-01T21:45:16.123456789Z');

  const earlyYear = observation('b', { occurredAt: '0099-01-01T00:00:00.000000001Z' });
  const earlyResult = await project([earlyYear]);
  assert.equal(earlyResult.result.events[0].sourceOccurredAt, '0099-01-01T00:00:00.000000001Z');
});

test('excludes untimed non-conversation metadata before temporal normalization', async () => {
  const metadata = observation('c', {
    role: 'unknown',
    direction: 'unknown',
    contentType: 'none',
    contentParts: 0,
    hasContent: false,
    occurredAt: null,
    visibleText: null,
  });
  const { result, recorder } = await project([metadata]);
  assert.equal(result.outcome, 'excluded');
  assert.equal(result.reason, 'preferred_ineligible');
  assert.equal(result.evidence.excludedCount, 1);
  assert.equal(recorder.calls.length, 0);
});

test('deduplicates delivery handoffs and retains the deterministic native representative', async () => {
  const native = observation('2', { normalizedPayloadDigest: normalizedDigest('a'), migrationSequence: 2 });
  const handoff = observation('3', {
    observationClass: 'delivery-handoff', sourceKind: 'principia', normalizedPayloadDigest: normalizedDigest('a'),
    migrationSequence: 1,
  });
  const { result, recorder } = await project([handoff, native]);
  assert.equal(result.events.length, 1);
  assert.equal(result.evidence.deduplicatedCount, 1);
  assert.equal(result.events[0].eventId.includes(native.eventId), false);
  assert.equal(recorder.calls[0].legacyEventId, native.eventId);
});

test('deduplicates a production-shaped 4114-observation logical group within the bounded input', async () => {
  const observations = Array.from({ length: 4_114 }, (_, index) => {
    const eventId = `evt_${(index + 1).toString(16).padStart(64, '0')}`;
    const item = observation('1', {
      eventId,
      migrationSequence: index + 1,
      sourceSequence: index + 1,
      normalizedPayloadDigest: normalizedDigest('1'),
      visibleText: 'stable synthetic text',
    });
    return item;
  });
  const { result, recorder } = await project(observations);
  assert.equal(result.outcome, 'projected');
  assert.equal(result.events.length, 1);
  assert.equal(result.evidence.deduplicatedCount, 4_113);
  assert.equal(recorder.calls.length, 1);
});

test('maps native revisions into edits and ambiguous variants into conflicts', async () => {
  const first = observation('4', { sequence: 1, migrationSequence: 1, nativeRevision: 1 });
  const edited = observation('5', { sequence: 2, migrationSequence: 2, nativeRevision: 2 });
  const chain = await project([first, edited]);
  assert.deepEqual(chain.result.events.map(event => event.state), ['active', 'edited']);
  assert.equal(chain.result.events[1].replacesEventId, chain.result.events[0].eventId);
  assert.equal(chain.result.events[1].revision, 2);
  assert.equal(chain.recorder.calls.length, 2);

  const conflictA = observation('6', { sourceKind: 'codex', sequence: 1, migrationSequence: 1 });
  const conflictB = observation('7', { sourceKind: 'claude', sequence: 2, migrationSequence: 2 });
  const conflicts = await project([conflictA, conflictB]);
  assert.deepEqual(conflicts.result.events.map(event => event.state), ['active', 'conflict']);
  assert.deepEqual(conflicts.result.events[1].conflictsWithEventIds, [conflicts.result.events[0].eventId]);

  const editedFirst = observation('a', { nativeRevision: null, migrationSequence: 1, sequence: 1 });
  const editedLater = observation('b', {
    nativeRevision: null,
    editedAt: '2026-01-01T00:00:02.000000001Z',
    occurredAt: '2026-01-01T00:00:01Z',
    migrationSequence: 2,
    sequence: 2,
  });
  const editedAtChain = await project([editedFirst, editedLater]);
  assert.deepEqual(editedAtChain.result.events.map(event => event.state), ['active', 'edited']);
});

test('maps authoritative contentType none deletion from its eligible predecessor semantics', async () => {
  const first = observation('8', { sequence: 1, migrationSequence: 1, nativeRevision: 1, role: 'assistant' });
  const edited = observation('9', { sequence: 2, migrationSequence: 2, nativeRevision: 2, role: 'assistant' });
  const deletion = observation('a', {
    sequence: 3,
    migrationSequence: 3,
    authoritativeDeletion: true,
    role: 'unknown',
    direction: 'internal',
    conversationKind: 'unknown',
    nativeRevision: 3,
  });
  const { result } = await project([first, edited, deletion]);
  assert.deepEqual(result.events.map(event => event.state), ['active', 'edited', 'tombstone']);
  const tombstone = result.events.at(-1);
  assert.equal(tombstone.role, 'assistant');
  assert.equal(tombstone.direction, 'outbound');
  assert.equal(tombstone.conversationKind, 'dm');
  assert.equal(tombstone.visibleText, undefined);
  assert.equal(tombstone.tombstonesEventId, result.events[1].eventId);
});

test('uses native revision when a deletion carries an earlier editedAt sentinel at the original timestamp', async () => {
  const occurredAt = '2026-07-13T06:58:00.369Z';
  const predecessor = observation('b', {
    sourceKind: 'hermes',
    occurredAt,
    nativeRevision: 1,
    migrationSequence: 2,
  });
  const deletion = observation('a', {
    sourceKind: 'hermes',
    occurredAt,
    editedAt: '1970-01-01T00:00:00.000Z',
    nativeRevision: 2,
    migrationSequence: 1,
    authoritativeDeletion: true,
  });
  const { result } = await project([deletion, predecessor]);
  assert.deepEqual(result.events.map(event => event.state), ['active', 'tombstone']);
  assert.equal(result.events.at(-1).sourceOccurredAt, occurredAt);
  assert.equal(result.events.at(-1).tombstonesEventId, result.events[0].eventId);
});

test('projects a colliding logical identity independently for each signed legacy session', async () => {
  const first = observation('c', {
    sourceKind: 'hermes',
    sessionId: sessionId('1'),
    occurredAt: '2026-07-09T10:27:08.123Z',
    migrationSequence: 1,
  });
  const second = observation('d', {
    sourceKind: 'hermes',
    sessionId: sessionId('2'),
    occurredAt: '2026-07-12T15:34:11.059Z',
    migrationSequence: 2,
  });
  const blocks = [];
  const { result } = await project([first, second], {
    identityCollector: { async accept(block) { blocks.push(block); } },
  });
  assert.deepEqual(result.events.map(event => event.state), ['active', 'active']);
  assert.equal(new Set(result.events.map(event => event.conversationId)).size, 2);
  assert.deepEqual(result.evidence, {
    inputCount: 2,
    eligibleCount: 2,
    outputCount: 2,
    deduplicatedCount: 0,
    excludedCount: 0,
    states: {
      active: 2,
      edited: 0,
      replacement: 0,
      tombstone: 0,
      conflict: 0,
    },
  });
  assert.equal(blocks.length, 2);
  assert.deepEqual(blocks.map(block => block.session.legacySessionId).sort(), [
    first.sessionId,
    second.sessionId,
  ].sort());
});

test('fails closed for deletion over conflicts and excludes preferred ineligible groups', async () => {
  const left = observation('b', { sourceKind: 'codex', sequence: 1, migrationSequence: 1 });
  const right = observation('c', { sourceKind: 'claude', sequence: 2, migrationSequence: 2 });
  const deletion = observation('d', { authoritativeDeletion: true, sequence: 3, migrationSequence: 3 });
  await assert.rejects(() => project([left, right, deletion]), {
    code: 'm4_v2_projector_deletion_conflict_history',
  });

  const ineligible = observation('e', { role: 'system', migrationSequence: 1 });
  const eligible = observation('f', { role: 'user', migrationSequence: 2 });
  const excluded = await project([ineligible, eligible]);
  assert.deepEqual(excluded.result.events, []);
  assert.equal(excluded.result.reason, 'preferred_ineligible');
  for (const mismatch of [
    observation('a', { role: 'user', direction: 'outbound' }),
    observation('b', { role: 'assistant', direction: 'inbound' }),
  ]) {
    const result = await project([mismatch]);
    assert.equal(result.result.reason, 'preferred_ineligible');
  }
});

test('strict edit identity drift maps variants to conflicts', async () => {
  const first = observation('c', { nativeRevision: 1, migrationSequence: 1 });
  const variants = [
    observation('d', { nativeRevision: 2, migrationSequence: 2, role: 'assistant' }),
    observation('e', { nativeRevision: 2, migrationSequence: 2, sourceTag: sourceTag('9') }),
    observation('f', {
      nativeRevision: 2,
      migrationSequence: 2,
      contextTags: { sender: [opaque('d')], conversation: [opaque('8')] },
    }),
  ];
  for (const variant of variants) {
    const result = await project([first, variant]);
    assert.deepEqual(result.result.events.map(event => event.state), ['active', 'conflict']);
  }
});

test('strips ineligible observations and rejects wrapper, logical, cross-binding, bounds, and text defects', async () => {
  const accepted = observation('1', { migrationSequence: 1 });
  const ignored = observation('2', { role: 'tool', migrationSequence: 2 });
  const filtered = await project([accepted, ignored]);
  assert.equal(filtered.result.events.length, 1);
  assert.equal(filtered.result.evidence.excludedCount, 1);

  const invalids = [
    ...['raw', 'contentId', 'storageRef', 'path', 'envelope', 'payload'].map(key => ({ ...accepted, [key]: 'forbidden' })),
    { ...accepted, visibleText: '   ' },
    { ...accepted, migrationSequence: -1 },
    { ...accepted, sourceTag: 'literal-tag' },
    { ...accepted, sourceTag: opaque('a') },
    { ...accepted, sessionId: sessionId('z') },
  ];
  for (const invalid of invalids) {
    await assert.rejects(() => projectM4V2LogicalGroup({
      logical: logical([accepted]), observations: [invalid], integrityFor: integrityRecorder().integrityFor,
    }), /m4_v2_projector_(?:observation_invalid|logical_drift)/);
  }
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: { ...logical([accepted]), payloadConflict: true }, observations: [accepted], integrityFor: integrityRecorder().integrityFor,
  }), { code: 'm4_v2_projector_logical_drift' });
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: { ...logical([accepted]), eventIds: [v2EventId('9')] }, observations: [accepted], integrityFor: integrityRecorder().integrityFor,
  }), { code: 'm4_v2_projector_logical_drift' });
  const otherSession = observation('3', { sessionId: sessionId('a'), migrationSequence: 3 });
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: logical([accepted, otherSession]), observations: [accepted, otherSession], integrityFor: integrityRecorder().integrityFor,
  }), { code: 'm4_v2_projector_observation_invalid' });
  const duplicateSequence = observation('4', { migrationSequence: accepted.migrationSequence });
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: logical([accepted, duplicateSequence]), observations: [accepted, duplicateSequence], integrityFor: integrityRecorder().integrityFor,
  }), { code: 'm4_v2_projector_observation_invalid' });
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: logical([accepted]), observations: [{ ...accepted, visibleText: 'x'.repeat(131_073) }], integrityFor: integrityRecorder().integrityFor,
  }), { code: 'm4_v2_projector_observation_invalid' });
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: logical([accepted, { ...accepted, migrationSequence: 3 }]),
    observations: [accepted, { ...accepted, migrationSequence: 3 }], integrityFor: integrityRecorder().integrityFor,
  }), /m4_v2_projector_(?:logical_invalid|observation_invalid)/);
});

test('derived identifiers ignore text/timestamps but bind opaque IDs and preserve contexts', async () => {
  const baseline = observation('3', { visibleText: 'synthetic short text', occurredAt: '2026-01-01T00:00:01Z' });
  const changed = observation('3', { visibleText: 'synthetic changed text', occurredAt: '2026-01-02T00:00:01Z' });
  const otherId = observation('4');
  const first = await project([baseline]);
  const second = await project([changed]);
  const third = await project([otherId]);
  assert.equal(first.result.events[0].eventId, second.result.events[0].eventId);
  assert.equal(first.result.events[0].conversationId, second.result.events[0].conversationId);
  assert.notEqual(first.result.events[0].eventId, third.result.events[0].eventId);
  assert.deepEqual(first.result.events[0].authorizationContextTags, baseline.projection.contextTags);
  assert.equal(Object.hasOwn(first.result.events[0], 'threadId'), false);
  const sourceChanged = observation('3', { sourceTag: sourceTag('9') });
  const changedSource = await project([sourceChanged]);
  assert.notEqual(first.result.events[0].sourceInstanceId, changedSource.result.events[0].sourceInstanceId);

  const filtered = observation('5', {
    role: 'system',
    sourceTag: sourceTag('8'),
    nativeRevision: 0,
    sourceSequence: 0,
    migrationSequence: 0,
  });
  const withFiltered = await project([baseline, filtered]);
  assert.deepEqual(
    withFiltered.result.events.map(({ logicalDigest, integrity, ...event }) => event),
    first.result.events.map(({ logicalDigest, integrity, ...event }) => event),
  );
  assert.notEqual(withFiltered.result.evidence.excludedCount, first.result.evidence.excludedCount);
});

test('deletion ordering, deduplication, conflicts, and evidence arithmetic fail closed', async () => {
  const predecessor = observation('6', { nativeRevision: 1, migrationSequence: 2, sequence: 2 });
  const earlyDeletion = observation('7', {
    authoritativeDeletion: true,
    nativeRevision: 2,
    migrationSequence: 1,
    sequence: 1,
  });
  const earlyRecorder = integrityRecorder();
  await assert.rejects(() => project([predecessor, earlyDeletion], { recorder: earlyRecorder }), {
    code: 'm4_v2_projector_deletion_order_invalid',
  });
  assert.equal(earlyRecorder.calls.length, 0);

  const first = observation('8', { nativeRevision: 1, migrationSequence: 1, sequence: 1 });
  const deletedOne = observation('9', {
    authoritativeDeletion: true,
    nativeRevision: 2,
    migrationSequence: 2,
    sequence: 2,
    normalizedPayloadDigest: normalizedDigest('a'),
  });
  const deletedTwo = observation('a', {
    authoritativeDeletion: true,
    nativeRevision: 3,
    migrationSequence: 3,
    sequence: 3,
    normalizedPayloadDigest: normalizedDigest('a'),
  });
  const duplicate = await project([first, deletedOne, deletedTwo]);
  assert.equal(duplicate.result.events.at(-1).state, 'tombstone');
  assert.equal(duplicate.result.evidence.deduplicatedCount, 1);
  assert.equal(
    duplicate.result.evidence.inputCount,
    duplicate.result.evidence.outputCount + duplicate.result.evidence.deduplicatedCount + duplicate.result.evidence.excludedCount,
  );

  const conflictingDeletion = { ...deletedTwo, projection: {
    ...deletedTwo.projection,
    normalizedPayloadDigest: normalizedDigest('b'),
  } };
  const conflictRecorder = integrityRecorder();
  await assert.rejects(() => project([first, deletedOne, conflictingDeletion], { recorder: conflictRecorder }), {
    code: 'm4_v2_projector_deletion_conflict',
  });
  assert.equal(conflictRecorder.calls.length, 0);

  const sourceDriftDeletion = observation('c', {
    authoritativeDeletion: true,
    nativeRevision: 2,
    migrationSequence: 3,
    sequence: 3,
    sourceTag: sourceTag('9'),
  });
  const bindingRecorder = integrityRecorder();
  await assert.rejects(() => project([predecessor, sourceDriftDeletion], { recorder: bindingRecorder }), {
    code: 'm4_v2_projector_deletion_binding_invalid',
  });
  assert.equal(bindingRecorder.calls.length, 0);
});

test('same-digest semantic drift fails before representative selection or integrity', async () => {
  const first = observation('d', {
    migrationSequence: 1,
    normalizedPayloadDigest: normalizedDigest('d'),
  });
  const changedRole = observation('e', {
    role: 'assistant',
    migrationSequence: 2,
    nativeRevision: 2,
    normalizedPayloadDigest: normalizedDigest('d'),
  });
  const recorder = integrityRecorder();
  await assert.rejects(() => project([first, changedRole], { recorder }), {
    code: 'm4_v2_projector_digest_semantics_invalid',
  });
  assert.equal(recorder.calls.length, 0);

  const changedContext = observation('f', {
    migrationSequence: 2,
    nativeRevision: 2,
    normalizedPayloadDigest: normalizedDigest('d'),
    contextTags: { sender: [opaque('d')], conversation: [opaque('9')] },
  });
  await assert.rejects(() => project([first, changedContext], { recorder: integrityRecorder() }), {
    code: 'm4_v2_projector_digest_semantics_invalid',
  });
});

test('conflict output bound fails before integrity callbacks', async () => {
  const variants = Array.from({ length: 34 }, (_, index) => {
    const hex = index.toString(16).padStart(64, '0');
    return observation('1', {
      eventId: `evt_${hex}`,
      normalizedPayloadDigest: `hmac-sha256:normalized-k1:${hex}`,
      sourceKind: index % 2 === 0 ? 'codex' : 'claude',
      nativeRevision: index + 1,
      sourceSequence: index + 1,
      migrationSequence: index + 1,
      sequence: Math.min(index + 1, 9),
    });
  });
  const recorder = integrityRecorder();
  await assert.rejects(() => project(variants, { recorder }), {
    code: 'm4_v2_projector_conflict_bound_invalid',
  });
  assert.equal(recorder.calls.length, 0);
});

test('integrity failures are content-free and output ordering is deterministic', async () => {
  const first = observation('5', { sequence: 1, migrationSequence: 2, nativeRevision: 1 });
  const second = observation('6', { sequence: 2, migrationSequence: 3, nativeRevision: 2 });
  const one = await project([second, first]);
  const two = await project([first, second]);
  assert.deepEqual(one.result.events, two.result.events);
  await assert.rejects(() => projectM4V2LogicalGroup({
    logical: logical([first]), observations: [first], integrityFor: async () => { throw new Error('synthetic text'); },
  }), error => error.code === 'm4_v2_projector_integrity_unavailable' && error.message === 'm4_v2_projector_integrity_unavailable');
});

test('exports the stable legacy event mapping used by preserved replay', () => {
  const legacyId = v2EventId('a');
  assert.equal(
    deriveM4V3EventIdFromLegacyEventId(legacyId),
    `cevt_${crypto.createHash('sha256').update(JSON.stringify([
      'amf.m4/v2-event-id/v1',
      legacyId,
    ])).digest('hex')}`,
  );
  assert.throws(
    () => deriveM4V3EventIdFromLegacyEventId('not-a-legacy-event'),
    { code: 'm4_v2_projector_legacy_event_id_invalid' },
  );
});

test('emits a content-free identity block only for accepted projector output', async () => {
  const first = observation('c', { sequence: 1, migrationSequence: 1, nativeRevision: 1, sourceTag: sourceTag('a') });
  const edited = observation('d', { sequence: 2, migrationSequence: 2, nativeRevision: 2, sourceTag: sourceTag('a') });
  const deleted = observation('e', { sequence: 3, migrationSequence: 3, nativeRevision: 3,
    sourceTag: sourceTag('a'), authoritativeDeletion: true, role: 'unknown', direction: 'internal',
    conversationKind: 'unknown', contentType: 'none', contentParts: 0, hasContent: false, visibleText: null });
  const blocks = [];
  const { result } = await project([first, edited, deleted], { recorder: integrityRecorder(),
    identityCollector: { async accept(block) { blocks.push(block); } } });
  assert.equal(blocks.length, 1);
  const block = blocks[0];
  assert.equal(block.schema, 'amf.m4-cross-phase-projector-identity-block/v1');
  assert.deepEqual(block.events.map(item => item.eventId).sort(), result.events.map(item => item.eventId).sort());
  assert.deepEqual(block.events.map(item => item.state).sort(), result.events.map(item => item.state).sort());
  for (const item of block.events) {
    const v3 = result.events.find(event => event.eventId === item.eventId);
    assert.equal(item.conversationId, v3.conversationId);
    assert.equal(item.sourceInstanceId, v3.sourceInstanceId);
    assert.deepEqual(item.authorizationContextTags, v3.authorizationContextTags);
  }
  assert.doesNotMatch(JSON.stringify(block), /visibleText|normalizedPayloadDigest|logicalMessageId|nativeEventId|nativeSessionId|integrity|attachment/i);

  const accumulator = createM4CrossPhaseIdentityInMemoryAccumulator({ registrySecret: Buffer.alloc(32, 3) });
  await project([first, edited, deleted], { identityCollector: { accept: accumulator.accept } });
  const sealed = accumulator.seal({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${'a'.repeat(64)}`, catalogRevisionDigest: `sha256:${'b'.repeat(64)}` },
    scanCompletion: { complete: true, acceptedGroupCount: 1, excludedGroupCount: 0, traversalDigest: `sha256:${'c'.repeat(64)}` } });
  assert.deepEqual(sealed.registry.authority.coverage, { sessionCount: 1, eventCount: 3,
    pageDigest: sealed.registry.authority.coverage.pageDigest });

  const mutationInput = observation('a');
  const mutationResult = await project([mutationInput], { identityCollector: { async accept(value) {
    value.session.sessionContextTags.conversation[0] = opaque('mutated-session');
    value.events[0].authorizationContextTags.conversation[0] = opaque('mutated-event');
    value.events[0].sourceTags[0] = sourceTag('z');
  } } });
  assert.notEqual(mutationResult.result.events[0].authorizationContextTags.conversation[0], opaque('mutated-event'));
  assert.notEqual(mutationInput.projection.contextTags.conversation[0], opaque('mutated-event'));
  assert.ok(mutationResult.result.events[0].sourceInstanceId);

  const multiA = observation('7', { migrationSequence: 4, sequence: 4, sourceTag: sourceTag('a') });
  const multiB = observation('8', { migrationSequence: 5, sequence: 5, sourceTag: sourceTag('b'), sourceKind: 'claude' });
  const multi = [];
  const multiResult = await project([multiA, multiB], { identityCollector: { async accept(value) { multi.push(value); } } });
  assert.deepEqual(multi[0].events[0].sourceTags, [sourceTag('a'), sourceTag('b')].sort());
  assert.deepEqual(multi[0].events.map(item => [item.eventId, item.state]).sort(),
    multiResult.result.events.map(item => [item.eventId, item.state]).sort());
  assert.ok(multi[0].events.some(item => item.state === 'conflict'));

  let calls = 0;
  const ineligible = observation('f', { role: 'tool', direction: 'internal', visibleText: 'synthetic ineligible' });
  const excludedResult = await projectM4V2LogicalGroup({ logical: logical([ineligible]), observations: [ineligible],
    integrityFor: integrityRecorder().integrityFor, identityCollector: { async accept() { calls += 1; } } });
  assert.equal(excludedResult.outcome, 'excluded');
  assert.equal(calls, 0);
  await assert.rejects(() => projectM4V2LogicalGroup({ logical: logical([first]), observations: [first],
    integrityFor: integrityRecorder().integrityFor, identityCollector: { async accept() { throw new Error('fail'); } } }),
  { code: 'm4_v2_projector_identity_collector_failed' });
});
