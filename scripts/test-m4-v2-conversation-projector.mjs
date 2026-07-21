import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { validateConversationEvent } from '../src/conversation-event-v3.mjs';
import { selectLogicalMessage } from '../src/ingest/raw-projection-v2.mjs';
import { projectM4V2LogicalGroup } from '../src/migration/m4-v2-conversation-projector.mjs';

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
    occurredAt: options.occurredAt ?? `2026-01-01T00:00:0${options.sequence ?? 1}Z`,
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
    logical: logical([accepted]), observations: [{ ...accepted, visibleText: 'x'.repeat(65_537) }], integrityFor: integrityRecorder().integrityFor,
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
