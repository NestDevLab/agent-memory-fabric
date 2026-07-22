import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { selectLogicalMessage } from '../src/ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { runM4PreservedGroupReplay } from '../src/migration/m4-preserved-group-replay.mjs';

const KEY = Buffer.alloc(32, 7);
const sha = value => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
const opaque = value => `hmac-sha256:k1:${String(value).repeat(64).slice(0, 64)}`;
const eventId = value => `evt_${String(value).repeat(64).slice(0, 64)}`;
const logicalId = value => `lmsg_${String(value).repeat(64).slice(0, 64)}`;
const sessionId = value => `ses_${String(value).repeat(64).slice(0, 64)}`;
const authority = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: sha('authority') };

function projection(value, options = {}) {
  const deletion = options.deletion === true;
  const id = eventId(value);
  return {
    schema: 'amf.raw-event-projection/v2', eventId: id, sessionId: sessionId('b'),
    logicalMessageId: options.logicalMessageId ?? logicalId('c'), logicalMessageAliases: [],
    derivationVersion: 'amf-logical-message/v1', keyVersion: 'k1', sourceKind: options.sourceKind ?? 'codex',
    observationClass: options.observationClass ?? 'native', direction: options.direction ?? 'inbound',
    conversationKind: 'dm', contextTags: { sender: [opaque('a')], conversation: [opaque('b')] },
    subtype: deletion ? 'message.deleted' : 'message', occurredAt: `2026-01-01T00:00:0${options.sequence ?? 1}Z`,
    editedAt: options.editedAt ?? null, nativeRevision: options.nativeRevision ?? (options.sequence ?? 1),
    sourceSequence: options.sequence ?? 1, authoritativeDeletion: deletion, role: options.role ?? (deletion ? 'unknown' : 'user'),
    contentType: options.contentType ?? (deletion ? 'none' : 'text'), contentParts: deletion ? 0 : 1,
    hasContent: !deletion, normalizationVersion: 'amf-observation-normalization/v1',
    normalizedPayloadDigest: options.normalizedPayloadDigest ?? opaque(value),
  };
}

function observation(value, options = {}) {
  const item = projection(value, options);
  return { eventId: item.eventId, sessionId: item.sessionId, sourceTag: `migration:${'a'.repeat(64)}`,
    migrationSequence: options.sequence ?? 1, projection: item,
    visibleText: item.authoritativeDeletion ? null : (options.visibleText ?? `text ${value}`) };
}

function group(observations, token = String(observations[0].eventId.at(-1))) {
  const selected = selectLogicalMessage(observations.map(item => ({ eventId: item.eventId, projection: item.projection })));
  const logical = { ...selected, eventIds: observations.map(item => item.eventId).sort() };
  const members = observations.map((item, position) => ({ origin: 'v2-archive', position,
    legacyEventId: item.eventId,
    recordDigest: sha(canonicalJson({ schema: 'amf.m4-group-locator/v1', authorityDigest: authority.authorityDigest,
      origin: 'v2-archive', position, legacyEventId: item.eventId })), projectionDigest: sha(canonicalJson(item.projection))
  })).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return { descriptor: { schema: 'amf.m4-logical-group-descriptor/v1', authorityDigest: authority.authorityDigest,
    groupDigest: sha(canonicalJson({ schema: 'amf.m4-logical-group-binding/v1', authorityDigest: authority.authorityDigest,
      logicalMessageId: logical.logicalMessageId, members })), logicalMessageId: logical.logicalMessageId, members },
  logical, observations };
}

class Source {
  constructor(groups, authorityDigest = authority.authorityDigest) { this.groups = groups; this.authorityDigest = authorityDigest; }
  async open(input) {
    assert.equal(input.authorityDigest, this.authorityDigest);
    const start = input.after === null ? 0 : this.groups.findIndex(item => item.descriptor.groupDigest === input.after) + 1;
    const values = this.groups.slice(Math.max(0, start));
    return { schema: 'amf.m4-preserved-group-replay-source/v1', authorityDigest: this.authorityDigest,
      groups: (async function* () { for (const item of values) yield item; })(),
      completion: async () => ({ schema: 'amf.m4-preserved-group-replay-source/v1', authorityDigest: this.authorityDigest, complete: true }) };
  }
}

class Outbox {
  constructor({ conflictAt = null } = {}) { this.events = new Map(); this.delivered = []; this.conflictAt = conflictAt; this.enqueues = 0; }
  async enqueue(event) {
    this.enqueues += 1;
    if (this.enqueues === this.conflictAt) return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'conflict', duplicate: false };
    const prior = this.events.get(event.eventId);
    if (prior && prior !== event.integrity.payloadDigest) return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'conflict', duplicate: false };
    if (prior) return { eventId: event.eventId, payloadDigest: prior, state: 'acknowledged', duplicate: true };
    this.events.set(event.eventId, event.integrity.payloadDigest);
    return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'pending', duplicate: false };
  }
  async deliver(eventId, sink) {
    const payloadDigest = this.events.get(eventId); this.delivered.push(eventId);
    await sink.deliver({ eventId, integrity: { payloadDigest } }, { idempotencyKey: eventId, payloadDigest });
    return { eventId, payloadDigest, state: 'acknowledged', duplicate: false };
  }
}

class Checkpoints {
  constructor({ failOnce = false } = {}) { this.value = null; this.failOnce = failOnce; }
  async load() { return this.value; }
  async commit(value) { if (this.failOnce) { this.failOnce = false; throw new Error('crash'); } this.value = structuredClone(value); return structuredClone(value); }
}

function input(groups, options = {}) {
  return { authority, source: new Source(groups, options.sourceAuthority ?? authority.authorityDigest), outbox: options.outbox ?? new Outbox(),
    sink: { async deliver() { return {}; } }, checkpointStore: options.checkpoints ?? new Checkpoints(),
    integrityFor: async ({ eventId, state, revision }) => ({ keyId: 'k1', key: KEY, sentAt: '2026-01-01T01:00:00Z', nonce: `${state}${revision}${eventId.slice(5, 16)}`.padEnd(16, '0').slice(0, 16) }),
    ...(options.maxGroups === undefined ? {} : { maxGroups: options.maxGroups }),
    ...(options.maxObservations === undefined ? {} : { maxObservations: options.maxObservations }),
    ...(options.maxOutputEvents === undefined ? {} : { maxOutputEvents: options.maxOutputEvents }) }; }

test('delivers projector edit and tombstone order before one group checkpoint', async () => {
  const items = [observation('1', { sequence: 1 }), observation('2', { sequence: 2, nativeRevision: 2 }), observation('3', { sequence: 3, nativeRevision: 3, deletion: true })];
  const outbox = new Outbox(); const checkpoints = new Checkpoints();
  const result = await runM4PreservedGroupReplay(input([group(items)], { outbox, checkpoints }));
  assert.equal(result.groups, 1); assert.deepEqual(outbox.delivered.length, 3); assert.ok(checkpoints.value); assert.equal(result.outputEvents, 3);
  assert.equal(JSON.stringify(result).includes('text '), false);
  assert.equal(JSON.stringify(checkpoints.value).includes('text '), false);
});

test('binds opaque runtime observations to closed-source members without conflating domains', async () => {
  const item = group([observation('a', { sourceKind: 'codex' })], 'opaque-origin');
  assert.equal(item.descriptor.members[0].origin, 'v2-archive');
  assert.equal(item.observations[0].projection.sourceKind, 'codex');
  assert.match(item.observations[0].sourceTag, /^migration:/);
  const result = await runM4PreservedGroupReplay(input([item]));
  assert.equal(result.groups, 1);
});

test('deduplicates equal payloads, excludes non-conversation groups, and records conflicts', async () => {
  const duplicate = group([observation('4', { normalizedPayloadDigest: opaque('d') }), observation('5', { sequence: 2, nativeRevision: 1, normalizedPayloadDigest: opaque('d') })], 'duplicate');
  const excluded = group([observation('6', { role: 'tool', visibleText: 'ignored' })], 'excluded');
  const conflict = group([observation('7'), observation('8', { sequence: 2, sourceKind: 'claude', nativeRevision: 1 })], 'conflict');
  const outbox = new Outbox({ conflictAt: 2 }); const result = await runM4PreservedGroupReplay(input([duplicate, excluded, conflict], { outbox }));
  assert.equal(result.groups, 3); assert.equal(result.outputEvents, 3); assert.equal(outbox.delivered.length, 2);
});

test('replays durable outcomes after a crash before checkpoint without duplicate delivery', async () => {
  const item = group([observation('9')], 'crash'); const outbox = new Outbox(); const checkpoints = new Checkpoints({ failOnce: true });
  await assert.rejects(() => runM4PreservedGroupReplay(input([item], { outbox, checkpoints })), { code: 'm4_group_checkpoint_commit_failed' });
  assert.equal(outbox.delivered.length, 1);
  const resumed = await runM4PreservedGroupReplay(input([item], { outbox, checkpoints }));
  assert.equal(resumed.groups, 1); assert.equal(outbox.delivered.length, 1); assert.ok(checkpoints.value);
});

test('fails closed on authority drift and hard bounds before durable delivery', async () => {
  const item = group([observation('a')], 'bound'); const outbox = new Outbox();
  await assert.rejects(() => runM4PreservedGroupReplay(input([item], { outbox, maxObservations: 0 })), { code: 'm4_group_request_invalid' });
  await assert.rejects(() => runM4PreservedGroupReplay(input([item], { sourceAuthority: sha('other') })), { code: 'm4_group_source_open_failed' });
  const first = group([observation('b')], 'first');
  const oversized = group([observation('c'), observation('d', { sequence: 2, nativeRevision: 2 })], 'observation-bound');
  const observationBoundary = await runM4PreservedGroupReplay(input([first, oversized], { outbox, maxObservations: 2 }));
  assert.equal(observationBoundary.complete, false); assert.equal(observationBoundary.groups, 1); assert.equal(outbox.delivered.length, 1);
  const multiEvent = group([observation('d'), observation('e', { sequence: 2, nativeRevision: 2 })], 'output-bound');
  const outputOutbox = new Outbox();
  const outputBoundary = await runM4PreservedGroupReplay(input([first, multiEvent], { outbox: outputOutbox, maxOutputEvents: 2 }));
  assert.equal(outputBoundary.complete, false); assert.equal(outputBoundary.groups, 1); assert.equal(outputOutbox.delivered.length, 1);
});

test('rejects materialization whose private observation membership differs from the descriptor', async () => {
  const item = group([observation('f')], 'mismatch');
  item.observations[0] = observation('a', { logicalMessageId: item.logical.logicalMessageId });
  await assert.rejects(() => runM4PreservedGroupReplay(input([item])), { code: 'm4_group_materialization_mismatch' });
});

test('preserves the primary failure when iterator close also fails', async () => {
  const item = group([observation('f')], 'close');
  item.observations[0] = observation('a', { logicalMessageId: item.logical.logicalMessageId });
  const dependencies = input([item]);
  dependencies.source = { async open() {
    return { schema: 'amf.m4-preserved-group-replay-source/v1', authorityDigest: authority.authorityDigest,
      groups: (async function* () { try { yield item; } finally { throw new Error('close failed'); } })(),
      completion: async () => ({ schema: 'amf.m4-preserved-group-replay-source/v1', authorityDigest: authority.authorityDigest, complete: true }) };
  } };
  await assert.rejects(() => runM4PreservedGroupReplay(dependencies), { code: 'm4_group_materialization_mismatch' });
});
