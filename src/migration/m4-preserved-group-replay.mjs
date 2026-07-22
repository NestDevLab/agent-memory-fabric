import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { projectM4V2LogicalGroup } from './m4-v2-conversation-projector.mjs';

export const M4_PRESERVED_GROUP_MAX_GROUPS = 100;
export const M4_PRESERVED_GROUP_MAX_OBSERVATIONS = 1_000;
export const M4_PRESERVED_GROUP_MAX_OUTPUT_EVENTS = 1_000;

const AUTHORITY_SCHEMA = 'amf.m4-group-replay-authority/v1';
const REQUEST_SCHEMA = 'amf.m4-preserved-group-replay-request/v1';
const SOURCE_SCHEMA = 'amf.m4-preserved-group-replay-source/v1';
const DESCRIPTOR_SCHEMA = 'amf.m4-logical-group-descriptor/v1';
const CHECKPOINT_SCHEMA = 'amf.m4-group-replay-checkpoint/v1';
const RESULT_SCHEMA = 'amf.m4-group-replay-result/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const LOGICAL = /^lmsg_[a-f0-9]{64}$/;
const EVENT = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const LEGACY_EVENT = /^evt_[a-f0-9]{64}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && (typeof value === 'object' || typeof value === 'function'); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }

function authority(value) {
  if (!exact(value, ['schema', 'authorityDigest']) || value.schema !== AUTHORITY_SCHEMA || !DIGEST.test(value.authorityDigest)) fail('m4_group_authority_invalid');
  return { schema: AUTHORITY_SCHEMA, authorityDigest: value.authorityDigest };
}

function member(value) {
  if (!exact(value, ['origin', 'position', 'legacyEventId', 'recordDigest', 'projectionDigest'])
    || !['v2-archive', 'preserved-outbox', 'preserved-deadletter'].includes(value.origin)
    || !Number.isSafeInteger(value.position) || value.position < 0
    || !LEGACY_EVENT.test(value.legacyEventId) || !DIGEST.test(value.recordDigest) || !DIGEST.test(value.projectionDigest)) {
    fail('m4_group_descriptor_invalid');
  }
  return structuredClone(value);
}

function descriptorDigest(value) {
  return digest({ schema: 'amf.m4-logical-group-binding/v1', authorityDigest: value.authorityDigest,
    logicalMessageId: value.logicalMessageId, members: value.members });
}

function descriptor(value, expectedAuthority) {
  if (!exact(value, ['schema', 'authorityDigest', 'groupDigest', 'logicalMessageId', 'members'])
    || value.schema !== DESCRIPTOR_SCHEMA || value.authorityDigest !== expectedAuthority
    || !DIGEST.test(value.groupDigest) || !LOGICAL.test(value.logicalMessageId) || !Array.isArray(value.members)
    || value.members.length < 1 || value.members.length > M4_PRESERVED_GROUP_MAX_OBSERVATIONS) {
    fail('m4_group_descriptor_invalid');
  }
  const safe = { ...value, members: value.members.map(item => member(item)) };
  const identities = safe.members.map(item => item.legacyEventId);
  if (new Set(identities).size !== identities.length || canonicalJson(safe.members) !== canonicalJson([...safe.members].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))))
    || descriptorDigest(safe) !== safe.groupDigest) fail('m4_group_descriptor_invalid');
  return safe;
}

function materializedProjection(observation) {
  if (!plain(observation) || !LEGACY_EVENT.test(observation.eventId) || !plain(observation.projection)) {
    fail('m4_group_source_invalid');
  }
  return { legacyEventId: observation.eventId, projectionDigest: digest(observation.projection) };
}

function bindMaterialization(current, observations) {
  if (!Array.isArray(observations) || observations.length !== current.members.length) fail('m4_group_source_invalid');
  const expected = new Map(current.members.map(item => [item.legacyEventId, item]));
  for (const observation of observations) {
    const actual = materializedProjection(observation);
    const bound = expected.get(actual.legacyEventId);
    if (!bound || bound.projectionDigest !== actual.projectionDigest) fail('m4_group_materialization_mismatch');
    expected.delete(actual.legacyEventId);
  }
  if (expected.size !== 0) fail('m4_group_materialization_mismatch');
}

function checkpoint(value, expectedAuthority, { nullable = false } = {}) {
  if (value === null && nullable) return null;
  if (!exact(value, ['schema', 'authorityDigest', 'sequence', 'groupDigest', 'outcomeDigest'])
    || value.schema !== CHECKPOINT_SCHEMA || value.authorityDigest !== expectedAuthority
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1
    || !DIGEST.test(value.groupDigest) || !DIGEST.test(value.outcomeDigest)) fail('m4_group_checkpoint_invalid');
  return structuredClone(value);
}

function dependencies(value) {
  const required = ['authority', 'source', 'outbox', 'sink', 'checkpointStore', 'integrityFor'];
  const allowed = new Set([...required, 'maxGroups', 'maxObservations', 'maxOutputEvents']);
  if (!plain(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !allowed.has(key))) fail('m4_group_dependency_invalid');
  if (!object(value.source) || typeof value.source.open !== 'function'
    || !object(value.outbox) || typeof value.outbox.enqueue !== 'function' || typeof value.outbox.deliver !== 'function'
    || !object(value.sink) || typeof value.sink.deliver !== 'function'
    || !object(value.checkpointStore) || typeof value.checkpointStore.load !== 'function' || typeof value.checkpointStore.commit !== 'function'
    || typeof value.integrityFor !== 'function') fail('m4_group_dependency_invalid');
  return { authority: authority(value.authority), source: value.source, outbox: value.outbox, sink: value.sink,
    checkpointStore: value.checkpointStore, integrityFor: value.integrityFor };
}

function receipt(value, event) {
  if (!exact(value, ['eventId', 'payloadDigest', 'state', 'duplicate']) || value.eventId !== event.eventId
    || value.payloadDigest !== event.integrity.payloadDigest || typeof value.duplicate !== 'boolean'
    || !['pending', 'acknowledged', 'conflict'].includes(value.state)) fail('m4_group_outbox_invalid');
  return value;
}

async function terminalOutcome(deps, event) {
  let queued;
  try { queued = receipt(await deps.outbox.enqueue(event), event); } catch { fail('m4_group_outbox_failed'); }
  if (queued.state === 'conflict') return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'conflict' };
  if (queued.state === 'acknowledged') return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, state: 'duplicate' };
  let delivered;
  try { delivered = receipt(await deps.outbox.deliver(event.eventId, deps.sink), event); } catch { fail('m4_group_delivery_failed'); }
  if (delivered.state !== 'acknowledged') fail('m4_group_delivery_invalid');
  return { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest,
    state: delivered.duplicate ? 'duplicate' : 'accepted' };
}

function evidence(value) {
  if (!exact(value, ['inputCount', 'eligibleCount', 'outputCount', 'deduplicatedCount', 'excludedCount', 'states'])
    || !plain(value.states) || Object.keys(value.states).sort().join('\0') !== 'active\0conflict\0edited\0replacement\0tombstone'
    || [...['inputCount', 'eligibleCount', 'outputCount', 'deduplicatedCount', 'excludedCount'].map(key => value[key]), ...Object.values(value.states)]
      .some(item => typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0)) {
    fail('m4_group_projection_invalid');
  }
  return structuredClone(value);
}

function outcomeDigest(descriptorValue, outcome, projectionEvidence, eventOutcomes) {
  return digest({ schema: 'amf.m4-group-replay-outcome/v1', authorityDigest: descriptorValue.authorityDigest,
    groupDigest: descriptorValue.groupDigest, outcome, evidence: projectionEvidence, eventOutcomes });
}

async function openSource(deps, after, limits) {
  let value;
  try { value = await deps.source.open({ schema: REQUEST_SCHEMA, authorityDigest: deps.authority.authorityDigest,
    after, maxGroups: limits.groups, maxObservations: limits.observations, maxOutputEvents: limits.events }); }
  catch { fail('m4_group_source_open_failed'); }
  if (!exact(value, ['schema', 'authorityDigest', 'groups', 'completion']) || value.schema !== SOURCE_SCHEMA
    || value.authorityDigest !== deps.authority.authorityDigest || typeof value.completion !== 'function'
    || typeof value.groups?.[Symbol.asyncIterator] !== 'function') fail('m4_group_source_invalid');
  return value;
}

export async function runM4PreservedGroupReplay(input = {}) {
  const deps = dependencies(input);
  const limits = { groups: input.maxGroups ?? M4_PRESERVED_GROUP_MAX_GROUPS,
    observations: input.maxObservations ?? M4_PRESERVED_GROUP_MAX_OBSERVATIONS,
    events: input.maxOutputEvents ?? M4_PRESERVED_GROUP_MAX_OUTPUT_EVENTS };
  if (!Object.values(limits).every(value => Number.isSafeInteger(value) && value >= 1)
    || limits.groups > M4_PRESERVED_GROUP_MAX_GROUPS || limits.observations > M4_PRESERVED_GROUP_MAX_OBSERVATIONS
    || limits.events > M4_PRESERVED_GROUP_MAX_OUTPUT_EVENTS) fail('m4_group_request_invalid');
  let prior;
  try { prior = checkpoint(await deps.checkpointStore.load({ authorityDigest: deps.authority.authorityDigest }), deps.authority.authorityDigest, { nullable: true }); }
  catch (error) { if (error?.code?.startsWith?.('m4_group_')) throw error; fail('m4_group_checkpoint_load_failed'); }
  const opened = await openSource(deps, prior?.groupDigest ?? null, limits);
  let groups = 0; let observations = 0; let outputEvents = 0; let last = prior; let complete = false;
  let iterator; let primaryFailure = null; let stoppedAtCapacity = false; let exhausted = false;
  try {
    iterator = opened.groups[Symbol.asyncIterator]();
    if (!object(iterator) || typeof iterator.next !== 'function' || (iterator.return !== undefined && typeof iterator.return !== 'function')) fail('m4_group_source_invalid');
    while (groups < limits.groups) {
      let step;
      try { step = await iterator.next(); } catch { fail('m4_group_source_invalid'); }
      if (!plain(step) || typeof step.done !== 'boolean') fail('m4_group_source_invalid');
      if (step.done) { exhausted = true; break; }
      const item = step.value;
      if (!exact(item, ['descriptor', 'logical', 'observations'])) fail('m4_group_source_invalid');
      const current = descriptor(item.descriptor, deps.authority.authorityDigest);
      if (!plain(item.logical) || item.logical.logicalMessageId !== current.logicalMessageId) fail('m4_group_source_invalid');
      if (current.groupDigest === prior?.groupDigest) fail('m4_group_resume_invalid');
      bindMaterialization(current, item.observations);
      if (observations + current.members.length > limits.observations) { stoppedAtCapacity = true; break; }
      let projected;
      try { projected = await projectM4V2LogicalGroup({ logical: item.logical, observations: item.observations, integrityFor: deps.integrityFor }); }
      catch (error) { if (error?.code?.startsWith?.('m4_v2_')) fail('m4_group_projection_failed'); fail('m4_group_projection_failed'); }
      if (!exact(projected, ['schema', 'outcome', 'reason', 'evidence', 'events']) || !['projected', 'excluded'].includes(projected.outcome)
        || !Array.isArray(projected.events)) fail('m4_group_projection_invalid');
      const safeEvidence = evidence(projected.evidence);
      if (projected.outcome === 'excluded' && projected.events.length !== 0) fail('m4_group_projection_invalid');
      if (outputEvents + projected.events.length > limits.events) { stoppedAtCapacity = true; break; }
      const eventOutcomes = [];
      for (const event of projected.events) {
        if (!plain(event) || !EVENT.test(event.eventId) || !DIGEST.test(event.integrity?.payloadDigest)) fail('m4_group_projection_invalid');
        eventOutcomes.push(await terminalOutcome(deps, event));
      }
      const outcome = projected.outcome;
      const safeOutcomes = eventOutcomes.map(item => ({ ...item }));
      const next = { schema: CHECKPOINT_SCHEMA, authorityDigest: deps.authority.authorityDigest, sequence: (last?.sequence ?? 0) + 1,
        groupDigest: current.groupDigest, outcomeDigest: outcomeDigest(current, outcome, safeEvidence, safeOutcomes) };
      let committed;
      try { committed = checkpoint(await deps.checkpointStore.commit(next), deps.authority.authorityDigest); }
      catch (error) { if (error?.code?.startsWith?.('m4_group_')) throw error; fail('m4_group_checkpoint_commit_failed'); }
      if (canonicalJson(committed) !== canonicalJson(next)) fail('m4_group_checkpoint_commit_invalid');
      last = committed; groups += 1; observations += current.members.length; outputEvents += projected.events.length;
    }
    if (!stoppedAtCapacity && exhausted && groups < limits.groups) {
      let completion;
      try { completion = await opened.completion(); } catch { fail('m4_group_completion_failed'); }
      if (!exact(completion, ['schema', 'authorityDigest', 'complete']) || completion.schema !== SOURCE_SCHEMA
        || completion.authorityDigest !== deps.authority.authorityDigest || typeof completion.complete !== 'boolean') fail('m4_group_completion_invalid');
      complete = completion.complete;
    }
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    try { await iterator?.return?.(); } catch (error) { if (primaryFailure === null) fail('m4_group_iterator_close_failed'); }
  }
  return { schema: RESULT_SCHEMA, authorityDigest: deps.authority.authorityDigest, groups, observations, outputEvents,
    lastCheckpoint: last === null ? null : structuredClone(last), complete };
}
