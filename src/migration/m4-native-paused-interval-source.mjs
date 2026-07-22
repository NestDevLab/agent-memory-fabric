import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createConversationEvent, isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { normalizeContextTags } from '../ingest/raw-projection-v2.mjs';
import { eligibleCodexConversationLifecyclePayload,
  eligibleClaudeConversationLifecyclePayload, eligibleOpenClawConversationLifecyclePayload,
  eligibleHermesConversationLifecyclePayload } from '../ingest/transcripts/conversation-v3.mjs';

const AUTHORITY_SCHEMA = 'amf.m4-native-paused-interval-authority/v1';
const READER_SCHEMA = 'amf.m4-native-paused-reader/v1';
const COMPLETION_SCHEMA = 'amf.m4-native-paused-completion/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const NATIVE_ID = /^\S+$/u;

// Bounds excluded records and resume scans before an M4 coordinator batch can
// observe a row. It is deliberately independent from the coordinator's 1,000
// emitted-event limit.
export const M4_NATIVE_PAUSED_MAX_VISITED_RECORDS = 10_000;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function snapshot(value, keys, code) {
  try {
    if (!plain(value)) fail(code);
    const actual = Object.keys(value);
    if (actual.length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
    const result = {};
    for (const key of keys) result[key] = value[key];
    return result;
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}
function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function evidence(value, code) {
  const item = snapshot(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function hmac(key, domain, values) { return crypto.createHmac('sha256', key).update(canonicalJson([domain, ...values]), 'utf8').digest('hex'); }
function tag(key, namespace, tuple) { return `hmac-sha256:${namespace}:${hmac(key, `amf.m4-native-paused/tag/${namespace}/v1`, tuple)}`; }
function interval(value, code) {
  const item = snapshot(value, ['startExclusive', 'endInclusive', 'chain'], code);
  if (!Number.isSafeInteger(item.startExclusive) || item.startExclusive < 0 || !Number.isSafeInteger(item.endInclusive)
    || item.endInclusive <= item.startExclusive) fail(code);
  return { startExclusive: item.startExclusive, endInclusive: item.endInclusive, chain: checkpoint(item.chain, code) };
}

function authority(value) {
  const item = snapshot(value, ['schema', 'pauseEvidence', 'source', 'sourceBinding', 'projectionBinding', 'interval', 'initialCheckpoint'], 'm4_native_paused_authority_invalid');
  if (item.schema !== AUTHORITY_SCHEMA) fail('m4_native_paused_authority_invalid');
  if (typeof item.sourceBinding !== 'string' || !/^hmac-sha256:source-v1:[a-f0-9]{64}$/.test(item.sourceBinding)) fail('m4_native_paused_authority_invalid');
  return { schema: AUTHORITY_SCHEMA, pauseEvidence: evidence(item.pauseEvidence, 'm4_native_paused_authority_invalid'),
    source: checkpoint(item.source, 'm4_native_paused_authority_invalid'), sourceBinding: item.sourceBinding,
    projectionBinding: projectionBinding(item.projectionBinding, 'm4_native_paused_authority_invalid'), interval: interval(item.interval, 'm4_native_paused_authority_invalid'),
    initialCheckpoint: checkpoint(item.initialCheckpoint, 'm4_native_paused_authority_invalid') };
}

function dependencies(value) {
  const item = snapshot(value, ['authority', 'derivationKey', 'derivationKeyId', 'verifyPauseEvidence', 'reader', 'projectionIdentityResolver', 'integrityFor'], 'm4_native_paused_dependency_invalid');
  if (!Buffer.isBuffer(item.derivationKey) || item.derivationKey.length !== 32 || typeof item.derivationKeyId !== 'string'
    || !/^[A-Za-z0-9._-]{1,64}$/.test(item.derivationKeyId) || typeof item.verifyPauseEvidence !== 'function'
    || typeof item.integrityFor !== 'function') fail('m4_native_paused_dependency_invalid');
  const reader = snapshot(item.reader, ['open'], 'm4_native_paused_dependency_invalid');
  if (typeof reader.open !== 'function') fail('m4_native_paused_dependency_invalid');
  if (!plain(item.projectionIdentityResolver) || typeof item.projectionIdentityResolver.resolve !== 'function') fail('m4_native_paused_dependency_invalid');
  return { authority: authority(item.authority), derivationKey: Buffer.from(item.derivationKey), derivationKeyId: item.derivationKeyId,
    verifyPauseEvidence: item.verifyPauseEvidence, reader, projectionIdentityResolver: item.projectionIdentityResolver, integrityFor: item.integrityFor };
}

function projectionBinding(value, code) {
  const item = snapshot(value, ['schema', 'runtime', 'sourceId', 'digest'], code);
  if (item.schema !== 'amf.m4-paused-projection-binding/v1' || !['codex', 'claude', 'hermes', 'openclaw'].includes(item.runtime)
    || typeof item.sourceId !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(item.sourceId) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}

function request(value, initialCheckpoint) {
  const item = snapshot(value, ['runId', 'phase', 'after', 'afterSequence', 'maxEvents'], 'm4_native_paused_request_invalid');
  if (typeof item.runId !== 'string' || !ID.test(item.runId) || item.phase !== 'paused-native' || !Number.isSafeInteger(item.afterSequence)
    || item.afterSequence < 0 || !Number.isSafeInteger(item.maxEvents) || item.maxEvents < 1 || item.maxEvents > 1000) fail('m4_native_paused_request_invalid');
  const after = checkpoint(item.after, 'm4_native_paused_request_invalid');
  if (item.afterSequence === 0 && !same(after, initialCheckpoint)) fail('m4_native_paused_checkpoint_drift');
  if (item.afterSequence > 0 && !/^m4np-[a-f0-9]{64}$/.test(after.id)) fail('m4_native_paused_checkpoint_drift');
  return { runId: item.runId, phase: 'paused-native', after, afterSequence: item.afterSequence, maxEvents: item.maxEvents };
}

function native(value) {
  const item = snapshot(value, ['runtime', 'sourceId', 'conversationId', 'threadId', 'messageId', 'position', 'sourceOccurredAt'], 'm4_native_paused_reader_invalid');
  if (!['codex', 'claude', 'hermes', 'openclaw'].includes(item.runtime) || ![item.sourceId, item.conversationId, item.messageId].every(nativeId)
    || !(item.threadId === null || nativeId(item.threadId)) || !Number.isSafeInteger(item.position) || item.position < 0
    || !isConversationEventUtcTimestamp(item.sourceOccurredAt)) fail('m4_native_paused_reader_invalid');
  return item;
}
function nativeId(value) { return typeof value === 'string' && NATIVE_ID.test(value) && Buffer.byteLength(value, 'utf8') <= 1024; }
function record(value) {
  const item = snapshot(value, ['native', 'value', 'sessionHint', 'projectionIdentity'], 'm4_native_paused_reader_invalid');
  let raw;
  try { raw = structuredClone(item.value); } catch { fail('m4_native_paused_reader_invalid'); }
  if (!(item.sessionHint === null || nativeId(item.sessionHint))) fail('m4_native_paused_reader_invalid');
  let projectionIdentity; try { projectionIdentity = readerProjectionIdentity(item.projectionIdentity); } catch { fail('m4_native_paused_reader_invalid'); }
  return { native: native(item.native), value: raw, sessionHint: item.sessionHint, projectionIdentity };
}

function readerProjectionIdentity(value) {
  const item = snapshot(value, ['schema', 'binding', 'runtime', 'sourceId', 'sourceKind', 'observationClass', 'authoritativeDeletion', 'occurredAt', 'editedAt', 'legacy', 'routing', 'lifecycle'], 'm4_native_paused_reader_invalid');
  const binding = projectionBinding(item.binding, 'm4_native_paused_reader_invalid');
  if (item.schema !== 'amf.m4-paused-projection-identity/v1' || item.runtime !== binding.runtime || item.sourceId !== binding.sourceId
    || item.sourceKind !== item.runtime || item.observationClass !== 'native' || typeof item.authoritativeDeletion !== 'boolean'
    || !isConversationEventUtcTimestamp(item.occurredAt) || !(item.editedAt === null || isConversationEventUtcTimestamp(item.editedAt))
    || !plain(item.legacy) || !snapshot(item.legacy, ['sessionId', 'eventId', 'priorEventId'], 'm4_native_paused_reader_invalid')
    || !/^ses_[a-f0-9]{64}$/.test(item.legacy.sessionId) || !/^evt_[a-f0-9]{64}$/.test(item.legacy.eventId)
    || !(item.legacy.priorEventId === null || /^evt_[a-f0-9]{64}$/.test(item.legacy.priorEventId))
    || !plain(item.routing) || !snapshot(item.routing, ['role', 'direction', 'conversationKind', 'authorizationContextTags'], 'm4_native_paused_reader_invalid')
    || !['user', 'assistant', 'system', 'tool', 'unknown'].includes(item.routing.role)
    || !['inbound', 'outbound', 'internal', 'unknown'].includes(item.routing.direction)
    || !['dm', 'group', 'channel', 'thread', 'session', 'unknown'].includes(item.routing.conversationKind)
    || !plain(item.lifecycle) || !snapshot(item.lifecycle, ['change', 'nativeRevision'], 'm4_native_paused_reader_invalid')
    || !['new', 'changed', 'deleted'].includes(item.lifecycle.change)
    || !(item.lifecycle.nativeRevision === null || (Number.isSafeInteger(item.lifecycle.nativeRevision) && item.lifecycle.nativeRevision >= 0))
    || item.authoritativeDeletion !== (item.lifecycle.change === 'deleted')
    || ((item.lifecycle.change === 'new') !== (item.legacy.priorEventId === null))) fail('m4_native_paused_reader_invalid');
  let context; try { context = normalizeContextTags(item.routing.authorizationContextTags); } catch { fail('m4_native_paused_reader_invalid'); }
  return { ...structuredClone(item), routing: { ...structuredClone(item.routing), authorizationContextTags: context } };
}
function resolverEligible(identity) { return ['user', 'assistant'].includes(identity.routing.role) && ['inbound', 'outbound'].includes(identity.routing.direction)
  && ['dm', 'group', 'channel', 'thread', 'session'].includes(identity.routing.conversationKind); }

function rowCheckpoint(authorityValue, key, nativeValue, event) {
  const opaqueNative = hmac(key, 'amf.m4-native-paused/checkpoint-native/v1', [nativeValue.runtime, nativeValue.sourceId, nativeValue.conversationId, nativeValue.threadId, nativeValue.messageId]);
  return { id: `m4np-${opaqueNative}`, digest: digest({ schema: 'amf.m4-native-paused-checkpoint/v1', authority: authorityValue.source,
    chain: authorityValue.interval.chain, position: nativeValue.position, native: opaqueNative, eventId: event.eventId, payloadDigest: event.integrity.payloadDigest }) };
}

async function verified(deps) {
  let result;
  try { result = await deps.verifyPauseEvidence(); } catch { fail('m4_native_paused_pause_unverified'); }
  const item = snapshot(result, ['pauseEvidence', 'nativeTranscriptAuthority', 'sourceCheckpoint'], 'm4_native_paused_pause_unverified');
  if (!same(evidence(item.pauseEvidence, 'm4_native_paused_pause_unverified'), deps.authority.pauseEvidence)
    || !same(checkpoint(item.nativeTranscriptAuthority, 'm4_native_paused_pause_unverified'), deps.authority.source)
    || !same(checkpoint(item.sourceCheckpoint, 'm4_native_paused_pause_unverified'), deps.authority.initialCheckpoint)) fail('m4_native_paused_pause_mismatch');
}

function readerAttestation(value, authorityValue, key) {
  const item = snapshot(value, ['schema', 'source', 'interval', 'runtime', 'sourceId', 'projectionBinding', 'records', 'completion'], 'm4_native_paused_reader_invalid');
  if (item.schema !== READER_SCHEMA || !same(checkpoint(item.source, 'm4_native_paused_reader_invalid'), authorityValue.source)
    || !same(interval(item.interval, 'm4_native_paused_reader_invalid'), authorityValue.interval)
    || !['codex', 'claude', 'hermes', 'openclaw'].includes(item.runtime) || !nativeId(item.sourceId)
    || tag(key, 'source-v1', [item.runtime, item.sourceId]) !== authorityValue.sourceBinding
    || typeof item.completion !== 'function') fail('m4_native_paused_reader_attestation_mismatch');
  let records; let next; let close;
  try {
    const iteratorFactory = item.records?.[Symbol.asyncIterator];
    if (typeof iteratorFactory !== 'function') fail('m4_native_paused_reader_invalid');
    records = iteratorFactory.call(item.records);
    next = records?.next;
    close = records?.return;
  } catch (error) { if (error?.code === 'm4_native_paused_reader_invalid') throw error; fail('m4_native_paused_reader_invalid'); }
  if (typeof next !== 'function' || (close !== undefined && typeof close !== 'function')) fail('m4_native_paused_reader_invalid');
  const binding = projectionBinding(item.projectionBinding, 'm4_native_paused_reader_invalid');
  if (!same(binding, authorityValue.projectionBinding) || binding.runtime !== item.runtime || binding.sourceId !== item.sourceId) fail('m4_native_paused_reader_attestation_mismatch');
  return { next: next.bind(records), close: close?.bind(records), completion: item.completion, runtime: item.runtime, sourceId: item.sourceId, projectionBinding: binding };
}
async function complete(completion, authorityValue) {
  let result;
  try { result = await completion(); } catch { fail('m4_native_paused_completion_invalid'); }
  const item = snapshot(result, ['schema', 'source', 'endInclusive', 'chain'], 'm4_native_paused_completion_invalid');
  if (item.schema !== COMPLETION_SCHEMA || !same(checkpoint(item.source, 'm4_native_paused_completion_invalid'), authorityValue.source)
    || item.endInclusive !== authorityValue.interval.endInclusive || !same(checkpoint(item.chain, 'm4_native_paused_completion_invalid'), authorityValue.interval.chain)) fail('m4_native_paused_completion_mismatch');
}
function firstNativeId(...values) { return values.find(nativeId) ?? null; }
function boundNativeMetadata(value, runtime, sessionHint) {
  if (!plain(value)) return null;
  if (runtime === 'codex') {
    if (value.type !== 'response_item' || !plain(value.payload)) return null;
    return { conversationId: firstNativeId(value.session_id, value.sessionId, sessionHint), messageId: firstNativeId(value.id, value.payload.id, value.uuid) };
  }
  if (runtime === 'openclaw') {
    if (value.type !== 'message' || !plain(value.message)) return null;
    return { conversationId: firstNativeId(value.sessionKey, value.session_key, value.sessionId,
      value.session_id, sessionHint), messageId: firstNativeId(value.id, value.uuid,
      value.messageId, value.message_id, value.message.id) };
  }
  if (runtime === 'hermes') {
    if (!['user', 'assistant'].includes(value.role)) return null;
    return { conversationId: firstNativeId(value.session_id, sessionHint), messageId: firstNativeId(value.revisionEventId) };
  }
  if (!['user', 'assistant'].includes(value.type) || !plain(value.message)) return null;
  return { conversationId: firstNativeId(value.sessionId, value.session_id, value.conversationId, sessionHint), messageId: firstNativeId(value.uuid, value.id, value.message.id) };
}
function duplicateSemanticDigest(event) {
  const { integrity, ordering, ...semantic } = event;
  return digest({ schema: 'amf.m4-native-paused-duplicate-semantics/v1', event: semantic });
}

export function createM4NativePausedIntervalSource(input = {}) {
  const deps = dependencies(input);
  let closed = false;
  return { open(openInput) {
    if (closed) fail('m4_native_paused_source_closed');
    const opened = request(openInput, deps.authority.initialCheckpoint);
    return (async function* () {
      await verified(deps);
      let readerValue;
      try { readerValue = await deps.reader.open({ schema: AUTHORITY_SCHEMA, source: structuredClone(deps.authority.source), interval: structuredClone(deps.authority.interval) }); }
      catch { fail('m4_native_paused_reader_open_failed'); }
      const attested = readerAttestation(readerValue, deps.authority, deps.derivationKey);
      const { next: readNext, close, completion } = attested;
      let previousPosition = deps.authority.interval.startExclusive;
      let emitted = 0; let visited = 0; let resume = opened.afterSequence === 0 ? null : opened.after;
      const seen = new Map();
      let primaryError = null;
      try {
        while (true) {
          let nextValue;
          try { nextValue = await readNext(); } catch { fail('m4_native_paused_reader_read_failed'); }
          const result = snapshot(nextValue, ['value', 'done'], 'm4_native_paused_reader_invalid');
          if (typeof result.done !== 'boolean') fail('m4_native_paused_reader_invalid');
          if (result.done) { if (resume !== null) fail('m4_native_paused_checkpoint_drift'); await complete(completion, deps.authority); return; }
          visited += 1; if (visited > M4_NATIVE_PAUSED_MAX_VISITED_RECORDS) fail('m4_native_paused_scan_limit');
          const candidate = record(result.value);
          if (candidate.native.position <= previousPosition || candidate.native.position > deps.authority.interval.endInclusive) fail('m4_native_paused_reader_invalid');
          previousPosition = candidate.native.position;
          if (candidate.native.runtime !== attested.runtime || candidate.native.sourceId !== attested.sourceId
            || !same(candidate.projectionIdentity.binding, attested.projectionBinding)
            || candidate.projectionIdentity.occurredAt !== candidate.native.sourceOccurredAt) fail('m4_native_paused_projection_identity_mismatch');
          if (!resolverEligible(candidate.projectionIdentity)) continue;
          let resolved;
          try { resolved = deps.projectionIdentityResolver.resolve({ identity: candidate.projectionIdentity, attestation: attested.projectionBinding }); }
          catch { fail('m4_native_paused_projection_identity_unresolved'); }
          const eventIdentity = { eventId: resolved.eventId, conversationId: resolved.conversationId, sourceInstanceId: resolved.sourceInstanceId,
            conversationKind: resolved.conversationKind, authorizationContextTags: resolved.authorizationContextTags };
          let payload;
          try {
            const options = { value: candidate.value, identity: eventIdentity, sourceSequence: candidate.native.position,
              occurredAt: candidate.projectionIdentity.editedAt ?? candidate.projectionIdentity.occurredAt, sessionHint: candidate.sessionHint,
              lifecycle: candidate.projectionIdentity.lifecycle, resolved };
            payload = candidate.native.runtime === 'codex' ? eligibleCodexConversationLifecyclePayload(options)
              : candidate.native.runtime === 'openclaw' ? eligibleOpenClawConversationLifecyclePayload(options)
                : candidate.native.runtime === 'hermes' ? eligibleHermesConversationLifecyclePayload(options)
                  : eligibleClaudeConversationLifecyclePayload(options);
          } catch { fail('m4_native_paused_projection_failed'); }
          if (payload === null) continue;
          if (payload.sourceOccurredAt !== candidate.projectionIdentity.occurredAt) fail('m4_native_paused_projection_identity_mismatch');
          if (payload.role !== candidate.projectionIdentity.routing.role || payload.direction !== candidate.projectionIdentity.routing.direction
            || payload.conversationKind !== candidate.projectionIdentity.routing.conversationKind
            || !same(payload.authorizationContextTags, candidate.projectionIdentity.routing.authorizationContextTags)) fail('m4_native_paused_projection_identity_mismatch');
          const metadata = boundNativeMetadata(candidate.value, candidate.native.runtime, candidate.sessionHint);
          if (metadata === null
            || candidate.native.conversationId !== metadata.conversationId || candidate.native.messageId !== metadata.messageId) fail('m4_native_paused_native_binding_invalid');
          let integrity;
          try { integrity = await deps.integrityFor({ eventId: eventIdentity.eventId, derivationKeyId: deps.derivationKeyId }); } catch { fail('m4_native_paused_integrity_unavailable'); }
          let event;
          try {
            event = createConversationEvent(payload, integrity);
            if (event.sourceOccurredAt !== candidate.native.sourceOccurredAt) fail('m4_native_paused_projection_failed');
          } catch (error) { if (error?.code === 'm4_native_paused_projection_failed') throw error; fail('m4_native_paused_projection_failed'); }
          const eventDigest = duplicateSemanticDigest(event); const prior = seen.get(event.eventId);
          if (prior !== undefined) { if (prior !== eventDigest) fail('m4_native_paused_duplicate_conflict'); continue; }
          seen.set(event.eventId, eventDigest);
          const checkpointValue = rowCheckpoint(deps.authority, deps.derivationKey, candidate.native, event);
          if (resume !== null) { if (same(resume, checkpointValue)) { resume = null; continue; } continue; }
          emitted += 1;
          yield { sequence: opened.afterSequence + emitted, checkpoint: checkpointValue, event: structuredClone(event),
            postCutoffBinding: resolved.postCutoffBinding === undefined ? null : structuredClone(resolved.postCutoffBinding) };
          if (emitted >= opened.maxEvents + 1) return;
        }
      } catch (error) {
        if (error?.code?.startsWith?.('m4_native_paused_')) primaryError = error;
        else {
          primaryError = new Error('m4_native_paused_enumeration_failed');
          primaryError.code = 'm4_native_paused_enumeration_failed';
        }
        throw primaryError;
      } finally {
        try { await close?.(); }
        catch { if (primaryError === null) fail('m4_native_paused_reader_close_failed'); }
      }
    })();
  }, close() {
    if (closed) return;
    closed = true;
    deps.derivationKey.fill(0);
  } };
}
