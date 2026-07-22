import crypto from 'node:crypto';

import { validateConversationEvent } from '../conversation-event-v3.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { deriveM4V3EventIdFromLegacyEventId } from './m4-v2-conversation-projector.mjs';

const AUTHORITY_SCHEMA = 'amf.m4-preserved-replay-authority/v2';
const READER_SCHEMA = 'amf.m4-preserved-replay-reader/v2';
const DECODED_SCHEMA = 'amf.m4-preserved-replay-decoded/v2';
const COMPLETION_SCHEMA = 'amf.m4-preserved-replay-completion/v2';
const ACK_SCHEMA = 'amf.m4-preserved-replay-ack/v2';
const CONFLICT_SCHEMA = 'amf.m4-preserved-replay-conflict/v2';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const LEGACY_EVENT_ID = /^evt_[a-f0-9]{64}$/;
const REPLAY_CHECKPOINT_ID = /^m4pr-[a-f0-9]{64}$/;
const SOURCE_KINDS = new Set(['outbox', 'deadletter']);

export const M4_PRESERVED_REPLAY_MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
export const M4_PRESERVED_REPLAY_MAX_VISITED_RECORDS = 10_000;

function typedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function fail(code) {
  throw typedError(code);
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function snapshot(value, keys, code) {
  try {
    if (!plain(value) || Object.keys(value).length !== keys.length
      || keys.some(key => !Object.hasOwn(value, key))) fail(code);
    const result = {};
    for (const key of keys) result[key] = value[key];
    return result;
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

function bindMethod(value, name, code) {
  let method;
  try {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) fail(code);
    method = value[name];
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
  if (typeof method !== 'function') fail(code);
  return method.bind(value);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sha256Bytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function sha256Value(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function hmac(key, domain, values) {
  return crypto.createHmac('sha256', key)
    .update(canonicalJson([domain, ...values]), 'utf8')
    .digest('hex');
}

function sourceKind(value, code) {
  if (typeof value !== 'string' || !SOURCE_KINDS.has(value)) fail(code);
  return value;
}

function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id)
    || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}

function signedEvidence(value, code) {
  const item = snapshot(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}

function interval(value, code) {
  const item = snapshot(value, ['startExclusive', 'endInclusive', 'chain'], code);
  if (!Number.isSafeInteger(item.startExclusive) || item.startExclusive < 0
    || !Number.isSafeInteger(item.endInclusive) || item.endInclusive < item.startExclusive) fail(code);
  return {
    startExclusive: item.startExclusive,
    endInclusive: item.endInclusive,
    chain: checkpoint(item.chain, code),
  };
}

function sourceAuthority(value) {
  const item = snapshot(
    value,
    ['pauseCheckpoint', 'interval', 'initialCheckpoint'],
    'm4_preserved_replay_authority_invalid',
  );
  return {
    pauseCheckpoint: checkpoint(item.pauseCheckpoint, 'm4_preserved_replay_authority_invalid'),
    interval: interval(item.interval, 'm4_preserved_replay_authority_invalid'),
    initialCheckpoint: checkpoint(item.initialCheckpoint, 'm4_preserved_replay_authority_invalid'),
  };
}

function authority(value) {
  const item = snapshot(
    value,
    ['schema', 'pauseEvidence', 'acknowledgements', 'sources'],
    'm4_preserved_replay_authority_invalid',
  );
  if (item.schema !== AUTHORITY_SCHEMA) fail('m4_preserved_replay_authority_invalid');
  const sources = snapshot(item.sources, ['outbox', 'deadletter'], 'm4_preserved_replay_authority_invalid');
  return {
    schema: AUTHORITY_SCHEMA,
    pauseEvidence: signedEvidence(item.pauseEvidence, 'm4_preserved_replay_authority_invalid'),
    acknowledgements: checkpoint(item.acknowledgements, 'm4_preserved_replay_authority_invalid'),
    sources: {
      outbox: sourceAuthority(sources.outbox),
      deadletter: sourceAuthority(sources.deadletter),
    },
  };
}

function dependencies(value) {
  const item = snapshot(
    value,
    ['authority', 'verifyPauseEvidence', 'reader', 'authorize', 'decoder', 'outbox', 'nativeSink', 'derivationKey'],
    'm4_preserved_replay_dependency_invalid',
  );
  if (!Buffer.isBuffer(item.derivationKey) || item.derivationKey.length !== 32
    || typeof item.verifyPauseEvidence !== 'function' || typeof item.authorize !== 'function') {
    fail('m4_preserved_replay_dependency_invalid');
  }
  const nativeDeliver = bindMethod(item.nativeSink, 'deliver', 'm4_preserved_replay_dependency_invalid');
  return {
    authority: authority(item.authority),
    derivationKey: Buffer.from(item.derivationKey),
    verifyPauseEvidence: item.verifyPauseEvidence.bind(value),
    readerOpen: bindMethod(item.reader, 'open', 'm4_preserved_replay_dependency_invalid'),
    authorize: item.authorize.bind(value),
    decoderNormalize: bindMethod(item.decoder, 'normalize', 'm4_preserved_replay_dependency_invalid'),
    resolveIntegrityKey: bindMethod(item.decoder, 'resolveIntegrityKey', 'm4_preserved_replay_dependency_invalid'),
    outboxEnqueue: bindMethod(item.outbox, 'enqueue', 'm4_preserved_replay_dependency_invalid'),
    outboxDeliver: bindMethod(item.outbox, 'deliver', 'm4_preserved_replay_dependency_invalid'),
    nativeSink: Object.freeze({ deliver: nativeDeliver }),
  };
}

function request(value, authorityValue) {
  const item = snapshot(value, ['sourceKind', 'after', 'afterSequence', 'maxEvents'], 'm4_preserved_replay_request_invalid');
  const kind = sourceKind(item.sourceKind, 'm4_preserved_replay_request_invalid');
  if (!Number.isSafeInteger(item.afterSequence) || item.afterSequence < 0
    || !Number.isSafeInteger(item.maxEvents) || item.maxEvents < 1 || item.maxEvents > 1_000) {
    fail('m4_preserved_replay_request_invalid');
  }
  const after = checkpoint(item.after, 'm4_preserved_replay_request_invalid');
  const selected = authorityValue.sources[kind];
  if (item.afterSequence > selected.interval.endInclusive
    || (item.afterSequence > 0 && item.afterSequence <= selected.interval.startExclusive)) {
    fail('m4_preserved_replay_checkpoint_drift');
  }
  if (item.afterSequence === 0 && !same(after, selected.initialCheckpoint)) {
    fail('m4_preserved_replay_checkpoint_drift');
  }
  if (item.afterSequence > 0 && !REPLAY_CHECKPOINT_ID.test(after.id)) {
    fail('m4_preserved_replay_checkpoint_drift');
  }
  return { sourceKind: kind, after, afterSequence: item.afterSequence, maxEvents: item.maxEvents, selected };
}

async function verifyPause(deps) {
  let value;
  try {
    value = await deps.verifyPauseEvidence();
  } catch {
    fail('m4_preserved_replay_pause_unverified');
  }
  const item = snapshot(
    value,
    ['pauseEvidence', 'pendingOutbox', 'acknowledgements', 'deadLetters'],
    'm4_preserved_replay_pause_unverified',
  );
  if (!same(signedEvidence(item.pauseEvidence, 'm4_preserved_replay_pause_unverified'), deps.authority.pauseEvidence)
    || !same(checkpoint(item.pendingOutbox, 'm4_preserved_replay_pause_unverified'), deps.authority.sources.outbox.pauseCheckpoint)
    || !same(checkpoint(item.acknowledgements, 'm4_preserved_replay_pause_unverified'), deps.authority.acknowledgements)
    || !same(checkpoint(item.deadLetters, 'm4_preserved_replay_pause_unverified'), deps.authority.sources.deadletter.pauseCheckpoint)) {
    fail('m4_preserved_replay_pause_mismatch');
  }
}

function replayRecord(value, kind) {
  const item = snapshot(
    value,
    ['sourceKind', 'position', 'legacyEventId', 'envelopeDigest', 'ciphertext'],
    'm4_preserved_replay_record_invalid',
  );
  if (sourceKind(item.sourceKind, 'm4_preserved_replay_record_invalid') !== kind
    || !Number.isSafeInteger(item.position) || item.position < 0
    || typeof item.legacyEventId !== 'string' || !LEGACY_EVENT_ID.test(item.legacyEventId)
    || typeof item.envelopeDigest !== 'string' || !DIGEST.test(item.envelopeDigest)
    || !Buffer.isBuffer(item.ciphertext) || item.ciphertext.length < 1
    || item.ciphertext.length > M4_PRESERVED_REPLAY_MAX_CIPHERTEXT_BYTES) {
    fail('m4_preserved_replay_record_invalid');
  }
  const ciphertext = Buffer.from(item.ciphertext);
  if (sha256Bytes(ciphertext) !== item.envelopeDigest) fail('m4_preserved_replay_envelope_mismatch');
  return { ...item, ciphertext };
}

function readerAttestation(value, opened) {
  const item = snapshot(
    value,
    ['schema', 'sourceKind', 'pauseCheckpoint', 'interval', 'records', 'completion'],
    'm4_preserved_replay_reader_invalid',
  );
  if (item.schema !== READER_SCHEMA || item.sourceKind !== opened.sourceKind
    || !same(checkpoint(item.pauseCheckpoint, 'm4_preserved_replay_reader_invalid'), opened.selected.pauseCheckpoint)
    || !same(interval(item.interval, 'm4_preserved_replay_reader_invalid'), opened.selected.interval)
    || typeof item.completion !== 'function') {
    fail('m4_preserved_replay_reader_attestation_mismatch');
  }
  let iterator;
  let next;
  let close;
  try {
    const iteratorFactory = item.records?.[Symbol.asyncIterator];
    if (typeof iteratorFactory !== 'function') fail('m4_preserved_replay_reader_invalid');
    iterator = iteratorFactory.call(item.records);
    next = iterator?.next;
    close = iterator?.return;
  } catch (error) {
    if (error?.code === 'm4_preserved_replay_reader_invalid') throw error;
    fail('m4_preserved_replay_reader_invalid');
  }
  if (typeof next !== 'function' || (close !== undefined && typeof close !== 'function')) {
    fail('m4_preserved_replay_reader_invalid');
  }
  return {
    next: next.bind(iterator),
    close: close?.bind(iterator) ?? null,
    completion: item.completion.bind(value),
  };
}

async function verifyCompletion(call, opened) {
  let value;
  try {
    value = await call();
  } catch {
    fail('m4_preserved_replay_completion_invalid');
  }
  const item = snapshot(
    value,
    ['schema', 'sourceKind', 'pauseCheckpoint', 'endInclusive', 'chain'],
    'm4_preserved_replay_completion_invalid',
  );
  if (item.schema !== COMPLETION_SCHEMA || item.sourceKind !== opened.sourceKind
    || !same(checkpoint(item.pauseCheckpoint, 'm4_preserved_replay_completion_invalid'), opened.selected.pauseCheckpoint)
    || item.endInclusive !== opened.selected.interval.endInclusive
    || !same(checkpoint(item.chain, 'm4_preserved_replay_completion_invalid'), opened.selected.interval.chain)) {
    fail('m4_preserved_replay_completion_mismatch');
  }
}

function decodedEvent(value, record, deps) {
  const item = snapshot(
    value,
    ['schema', 'legacyEventId', 'envelopeDigest', 'event'],
    'm4_preserved_replay_decode_failed',
  );
  if (item.schema !== DECODED_SCHEMA || item.legacyEventId !== record.legacyEventId
    || item.envelopeDigest !== record.envelopeDigest) fail('m4_preserved_replay_decoder_binding_invalid');
  let event;
  try {
    event = validateConversationEvent(item.event, { resolveIntegrityKey: deps.resolveIntegrityKey });
  } catch {
    fail('m4_preserved_replay_decode_failed');
  }
  if (event.eventId !== deriveM4V3EventIdFromLegacyEventId(record.legacyEventId)) {
    fail('m4_preserved_replay_event_identity_invalid');
  }
  return event;
}

function replayCheckpoint(deps, opened, record, event) {
  const opaqueLegacyId = hmac(
    deps.derivationKey,
    'amf.m4-preserved-replay/legacy-event/v2',
    [record.legacyEventId],
  );
  const token = hmac(
    deps.derivationKey,
    'amf.m4-preserved-replay/checkpoint/v2',
    [opened.sourceKind, record.position, opaqueLegacyId, record.envelopeDigest],
  );
  return {
    id: `m4pr-${token}`,
    digest: sha256Value({
      schema: 'amf.m4-preserved-replay-checkpoint/v2',
      pauseEvidence: deps.authority.pauseEvidence,
      acknowledgements: deps.authority.acknowledgements,
      sourceKind: opened.sourceKind,
      pauseCheckpoint: opened.selected.pauseCheckpoint,
      interval: opened.selected.interval,
      initialCheckpoint: opened.selected.initialCheckpoint,
      position: record.position,
      opaqueLegacyId,
      envelopeDigest: record.envelopeDigest,
      eventId: event.eventId,
      payloadDigest: event.integrity.payloadDigest,
    }),
  };
}

function queueReceipt(value, event) {
  const item = snapshot(value, ['eventId', 'payloadDigest', 'state', 'duplicate'], 'm4_preserved_replay_outbox_invalid');
  if (item.eventId !== event.eventId || item.payloadDigest !== event.integrity.payloadDigest
    || !['pending', 'acknowledged', 'conflict'].includes(item.state)
    || typeof item.duplicate !== 'boolean'
    || (item.state === 'acknowledged' && item.duplicate !== true)) {
    fail('m4_preserved_replay_outbox_invalid');
  }
  return item;
}

function deliveryReceipt(value, event) {
  const item = snapshot(value, ['eventId', 'payloadDigest', 'state', 'duplicate'], 'm4_preserved_replay_delivery_invalid');
  if (item.eventId !== event.eventId || item.payloadDigest !== event.integrity.payloadDigest
    || item.state !== 'acknowledged' || typeof item.duplicate !== 'boolean') {
    fail('m4_preserved_replay_delivery_invalid');
  }
  return item;
}

function acknowledgement(opened, sequence, checkpointValue, event, outcome, duplicate) {
  return {
    schema: ACK_SCHEMA,
    sequence,
    sourceKind: opened.sourceKind,
    checkpoint: checkpointValue,
    eventId: event.eventId,
    payloadDigest: event.integrity.payloadDigest,
    outcome,
    duplicate,
    ...(outcome === 'conflict' ? {
      conflict: {
        schema: CONFLICT_SCHEMA,
        eventId: event.eventId,
        receivedPayloadDigest: event.integrity.payloadDigest,
      },
    } : {}),
  };
}

function normalizePrimary(error) {
  const code = typeof error?.code === 'string'
    && /^m4_preserved_replay_[a-z0-9_]{1,64}$/.test(error.code)
    ? error.code
    : 'm4_preserved_replay_enumeration_failed';
  return typedError(code);
}

export function createM4PreservedReplayCoordinator(input = {}) {
  const deps = dependencies(input);
  return {
    open(openInput) {
      const opened = request(openInput, deps.authority);
      return (async function* replay() {
        await verifyPause(deps);
        let readerValue;
        try {
          readerValue = await deps.readerOpen({
            schema: AUTHORITY_SCHEMA,
            sourceKind: opened.sourceKind,
            pauseCheckpoint: structuredClone(opened.selected.pauseCheckpoint),
            interval: structuredClone(opened.selected.interval),
            afterSequence: opened.afterSequence,
          });
        } catch {
          fail('m4_preserved_replay_reader_open_failed');
        }
        const reader = readerAttestation(readerValue, opened);
        let previousPosition = opened.afterSequence === 0
          ? opened.selected.interval.startExclusive
          : opened.afterSequence - 1;
        let visited = 0;
        let emitted = 0;
        let resume = opened.afterSequence === 0 ? null : opened.after;
        let primary = null;
        try {
          while (true) {
            if (resume === null && emitted >= opened.maxEvents) {
              let probeValue;
              try {
                probeValue = await reader.next();
              } catch {
                fail('m4_preserved_replay_reader_read_failed');
              }
              const probe = snapshot(probeValue, ['value', 'done'], 'm4_preserved_replay_reader_invalid');
              if (typeof probe.done !== 'boolean') fail('m4_preserved_replay_reader_invalid');
              if (!probe.done) return;
              await verifyCompletion(reader.completion, opened);
              return;
            }
            let nextValue;
            try {
              nextValue = await reader.next();
            } catch {
              fail('m4_preserved_replay_reader_read_failed');
            }
            const next = snapshot(nextValue, ['value', 'done'], 'm4_preserved_replay_reader_invalid');
            if (typeof next.done !== 'boolean') fail('m4_preserved_replay_reader_invalid');
            if (next.done) {
              if (resume !== null) fail('m4_preserved_replay_checkpoint_drift');
              await verifyCompletion(reader.completion, opened);
              return;
            }
            visited += 1;
            if (visited > M4_PRESERVED_REPLAY_MAX_VISITED_RECORDS) fail('m4_preserved_replay_scan_limit');
            const record = replayRecord(next.value, opened.sourceKind);
            if (record.position <= previousPosition || record.position > opened.selected.interval.endInclusive) {
              fail('m4_preserved_replay_record_invalid');
            }
            previousPosition = record.position;
            let authorized;
            try {
              authorized = await deps.authorize({
                sourceKind: opened.sourceKind,
                legacyEventId: record.legacyEventId,
                envelopeDigest: record.envelopeDigest,
                pauseCheckpoint: structuredClone(opened.selected.pauseCheckpoint),
              });
            } catch {
              fail('m4_preserved_replay_authorization_failed');
            }
            if (authorized !== true) fail('m4_preserved_replay_authorization_failed');
            let normalized;
            try {
              normalized = await deps.decoderNormalize({
                sourceKind: opened.sourceKind,
                legacyEventId: record.legacyEventId,
                envelopeDigest: record.envelopeDigest,
                ciphertext: Buffer.from(record.ciphertext),
              });
            } catch {
              fail('m4_preserved_replay_decode_failed');
            }
            const event = decodedEvent(normalized, record, deps);
            const checkpointValue = replayCheckpoint(deps, opened, record, event);
            if (resume !== null) {
              if (same(resume, checkpointValue)) resume = null;
              continue;
            }
            let queuedValue;
            try {
              queuedValue = await deps.outboxEnqueue(event);
            } catch {
              fail('m4_preserved_replay_outbox_failed');
            }
            const queued = queueReceipt(queuedValue, event);
            let outcome;
            let duplicate;
            if (queued.state === 'conflict') {
              outcome = 'conflict';
              duplicate = queued.duplicate;
            } else if (queued.state === 'acknowledged') {
              outcome = 'duplicate';
              duplicate = true;
            } else {
              let deliveredValue;
              try {
                deliveredValue = await deps.outboxDeliver(event.eventId, deps.nativeSink);
              } catch {
                fail('m4_preserved_replay_delivery_failed');
              }
              const delivered = deliveryReceipt(deliveredValue, event);
              outcome = delivered.duplicate ? 'duplicate' : 'accepted';
              duplicate = delivered.duplicate;
            }
            emitted += 1;
            yield acknowledgement(
              opened,
              opened.afterSequence + emitted,
              checkpointValue,
              event,
              outcome,
              duplicate,
            );
          }
        } catch (error) {
          primary = normalizePrimary(error);
          throw primary;
        } finally {
          try {
            await reader.close?.();
          } catch {
            if (primary === null) fail('m4_preserved_replay_reader_close_failed');
          }
        }
      })();
    },
  };
}
