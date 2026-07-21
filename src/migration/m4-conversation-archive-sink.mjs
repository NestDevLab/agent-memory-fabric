import { validateConversationEvent } from '../conversation-event-v3.mjs';

const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function archiveKey(eventId) { return `cai_${eventId.slice(5)}`; }

function acknowledgement(value, event) {
  if (!exact(value, ['outcome', 'stateChanged', 'items', 'nextCursor'])
    || !['stored', 'duplicate'].includes(value.outcome)
    || typeof value.stateChanged !== 'boolean'
    || value.stateChanged !== (value.outcome === 'stored')
    || !Array.isArray(value.items) || value.items.length !== 0 || value.nextCursor !== null) {
    fail('m4_archive_sink_outcome_invalid');
  }
  return {
    acknowledged: true,
    eventId: event.eventId,
    payloadDigest: event.integrity.payloadDigest,
    status: value.outcome,
  };
}

export class M4ConversationArchiveSink {
  constructor({ archive, resolveIntegrityKey } = {}) {
    if (archive === null || typeof archive !== 'object' || Array.isArray(archive)
      || typeof archive.append !== 'function' || typeof archive.tombstone !== 'function'
      || typeof resolveIntegrityKey !== 'function') fail('m4_archive_sink_dependency_invalid');
    this.archive = archive;
    this.resolveIntegrityKey = resolveIntegrityKey;
  }

  async deliver(event, input = {}) {
    if (!exact(input, ['idempotencyKey', 'payloadDigest'])
      || typeof input.idempotencyKey !== 'string' || !EVENT_ID.test(input.idempotencyKey)
      || typeof input.payloadDigest !== 'string' || !DIGEST.test(input.payloadDigest)) {
      fail('m4_archive_sink_request_invalid');
    }
    let validated;
    try { validated = validateConversationEvent(event, { resolveIntegrityKey: this.resolveIntegrityKey }); }
    catch { fail('m4_archive_sink_event_invalid'); }
    if (input.idempotencyKey !== validated.eventId || input.payloadDigest !== validated.integrity.payloadDigest) {
      fail('m4_archive_sink_idempotency_invalid');
    }
    const deliveryEvent = structuredClone(validated);
    let result;
    try {
      result = await (deliveryEvent.state === 'tombstone'
        ? this.archive.tombstone(deliveryEvent, archiveKey(deliveryEvent.eventId))
        : this.archive.append(deliveryEvent, archiveKey(deliveryEvent.eventId)));
    } catch { fail('m4_archive_sink_delivery_failed'); }
    return acknowledgement(result, deliveryEvent);
  }
}
