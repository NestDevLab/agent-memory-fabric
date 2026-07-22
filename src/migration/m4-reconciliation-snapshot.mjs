import crypto from 'node:crypto';

import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { timestampWithin } from './m4-authority-snapshots.mjs';

export const M4_RECONCILIATION_SNAPSHOT_SCHEMA = 'amf.m4-reconciliation-snapshot/v1';
export const M4_RECONCILIATION_ARCHIVE_REVISION_SCHEMA = 'amf.m4-reconciliation-archive-revision/v1';
export const M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS = 5_000_000;

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-reconciliation-snapshot/v1/integrity';
const REVISION_DOMAIN = 'amf.m4-reconciliation-archive-revision/v1/integrity';
const SET_DOMAIN = 'amf.m4-reconciliation-snapshot/v1/events';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}
function keyDocument(value, code) {
  if (!exact(value, ['schema', 'keyId', 'key']) || value.schema !== KEY_SCHEMA
    || typeof value.keyId !== 'string' || !ID.test(value.keyId) || typeof value.key !== 'string'
    || !BASE64.test(value.key)) fail(code);
  const key = Buffer.from(value.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== value.key) { key.fill(0); fail(code); }
  return { keyId: value.keyId, key };
}
function sha(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(payloadDigest, loaded, domain = DOMAIN) {
  return crypto.createHmac('sha256', loaded.key).update(canonicalJson([domain, payloadDigest, loaded.keyId]), 'utf8').digest('base64url');
}
function evidence(value, code) {
  if (!exact(value, ['manifestId', 'digest', 'signature']) || typeof value.manifestId !== 'string'
    || !ID.test(value.manifestId) || typeof value.digest !== 'string' || !DIGEST.test(value.digest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return { manifestId: value.manifestId, digest: value.digest, signature: value.signature };
}
function timestampNanoseconds(value, code) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) fail(code);
  const milliseconds = Date.parse(`${match[1]}Z`); if (!Number.isFinite(milliseconds)) fail(code);
  return BigInt(milliseconds) * 1_000_000n + BigInt((match[2] ?? '').padEnd(9, '0') || '0');
}
function payload(value, code) {
  if (!exact(value, ['schema', 'snapshotId', 'archive', 'revision', 'terminalCheckpoint', 'capturedAt',
    'revisionEvidence', 'prerequisiteEvidenceDigest', 'eventCount', 'eventSetDigest', 'eventFileDigest', 'staticEvidenceDigest'])
    || value.schema !== M4_RECONCILIATION_SNAPSHOT_SCHEMA || typeof value.snapshotId !== 'string'
    || !ID.test(value.snapshotId) || !['legacy-v2', 'v3'].includes(value.archive)
    || typeof value.capturedAt !== 'string' || !value.capturedAt.endsWith('Z')
    || !isConversationEventUtcTimestamp(value.capturedAt) || !Number.isSafeInteger(value.eventCount)
    || value.eventCount < 0 || value.eventCount > M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS
    || ![value.prerequisiteEvidenceDigest, value.eventSetDigest, value.eventFileDigest, value.staticEvidenceDigest]
      .every(digest => typeof digest === 'string' && DIGEST.test(digest))) fail(code);
  return { schema: M4_RECONCILIATION_SNAPSHOT_SCHEMA, snapshotId: value.snapshotId, archive: value.archive,
    revision: checkpoint(value.revision, code), terminalCheckpoint: checkpoint(value.terminalCheckpoint, code),
    capturedAt: value.capturedAt, revisionEvidence: evidence(value.revisionEvidence, code),
    prerequisiteEvidenceDigest: value.prerequisiteEvidenceDigest, eventCount: value.eventCount, eventSetDigest: value.eventSetDigest,
    eventFileDigest: value.eventFileDigest, staticEvidenceDigest: value.staticEvidenceDigest };
}

function revisionPayload(value, code) {
  if (!exact(value, ['schema', 'manifestId', 'archive', 'revision', 'observedAt', 'validThrough'])
    || value.schema !== M4_RECONCILIATION_ARCHIVE_REVISION_SCHEMA || typeof value.manifestId !== 'string'
    || !ID.test(value.manifestId) || !['legacy-v2', 'v3'].includes(value.archive)
    || typeof value.observedAt !== 'string' || typeof value.validThrough !== 'string'
    || !timestampWithin(value.observedAt, value.observedAt, value.validThrough)) fail(code);
  if (timestampNanoseconds(value.validThrough, code) - timestampNanoseconds(value.observedAt, code)
    > 7n * 24n * 60n * 60n * 1_000_000_000n) fail(code);
  return { schema: M4_RECONCILIATION_ARCHIVE_REVISION_SCHEMA, manifestId: value.manifestId,
    archive: value.archive, revision: checkpoint(value.revision, code), observedAt: value.observedAt,
    validThrough: value.validThrough };
}

export function createM4ReconciliationArchiveRevision(value, keyDocumentValue) {
  let input; try { input = structuredClone(value); } catch { fail('m4_reconciliation_archive_revision_input_invalid'); }
  const body = revisionPayload({ schema: M4_RECONCILIATION_ARCHIVE_REVISION_SCHEMA, ...input },
    'm4_reconciliation_archive_revision_input_invalid');
  const loaded = keyDocument(structuredClone(keyDocumentValue), 'm4_reconciliation_archive_revision_key_invalid');
  try {
    const payloadDigest = sha(body);
    return { ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest,
      signature: signatureFor(payloadDigest, loaded, REVISION_DOMAIN) } };
  } finally { loaded.key.fill(0); }
}

export function verifyM4ReconciliationArchiveRevision(value, keyDocumentValue) {
  let input; try { input = structuredClone(value); } catch { fail('m4_reconciliation_archive_revision_manifest_invalid'); }
  if (!plain(input) || !exact(input, ['schema', 'manifestId', 'archive', 'revision', 'observedAt', 'validThrough', 'integrity'])
    || !exact(input.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || input.integrity.algorithm !== 'hmac-sha256' || typeof input.integrity.keyId !== 'string'
    || !ID.test(input.integrity.keyId) || typeof input.integrity.payloadDigest !== 'string'
    || !DIGEST.test(input.integrity.payloadDigest) || typeof input.integrity.signature !== 'string'
    || !SIGNATURE.test(input.integrity.signature)) fail('m4_reconciliation_archive_revision_manifest_invalid');
  const body = revisionPayload(Object.fromEntries(Object.entries(input).filter(([name]) => name !== 'integrity')),
    'm4_reconciliation_archive_revision_manifest_invalid');
  const loaded = keyDocument(structuredClone(keyDocumentValue), 'm4_reconciliation_archive_revision_key_invalid');
  try {
    if (input.integrity.keyId !== loaded.keyId) fail('m4_reconciliation_archive_revision_key_id_mismatch');
    const digest = sha(body); if (digest !== input.integrity.payloadDigest) fail('m4_reconciliation_archive_revision_digest_mismatch');
    const expected = Buffer.from(signatureFor(digest, loaded, REVISION_DOMAIN), 'base64url');
    const received = Buffer.from(input.integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      fail('m4_reconciliation_archive_revision_signature_mismatch');
    }
    return { ...body, integrity: structuredClone(input.integrity) };
  } finally { loaded.key.fill(0); }
}

export function m4ReconciliationArchiveRevisionEvidence(value) {
  return { manifestId: value.manifestId, digest: value.integrity.payloadDigest, signature: value.integrity.signature };
}

export function createM4ReconciliationEventAccumulator() {
  const hash = crypto.createHash('sha256'); hash.update(`${SET_DOMAIN}\0`, 'utf8');
  let count = 0; let previous = null; let complete = false;
  return {
    add(event) {
      if (complete || !plain(event) || typeof event.eventId !== 'string' || (previous !== null && previous >= event.eventId)) {
        fail('m4_reconciliation_snapshot_event_order_invalid');
      }
      const encoded = canonicalJson(event); hash.update(`${Buffer.byteLength(encoded, 'utf8')}\0`, 'utf8'); hash.update(encoded, 'utf8');
      previous = event.eventId; count += 1;
      if (count > M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS) fail('m4_reconciliation_snapshot_event_count_invalid');
    },
    finish() {
      if (complete) fail('m4_reconciliation_snapshot_accumulator_closed');
      complete = true; return { eventCount: count, eventSetDigest: `sha256:${hash.digest('hex')}` };
    },
  };
}

export function createM4ReconciliationSnapshot(value, keyDocumentValue) {
  let input; try { input = structuredClone(value); } catch { fail('m4_reconciliation_snapshot_input_invalid'); }
  const body = payload({ schema: M4_RECONCILIATION_SNAPSHOT_SCHEMA, ...input }, 'm4_reconciliation_snapshot_input_invalid');
  const loaded = keyDocument(structuredClone(keyDocumentValue), 'm4_reconciliation_snapshot_key_invalid');
  try {
    const payloadDigest = sha(body);
    return { ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest,
      signature: signatureFor(payloadDigest, loaded) } };
  } finally { loaded.key.fill(0); }
}

export function verifyM4ReconciliationSnapshot(value, keyDocumentValue) {
  let input; try { input = structuredClone(value); } catch { fail('m4_reconciliation_snapshot_manifest_invalid'); }
  if (!plain(input) || !exact(input, ['schema', 'snapshotId', 'archive', 'revision', 'terminalCheckpoint',
    'capturedAt', 'revisionEvidence', 'prerequisiteEvidenceDigest', 'eventCount', 'eventSetDigest',
    'eventFileDigest', 'staticEvidenceDigest', 'integrity'])
    || !exact(input.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || input.integrity.algorithm !== 'hmac-sha256' || typeof input.integrity.keyId !== 'string'
    || !ID.test(input.integrity.keyId) || typeof input.integrity.payloadDigest !== 'string'
    || !DIGEST.test(input.integrity.payloadDigest) || typeof input.integrity.signature !== 'string'
    || !SIGNATURE.test(input.integrity.signature)) fail('m4_reconciliation_snapshot_manifest_invalid');
  const body = payload(Object.fromEntries(Object.entries(input).filter(([name]) => name !== 'integrity')),
    'm4_reconciliation_snapshot_manifest_invalid');
  const loaded = keyDocument(structuredClone(keyDocumentValue), 'm4_reconciliation_snapshot_key_invalid');
  try {
    if (input.integrity.keyId !== loaded.keyId) fail('m4_reconciliation_snapshot_key_id_mismatch');
    const digest = sha(body); if (digest !== input.integrity.payloadDigest) fail('m4_reconciliation_snapshot_digest_mismatch');
    const expected = Buffer.from(signatureFor(digest, loaded), 'base64url');
    const received = Buffer.from(input.integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      fail('m4_reconciliation_snapshot_signature_mismatch');
    }
    return { ...body, integrity: structuredClone(input.integrity) };
  } finally { loaded.key.fill(0); }
}
