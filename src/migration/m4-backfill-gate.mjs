import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { validatePauseManifest, verifyPauseManifest } from '../migration-pause.mjs';

const MANIFEST_SCHEMA = 'amf.migration-manifest/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const GATE_SCHEMA = 'amf.m4-backfill-gate/v1';
const SIGNATURE_DOMAIN = 'amf.migration-manifest/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const AGGREGATE_PAUSE_ID = /^pause-set-[a-f0-9]{64}$/;
const PHASES = new Set(['v2-archive', 'paused-native']);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plainObject(value) {
  return value !== null && typeof value === 'object'
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, expected, code) {
  if (!plainObject(value)) fail(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])) fail(code);
}

function copyId(value, code) {
  if (typeof value !== 'string' || !ID.test(value)) fail(code);
  return value;
}

function copyCheckpoint(value, code) {
  exactKeys(value, ['id', 'digest'], code);
  if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: copyId(value.id, code), digest: value.digest };
}

function copySignedEvidence(value, code) {
  exactKeys(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return {
    manifestId: copyId(value.manifestId, code),
    digest: value.digest,
    signature: value.signature,
  };
}

function copyRollback(value, code) {
  exactKeys(value, [
    'pauseEvidence', 'sourceCheckpoint', 'targetCheckpoint',
    'compatibilityRouteRevision', 'recoveryCopy', 'restoreTest',
  ], code);
  if (!['not-run', 'passed', 'failed'].includes(value.restoreTest)) fail(code);
  return {
    pauseEvidence: copySignedEvidence(value.pauseEvidence, code),
    sourceCheckpoint: copyCheckpoint(value.sourceCheckpoint, code),
    targetCheckpoint: copyCheckpoint(value.targetCheckpoint, code),
    compatibilityRouteRevision: copyId(value.compatibilityRouteRevision, code),
    recoveryCopy: copyCheckpoint(value.recoveryCopy, code),
    restoreTest: value.restoreTest,
  };
}

function copyRollbackPayload(value, code) {
  exactKeys(value, ['schema', 'manifestId', 'phase', 'revision', 'rollback'], code);
  if (value.schema !== MANIFEST_SCHEMA || value.phase !== 'rollback'
    || !Number.isSafeInteger(value.revision) || value.revision < 1) fail(code);
  return {
    schema: MANIFEST_SCHEMA,
    manifestId: copyId(value.manifestId, code),
    phase: 'rollback',
    revision: value.revision,
    rollback: copyRollback(value.rollback, code),
  };
}

function copyIntegrity(value, code) {
  exactKeys(value, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (value.algorithm !== 'hmac-sha256'
    || typeof value.payloadDigest !== 'string' || !DIGEST.test(value.payloadDigest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return {
    algorithm: 'hmac-sha256',
    keyId: copyId(value.keyId, code),
    payloadDigest: value.payloadDigest,
    signature: value.signature,
  };
}

function copyRollbackManifest(value, code) {
  exactKeys(value, ['schema', 'manifestId', 'phase', 'revision', 'rollback', 'integrity'], code);
  const payload = copyRollbackPayload({
    schema: value.schema,
    manifestId: value.manifestId,
    phase: value.phase,
    revision: value.revision,
    rollback: value.rollback,
  }, code);
  return { ...payload, integrity: copyIntegrity(value.integrity, code) };
}

function loadKey(value, code) {
  exactKeys(value, ['schema', 'keyId', 'key'], code);
  if (value.schema !== KEY_SCHEMA || typeof value.key !== 'string' || !BASE64.test(value.key)) fail(code);
  const keyId = copyId(value.keyId, code);
  const key = Buffer.from(value.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== value.key) fail(code);
  return { keyId, key };
}

function payloadDigest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function signatureFor(digest, keyId, key) {
  return crypto.createHmac('sha256', key)
    .update(canonicalJson([SIGNATURE_DOMAIN, digest, keyId]), 'utf8')
    .digest('base64url');
}

function evidenceFor(manifest) {
  return {
    manifestId: manifest.manifestId,
    digest: manifest.integrity.payloadDigest,
    signature: manifest.integrity.signature,
  };
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function createM4RollbackManifest(payloadValue, keyDocument) {
  const payload = copyRollbackPayload(payloadValue, 'm4_rollback_manifest_input_invalid');
  const loadedKey = loadKey(keyDocument, 'm4_rollback_key_invalid');
  const digest = payloadDigest(payload);
  return {
    ...payload,
    integrity: {
      algorithm: 'hmac-sha256',
      keyId: loadedKey.keyId,
      payloadDigest: digest,
      signature: signatureFor(digest, loadedKey.keyId, loadedKey.key),
    },
  };
}

export function verifyM4RollbackManifest(manifestValue, keyDocument) {
  const manifest = copyRollbackManifest(manifestValue, 'm4_rollback_manifest_invalid');
  const loadedKey = loadKey(keyDocument, 'm4_rollback_key_invalid');
  if (loadedKey.keyId !== manifest.integrity.keyId) fail('m4_rollback_key_id_mismatch');
  const { integrity, ...payload } = manifest;
  const digest = payloadDigest(payload);
  if (digest !== integrity.payloadDigest) fail('m4_rollback_digest_mismatch');
  const expected = Buffer.from(signatureFor(digest, integrity.keyId, loadedKey.key), 'base64url');
  const received = Buffer.from(integrity.signature, 'base64url');
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    fail('m4_rollback_signature_mismatch');
  }
  return structuredClone(manifest);
}

export function verifyM4BackfillGate(value) {
  exactKeys(value, [
    'runId', 'phase', 'pauseManifest', 'pauseKeyDocument',
    'rollbackManifest', 'rollbackKeyDocument',
  ], 'm4_backfill_gate_input_invalid');
  const runId = copyId(value.runId, 'm4_backfill_gate_input_invalid');
  if (typeof value.phase !== 'string' || !PHASES.has(value.phase)) fail('m4_backfill_gate_input_invalid');

  let pauseManifest;
  try {
    pauseManifest = validatePauseManifest(value.pauseManifest);
    if (!AGGREGATE_PAUSE_ID.test(pauseManifest.pause.evidence.id)) throw new Error('aggregate required');
    verifyPauseManifest(pauseManifest, value.pauseKeyDocument);
  } catch {
    fail('m4_backfill_gate_pause_invalid');
  }

  let rollbackManifest;
  try {
    rollbackManifest = verifyM4RollbackManifest(value.rollbackManifest, value.rollbackKeyDocument);
  } catch {
    fail('m4_backfill_gate_rollback_invalid');
  }

  const pauseEvidence = evidenceFor(pauseManifest);
  if (!same(rollbackManifest.rollback.pauseEvidence, pauseEvidence)
    || !same(rollbackManifest.rollback.sourceCheckpoint, pauseManifest.pause.sourceCheckpoint)) {
    fail('m4_backfill_gate_evidence_mismatch');
  }
  if (rollbackManifest.rollback.restoreTest !== 'passed') fail('m4_backfill_gate_restore_required');

  return {
    schema: GATE_SCHEMA,
    state: 'approved',
    runId,
    phase: value.phase,
    pauseEvidence: structuredClone(pauseEvidence),
    rollbackEvidence: evidenceFor(rollbackManifest),
    sourceCheckpoint: structuredClone(rollbackManifest.rollback.sourceCheckpoint),
    targetCheckpoint: structuredClone(rollbackManifest.rollback.targetCheckpoint),
  };
}

export function createM4BackfillGateVerifier(value) {
  const verified = verifyM4BackfillGate(value);
  return async () => structuredClone(verified);
}
