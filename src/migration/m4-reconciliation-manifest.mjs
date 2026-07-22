import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { validatePauseManifest, verifyPauseManifest } from '../migration-pause.mjs';
import { verifyM4RollbackManifest } from './m4-backfill-gate.mjs';
import { M4_DIMENSIONS, validateM4ReconciliationReport } from './m4-reconciliation-reader.mjs';

const MANIFEST_SCHEMA = 'amf.migration-manifest/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const SIGNATURE_DOMAIN = 'amf.migration-manifest/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const AGGREGATE_PAUSE_ID = /^pause-set-[a-f0-9]{64}$/;

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

function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id)
    || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}

function evidence(value, code) {
  const item = snapshot(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}

function signingKey(value, code) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId)
    || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) fail(code);
  return { keyId: item.keyId, key };
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function signatureFor(payloadDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key)
    .update(canonicalJson([SIGNATURE_DOMAIN, payloadDigest, loadedKey.keyId]), 'utf8')
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

function reconciliationBody(value, code) {
  const item = snapshot(value, [
    'state', 'pauseEvidence', 'rollbackEvidence', 'dimensions',
    'dimensionsBinding', 'completeness', 'tolerance', 'unresolvedMismatchCount',
  ], code);
  if (!['pending', 'complete'].includes(item.state)
    || !Array.isArray(item.dimensions) || canonicalJson(item.dimensions) !== canonicalJson(M4_DIMENSIONS)
    || item.completeness !== 1 || item.tolerance !== 0
    || !Number.isSafeInteger(item.unresolvedMismatchCount) || item.unresolvedMismatchCount < 0
    || (item.state === 'complete') !== (item.unresolvedMismatchCount === 0)) fail(code);
  return {
    state: item.state,
    pauseEvidence: evidence(item.pauseEvidence, code),
    rollbackEvidence: evidence(item.rollbackEvidence, code),
    dimensions: [...M4_DIMENSIONS],
    dimensionsBinding: checkpoint(item.dimensionsBinding, code),
    completeness: 1,
    tolerance: 0,
    unresolvedMismatchCount: item.unresolvedMismatchCount,
  };
}

function manifestPayload(value, code) {
  const item = snapshot(
    value,
    ['schema', 'manifestId', 'phase', 'revision', 'reconciliation'],
    code,
  );
  if (item.schema !== MANIFEST_SCHEMA || item.phase !== 'reconciliation'
    || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1) fail(code);
  return {
    schema: MANIFEST_SCHEMA,
    manifestId: item.manifestId,
    phase: 'reconciliation',
    revision: item.revision,
    reconciliation: reconciliationBody(item.reconciliation, code),
  };
}

function manifestWithIntegrity(value) {
  const item = snapshot(value, [
    'schema', 'manifestId', 'phase', 'revision', 'reconciliation', 'integrity',
  ], 'm4_reconciliation_manifest_invalid');
  const payload = manifestPayload({
    schema: item.schema,
    manifestId: item.manifestId,
    phase: item.phase,
    revision: item.revision,
    reconciliation: item.reconciliation,
  }, 'm4_reconciliation_manifest_invalid');
  const integrity = snapshot(
    item.integrity,
    ['algorithm', 'keyId', 'payloadDigest', 'signature'],
    'm4_reconciliation_manifest_invalid',
  );
  if (integrity.algorithm !== 'hmac-sha256'
    || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId)
    || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest)
    || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) {
    fail('m4_reconciliation_manifest_invalid');
  }
  return { ...payload, integrity };
}

function verifiedEvidence(item) {
  let pauseManifest;
  let rollbackManifest;
  try {
    pauseManifest = structuredClone(item.pauseManifest);
    validatePauseManifest(pauseManifest);
    verifyPauseManifest(pauseManifest, structuredClone(item.pauseKeyDocument));
    rollbackManifest = verifyM4RollbackManifest(
      structuredClone(item.rollbackManifest),
      structuredClone(item.rollbackKeyDocument),
    );
  } catch {
    fail('m4_reconciliation_manifest_evidence_invalid');
  }
  if (!AGGREGATE_PAUSE_ID.test(pauseManifest.pause.evidence.id)
    || !same(rollbackManifest.rollback.pauseEvidence, evidenceFor(pauseManifest))
    || !same(rollbackManifest.rollback.sourceCheckpoint, pauseManifest.pause.sourceCheckpoint)
    || rollbackManifest.rollback.restoreTest !== 'passed') {
    fail('m4_reconciliation_manifest_evidence_invalid');
  }
  return { pauseManifest, rollbackManifest };
}

export function createM4ReconciliationManifest(value) {
  const item = snapshot(value, [
    'manifestId', 'revision', 'report', 'pauseManifest', 'pauseKeyDocument',
    'rollbackManifest', 'rollbackKeyDocument', 'reconciliationKeyDocument',
  ], 'm4_reconciliation_manifest_input_invalid');
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1) {
    fail('m4_reconciliation_manifest_input_invalid');
  }
  let report;
  try {
    report = validateM4ReconciliationReport(item.report);
  } catch {
    fail('m4_reconciliation_manifest_report_invalid');
  }
  const verified = verifiedEvidence(item);
  const key = signingKey(item.reconciliationKeyDocument, 'm4_reconciliation_manifest_key_invalid');
  try {
    const reconciliation = reconciliationBody({
    state: report.state,
    pauseEvidence: evidenceFor(verified.pauseManifest),
    rollbackEvidence: evidenceFor(verified.rollbackManifest),
    dimensions: report.dimensions,
    dimensionsBinding: report.dimensionsBinding,
    completeness: report.completeness,
    tolerance: report.tolerance,
    unresolvedMismatchCount: report.unresolvedMismatchCount,
  }, 'm4_reconciliation_manifest_report_invalid');
  const payload = manifestPayload({
    schema: MANIFEST_SCHEMA,
    manifestId: item.manifestId,
    phase: 'reconciliation',
    revision: item.revision,
    reconciliation,
  }, 'm4_reconciliation_manifest_report_invalid');
  const payloadDigest = digest(payload);
    return { ...payload, integrity: { algorithm: 'hmac-sha256', keyId: key.keyId,
      payloadDigest, signature: signatureFor(payloadDigest, key) } };
  } finally { key.key.fill(0); }
}

export function verifyM4ReconciliationManifest(value, keyDocument) {
  const manifest = manifestWithIntegrity(value);
  const key = signingKey(keyDocument, 'm4_reconciliation_manifest_key_invalid');
  try {
    if (manifest.integrity.keyId !== key.keyId) fail('m4_reconciliation_manifest_key_id_mismatch');
    const { integrity, ...payload } = manifest;
    const payloadDigest = digest(payload);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_reconciliation_manifest_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, key), 'base64url');
    const received = Buffer.from(integrity.signature, 'base64url');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      fail('m4_reconciliation_manifest_signature_mismatch');
    }
    return structuredClone(manifest);
  } finally { key.key.fill(0); }
}
