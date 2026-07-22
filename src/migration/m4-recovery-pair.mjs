import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4ReconciliationManifest } from './m4-reconciliation-manifest.mjs';

const SCHEMA = 'amf.migration-manifest/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.migration-manifest/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ARCHIVES = ['legacy-v2', 'v3'];
const CHECKPOINTS = ['recoveryCopy', 'catalogSnapshot', 'isolatedRestoreTarget', 'restoredCheckpoint', 'verification'];

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function snapshot(value, keys, code) {
  try {
    if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
    return Object.fromEntries(keys.map(key => [key, value[key]]));
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}
function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function keyDocument(value, code) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) { key.fill(0); fail(code); }
  return { keyId: item.keyId, key };
}
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(payloadDigest, loadedKey) { return crypto.createHmac('sha256', loadedKey.key).update(canonicalJson([DOMAIN, payloadDigest, loadedKey.keyId]), 'utf8').digest('base64url'); }
function reconciliationEvidence(manifest, code) {
  try {
    return { manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest, signature: manifest.integrity.signature };
  } catch { fail(code); }
}
function record(value, expectedArchive, code) {
  const item = snapshot(value, ['archive', ...CHECKPOINTS, 'restoreTest'], code);
  if (item.archive !== expectedArchive || item.restoreTest !== 'passed') fail(code);
  const result = { archive: expectedArchive, restoreTest: 'passed' };
  for (const name of CHECKPOINTS) result[name] = checkpoint(item[name], code);
  for (let index = 0; index < CHECKPOINTS.length; index += 1) for (let other = index + 1; other < CHECKPOINTS.length; other += 1) {
    const left = result[CHECKPOINTS[index]]; const right = result[CHECKPOINTS[other]];
    if (left.id === right.id || left.digest === right.digest) fail(code);
  }
  return { archive: result.archive, recoveryCopy: result.recoveryCopy, catalogSnapshot: result.catalogSnapshot, isolatedRestoreTarget: result.isolatedRestoreTarget, restoredCheckpoint: result.restoredCheckpoint, verification: result.verification, restoreTest: result.restoreTest };
}
function distinctArchives(records, code) {
  const ids = new Set(); const digests = new Set();
  for (const item of records) for (const name of CHECKPOINTS) {
    const selected = item[name];
    if (ids.has(selected.id) || digests.has(selected.digest)) fail(code);
    ids.add(selected.id); digests.add(selected.digest);
  }
}
function payload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'phase', 'revision', 'reconciliationEvidence', 'archives'], code);
  if (item.schema !== SCHEMA || item.phase !== 'recovery' || typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || !Number.isSafeInteger(item.revision) || item.revision < 1 || !Array.isArray(item.archives) || item.archives.length !== 2) fail(code);
  const evidence = snapshot(item.reconciliationEvidence, ['manifestId', 'digest', 'signature'], code);
  if (typeof evidence.manifestId !== 'string' || !ID.test(evidence.manifestId) || typeof evidence.digest !== 'string' || !DIGEST.test(evidence.digest) || typeof evidence.signature !== 'string' || !SIGNATURE.test(evidence.signature)) fail(code);
  const archives = ARCHIVES.map((archive, index) => record(item.archives[index], archive, code));
  distinctArchives(archives, code);
  return { schema: SCHEMA, manifestId: item.manifestId, phase: 'recovery', revision: item.revision, reconciliationEvidence: evidence, archives };
}
function signedManifest(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'phase', 'revision', 'reconciliationEvidence', 'archives', 'integrity'], code);
  const body = payload({ schema: item.schema, manifestId: item.manifestId, phase: item.phase, revision: item.revision, reconciliationEvidence: item.reconciliationEvidence, archives: item.archives }, code);
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (integrity.algorithm !== 'hmac-sha256' || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId) || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest) || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) fail(code);
  return { ...body, integrity };
}

export function createM4RecoveryPairManifest(value) {
  const item = snapshot(value, ['manifestId', 'revision', 'reconciliationManifest', 'reconciliationKeyDocument', 'legacyRecord', 'v3Record', 'recoveryKeyDocument'], 'm4_recovery_pair_input_invalid');
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || !Number.isSafeInteger(item.revision) || item.revision < 1) fail('m4_recovery_pair_input_invalid');
  let reconciliation;
  try { reconciliation = verifyM4ReconciliationManifest(structuredClone(item.reconciliationManifest), structuredClone(item.reconciliationKeyDocument)); } catch { fail('m4_recovery_pair_reconciliation_invalid'); }
  if (reconciliation.reconciliation.state !== 'complete' || reconciliation.reconciliation.completeness !== 1 || reconciliation.reconciliation.tolerance !== 0 || reconciliation.reconciliation.unresolvedMismatchCount !== 0) fail('m4_recovery_pair_reconciliation_incomplete');
  const key = keyDocument(item.recoveryKeyDocument, 'm4_recovery_pair_key_invalid');
  try {
    const body = payload({ schema: SCHEMA, manifestId: item.manifestId, phase: 'recovery', revision: item.revision, reconciliationEvidence: reconciliationEvidence(reconciliation, 'm4_recovery_pair_reconciliation_invalid'), archives: [item.legacyRecord, item.v3Record] }, 'm4_recovery_pair_record_invalid');
    const payloadDigest = digest(body);
    return { ...body, integrity: { algorithm: 'hmac-sha256', keyId: key.keyId, payloadDigest, signature: signatureFor(payloadDigest, key) } };
  } finally { key.key.fill(0); }
}

export function verifyM4RecoveryPairManifest(value, recoveryKeyDocument) {
  const manifest = signedManifest(value, 'm4_recovery_pair_manifest_invalid');
  const key = keyDocument(recoveryKeyDocument, 'm4_recovery_pair_key_invalid');
  try {
    if (manifest.integrity.keyId !== key.keyId) fail('m4_recovery_pair_key_id_mismatch');
    const { integrity, ...body } = manifest; const payloadDigest = digest(body);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_recovery_pair_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, key), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_recovery_pair_signature_mismatch');
    return structuredClone(manifest);
  } finally { key.key.fill(0); }
}
