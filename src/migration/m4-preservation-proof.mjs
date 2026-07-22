import crypto from 'node:crypto';

import { resolveContentProtection } from '../content-protection-v1.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { m4AuthorityEvidence, m4PolicyDigest, timestampWithin, verifyM4SelectorScopeSnapshot } from './m4-authority-snapshots.mjs';

export const M4_PRESERVATION_PROOF_SCHEMA = 'amf.m4-preservation-proof/v1';

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-preservation-proof/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SOURCE = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const REVISION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PRESERVED_CLASSES = ['proposal', 'canonical-memory', 'document'];
const MAX_SELECTORS = 256;

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
function policyBinding(value, code) {
  const item = snapshot(value, ['revision', 'digest'], code);
  if (typeof item.revision !== 'string' || !REVISION.test(item.revision) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function authorityEvidence(value, code) {
  const item = snapshot(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}
function keyDocument(value, code) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) { key.fill(0); fail(code); }
  return { keyId: item.keyId, key };
}
function requireIndependentKeys(authorityDocument, claimantDocuments, code) {
  const authority = keyDocument(structuredClone(authorityDocument), code);
  try {
    for (const document of claimantDocuments) {
      const claimant = keyDocument(structuredClone(document), code);
      try {
        if (authority.keyId === claimant.keyId || (authority.key.length === claimant.key.length && crypto.timingSafeEqual(authority.key, claimant.key))) fail(code);
      } finally { claimant.key.fill(0); }
    }
  } finally { authority.key.fill(0); }
}
function sha(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(payloadDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key).update(canonicalJson([DOMAIN, payloadDigest, loadedKey.keyId]), 'utf8').digest('base64url');
}
function selector(value, code) {
  const item = snapshot(value, ['sourceInstanceId', 'contentClass'], code);
  if (typeof item.sourceInstanceId !== 'string' || !SOURCE.test(item.sourceInstanceId) || item.contentClass !== 'conversation') fail(code);
  return item;
}
function selectors(value, code) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_SELECTORS) fail(code);
  const result = value.map(item => selector(item, code));
  for (let index = 1; index < result.length; index += 1) {
    if (result[index - 1].sourceInstanceId >= result[index].sourceInstanceId) fail(code);
  }
  return result;
}
function disposition(value, expected, code) {
  const item = snapshot(value, ['sourceInstanceId', 'contentClass', 'scannedPlaintextCount', 'retainedEncryptedCount', 'cleanupTargetCount', 'binding'], code);
  if (item.sourceInstanceId !== expected.sourceInstanceId || item.contentClass !== expected.contentClass
    || !Number.isSafeInteger(item.scannedPlaintextCount) || item.scannedPlaintextCount < 0
    || !Number.isSafeInteger(item.retainedEncryptedCount) || item.retainedEncryptedCount < 0
    || !Number.isSafeInteger(item.cleanupTargetCount) || item.cleanupTargetCount < 0
    || item.scannedPlaintextCount !== item.retainedEncryptedCount + item.cleanupTargetCount) fail(code);
  return { sourceInstanceId: item.sourceInstanceId, contentClass: item.contentClass, scannedPlaintextCount: item.scannedPlaintextCount,
    retainedEncryptedCount: item.retainedEncryptedCount, cleanupTargetCount: item.cleanupTargetCount, binding: checkpoint(item.binding, code) };
}
function preserved(value, code) {
  if (!Array.isArray(value) || value.length !== PRESERVED_CLASSES.length) fail(code);
  return PRESERVED_CLASSES.map((contentClass, index) => {
    const item = snapshot(value[index], ['contentClass', 'count', 'binding'], code);
    if (item.contentClass !== contentClass || !Number.isSafeInteger(item.count) || item.count < 0) fail(code);
    return { contentClass, count: item.count, binding: checkpoint(item.binding, code) };
  });
}
function distinctBindings(dispositions, preservedItems, restore, code) {
  const ids = new Set(); const digests = new Set();
  for (const binding of [...dispositions.map(item => item.binding), ...preservedItems.map(item => item.binding), restore.evidence]) {
    if (ids.has(binding.id) || digests.has(binding.digest)) fail(code);
    ids.add(binding.id); digests.add(binding.digest);
  }
}
function payload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'provedAt', 'policyBinding', 'selectorScopeEvidence', 'selectors', 'dispositions', 'preservedSharedData', 'rollbackPolicyBinding', 'restoreTest'], code);
  if (item.schema !== M4_PRESERVATION_PROOF_SCHEMA || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || item.state !== 'passed') fail(code);
  try { if (!timestampWithin(item.provedAt, item.provedAt, item.provedAt)) fail(code); } catch { fail(code); }
  const selected = selectors(item.selectors, code);
  if (!Array.isArray(item.dispositions) || item.dispositions.length !== selected.length) fail(code);
  const dispositions = selected.map((expected, index) => disposition(item.dispositions[index], expected, code));
  const preservedItems = preserved(item.preservedSharedData, code);
  const restore = snapshot(item.restoreTest, ['state', 'evidence'], code);
  if (restore.state !== 'passed') fail(code);
  const restoreTest = { state: 'passed', evidence: checkpoint(restore.evidence, code) };
  distinctBindings(dispositions, preservedItems, restoreTest, code);
  return { schema: M4_PRESERVATION_PROOF_SCHEMA, manifestId: item.manifestId, revision: item.revision, state: 'passed', provedAt: item.provedAt,
    policyBinding: policyBinding(item.policyBinding, code), selectorScopeEvidence: authorityEvidence(item.selectorScopeEvidence, code), selectors: selected, dispositions, preservedSharedData: preservedItems,
    rollbackPolicyBinding: policyBinding(item.rollbackPolicyBinding, code), restoreTest };
}
function signed(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'provedAt', 'policyBinding', 'selectorScopeEvidence', 'selectors', 'dispositions', 'preservedSharedData', 'rollbackPolicyBinding', 'restoreTest', 'integrity'], code);
  const body = payload({ schema: item.schema, manifestId: item.manifestId, revision: item.revision, state: item.state,
    provedAt: item.provedAt, policyBinding: item.policyBinding, selectorScopeEvidence: item.selectorScopeEvidence, selectors: item.selectors, dispositions: item.dispositions, preservedSharedData: item.preservedSharedData,
    rollbackPolicyBinding: item.rollbackPolicyBinding, restoreTest: item.restoreTest }, code);
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (integrity.algorithm !== 'hmac-sha256' || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId)
    || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest)
    || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) fail(code);
  return { ...body, integrity };
}

export function createM4PreservationProof(value, authorities) {
  let item;
  try { item = structuredClone(value); } catch { fail('m4_preservation_proof_input_invalid'); }
  const input = snapshot(item, ['manifestId', 'revision', 'provedAt', 'policy', 'selectorScopeManifest', 'dispositions', 'preservedSharedData', 'rollbackPolicyBinding', 'restoreTest', 'signingKeyDocument'], 'm4_preservation_proof_input_invalid');
  let trusted;
  try { trusted = snapshot(structuredClone(authorities), ['selectorScopeKeyDocument'], 'm4_preservation_proof_authority_invalid'); }
  catch { fail('m4_preservation_proof_authority_invalid'); }
  requireIndependentKeys(trusted.selectorScopeKeyDocument, [input.signingKeyDocument], 'm4_preservation_proof_authority_invalid');
  if (typeof input.manifestId !== 'string' || !ID.test(input.manifestId) || !Number.isSafeInteger(input.revision) || input.revision < 1) fail('m4_preservation_proof_input_invalid');
  let policy;
  try { policy = structuredClone(input.policy); } catch { fail('m4_preservation_proof_policy_invalid'); }
  let scope;
  try { scope = verifyM4SelectorScopeSnapshot(input.selectorScopeManifest, trusted.selectorScopeKeyDocument); }
  catch { fail('m4_preservation_proof_scope_invalid'); }
  const selected = selectors(scope.selectors, 'm4_preservation_proof_scope_invalid');
  if (scope.policyRevision !== policy.revision || scope.policyDigest !== m4PolicyDigest(policy)) fail('m4_preservation_proof_policy_mismatch');
  if (!timestampWithin(input.provedAt, scope.observedAt, scope.validThrough)) fail('m4_preservation_proof_scope_stale');
  for (const itemSelector of selected) {
    let resolved; try { resolved = resolveContentProtection(policy, itemSelector.sourceInstanceId, itemSelector.contentClass); }
    catch { fail('m4_preservation_proof_policy_invalid'); }
    if (resolved.codec !== 'aes-256-gcm' || resolved.readPlaintext !== false) fail('m4_preservation_proof_plaintext_open');
  }
  const loaded = keyDocument(input.signingKeyDocument, 'm4_preservation_proof_key_invalid');
  try {
    const body = payload({ schema: M4_PRESERVATION_PROOF_SCHEMA, manifestId: input.manifestId, revision: input.revision, state: 'passed',
      provedAt: input.provedAt, policyBinding: { revision: policy.revision, digest: sha(policy) }, selectorScopeEvidence: m4AuthorityEvidence(scope), selectors: selected, dispositions: input.dispositions,
      preservedSharedData: input.preservedSharedData, rollbackPolicyBinding: input.rollbackPolicyBinding, restoreTest: input.restoreTest }, 'm4_preservation_proof_input_invalid');
    const payloadDigest = sha(body);
    return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: signatureFor(payloadDigest, loaded) } });
  } finally { loaded.key.fill(0); }
}

export function verifyM4PreservationProof(value, signingKeyDocument) {
  let manifest; try { manifest = signed(structuredClone(value), 'm4_preservation_proof_manifest_invalid'); }
  catch (error) { if (error?.code) throw error; fail('m4_preservation_proof_manifest_invalid'); }
  const loaded = keyDocument(structuredClone(signingKeyDocument), 'm4_preservation_proof_key_invalid');
  try {
    if (manifest.integrity.keyId !== loaded.keyId) fail('m4_preservation_proof_key_id_mismatch');
    const { integrity, ...body } = manifest; const payloadDigest = sha(body);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_preservation_proof_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_preservation_proof_signature_mismatch');
    return structuredClone(manifest);
  } finally { loaded.key.fill(0); }
}
