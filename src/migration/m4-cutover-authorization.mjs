import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4ConversationExtractorAliases } from './m4-conversation-extractor-aliases.mjs';
import { m4AuthorityEvidence, timestampWithin, verifyM4SelectorScopeSnapshot } from './m4-authority-snapshots.mjs';
import { verifyM4CutoverCanaryManifest } from './m4-cutover-canary.mjs';
import { verifyM4PreservationProof } from './m4-preservation-proof.mjs';
import { verifyM4ReconciliationManifest } from './m4-reconciliation-manifest.mjs';
import { verifyM4RecoveryPairManifest } from './m4-recovery-pair.mjs';

export const M4_CUTOVER_AUTHORIZATION_SCHEMA = 'amf.m4-cutover-authorization/v1';

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-cutover-authorization/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

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
function evidence(value, withState, code) {
  const keys = withState ? ['manifestId', 'digest', 'signature', 'state'] : ['manifestId', 'digest', 'signature'];
  const item = snapshot(value, keys, code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature) || (withState && item.state !== 'passed')) fail(code);
  return item;
}
function evidenceFor(manifest, state = null) {
  return { manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest, signature: manifest.integrity.signature,
    ...(state === null ? {} : { state }) };
}
function keyDocument(value, code, exactBytes = null) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if ((exactBytes === null ? key.length < 32 || key.length > 64 : key.length !== exactBytes) || key.toString('base64') !== item.key) { key.fill(0); fail(code); }
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
function routeConfiguration(value, code) {
  const item = snapshot(value, ['publicReader', 'extractorReader'], code);
  const publicReader = snapshot(item.publicReader, ['mode', 'revision'], code);
  const extractorReader = snapshot(item.extractorReader, ['mode', 'revision', 'stateGeneration', 'stateBoundary', 'coverageVerification'], code);
  if (publicReader.mode !== 'active' || extractorReader.mode !== 'v3' || extractorReader.stateGeneration !== 'conversation-v3') fail(code);
  const revision = checkpoint(extractorReader.revision, code); const stateBoundary = checkpoint(extractorReader.stateBoundary, code);
  const coverageVerification = checkpoint(extractorReader.coverageVerification, code);
  if (new Set([revision.id, stateBoundary.id, coverageVerification.id]).size !== 3
    || new Set([revision.digest, stateBoundary.digest, coverageVerification.digest]).size !== 3) fail(code);
  return { publicReader: { mode: 'active', revision: checkpoint(publicReader.revision, code) },
    extractorReader: { mode: 'v3', revision, stateGeneration: 'conversation-v3', stateBoundary, coverageVerification } };
}
function aliasBinding(value, code) {
  const item = snapshot(value, ['coveredThrough', 'conversationCount', 'conversationDigest', 'aliasDigest', 'manifestDigest'], code);
  if (typeof item.coveredThrough !== 'string' || !Number.isSafeInteger(item.conversationCount) || item.conversationCount < 0
    || !DIGEST.test(item.conversationDigest) || !DIGEST.test(item.aliasDigest) || !DIGEST.test(item.manifestDigest)) fail(code);
  return item;
}
function policyBinding(value, code) {
  const item = snapshot(value, ['revision', 'digest'], code);
  if (typeof item.revision !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(item.revision) || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function payload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'authorizedAt', 'reconciliationEvidence', 'recoveryEvidence', 'legacyRecoveryCopy', 'aliasBinding', 'canaryEvidence', 'preservationEvidence', 'selectorScopeEvidence', 'authoritativePolicyBinding', 'routeConfiguration', 'rollbackRevision'], code);
  if (item.schema !== M4_CUTOVER_AUTHORIZATION_SCHEMA || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || item.state !== 'authorized') fail(code);
  try { if (!timestampWithin(item.authorizedAt, item.authorizedAt, item.authorizedAt)) fail(code); } catch { fail(code); }
  return { schema: M4_CUTOVER_AUTHORIZATION_SCHEMA, manifestId: item.manifestId, revision: item.revision, state: 'authorized', authorizedAt: item.authorizedAt,
    reconciliationEvidence: evidence(item.reconciliationEvidence, false, code), recoveryEvidence: evidence(item.recoveryEvidence, false, code),
    legacyRecoveryCopy: checkpoint(item.legacyRecoveryCopy, code),
    aliasBinding: aliasBinding(item.aliasBinding, code), canaryEvidence: evidence(item.canaryEvidence, true, code),
    preservationEvidence: evidence(item.preservationEvidence, true, code), selectorScopeEvidence: evidence(item.selectorScopeEvidence, false, code),
    authoritativePolicyBinding: policyBinding(item.authoritativePolicyBinding, code), routeConfiguration: routeConfiguration(item.routeConfiguration, code),
    rollbackRevision: checkpoint(item.rollbackRevision, code) };
}
function signed(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'authorizedAt', 'reconciliationEvidence', 'recoveryEvidence', 'legacyRecoveryCopy', 'aliasBinding', 'canaryEvidence', 'preservationEvidence', 'selectorScopeEvidence', 'authoritativePolicyBinding', 'routeConfiguration', 'rollbackRevision', 'integrity'], code);
  const body = payload({ schema: item.schema, manifestId: item.manifestId, revision: item.revision, state: item.state,
    authorizedAt: item.authorizedAt,
    reconciliationEvidence: item.reconciliationEvidence, recoveryEvidence: item.recoveryEvidence, legacyRecoveryCopy: item.legacyRecoveryCopy, aliasBinding: item.aliasBinding,
    canaryEvidence: item.canaryEvidence, preservationEvidence: item.preservationEvidence, selectorScopeEvidence: item.selectorScopeEvidence,
    authoritativePolicyBinding: item.authoritativePolicyBinding, routeConfiguration: item.routeConfiguration,
    rollbackRevision: item.rollbackRevision }, code);
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (integrity.algorithm !== 'hmac-sha256' || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId)
    || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest)
    || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) fail(code);
  return { ...body, integrity };
}
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }

export function createM4CutoverAuthorization(value, authorities) {
  let input; try { input = structuredClone(value); } catch { fail('m4_cutover_authorization_input_invalid'); }
  const item = snapshot(input, ['manifestId', 'revision', 'reconciliationManifest', 'reconciliationKeyDocument', 'recoveryManifest', 'recoveryKeyDocument',
    'aliasManifest', 'aliasKeyDocument', 'canaryManifest', 'canaryKeyDocument', 'preservationManifest', 'preservationKeyDocument',
    'selectorScopeManifest', 'authorizedAt', 'routeConfiguration', 'rollbackRevision', 'authorizationKeyDocument'], 'm4_cutover_authorization_input_invalid');
  let trusted;
  try { trusted = snapshot(structuredClone(authorities), ['selectorScopeKeyDocument'], 'm4_cutover_authorization_authority_invalid'); }
  catch { fail('m4_cutover_authorization_authority_invalid'); }
  requireIndependentKeys(trusted.selectorScopeKeyDocument, [item.preservationKeyDocument, item.authorizationKeyDocument], 'm4_cutover_authorization_authority_invalid');
  let reconciliation; let recovery; let canary; let preservation; let scope; let verifiedAliases;
  try {
    reconciliation = verifyM4ReconciliationManifest(item.reconciliationManifest, item.reconciliationKeyDocument);
    recovery = verifyM4RecoveryPairManifest(item.recoveryManifest, item.recoveryKeyDocument);
    canary = verifyM4CutoverCanaryManifest(item.canaryManifest, item.canaryKeyDocument);
    preservation = verifyM4PreservationProof(item.preservationManifest, item.preservationKeyDocument);
    scope = verifyM4SelectorScopeSnapshot(item.selectorScopeManifest, trusted.selectorScopeKeyDocument);
  } catch { fail('m4_cutover_authorization_evidence_invalid'); }
  if (reconciliation.reconciliation.state !== 'complete' || canary.state !== 'passed' || preservation.state !== 'passed'
    || !same(recovery.reconciliationEvidence, evidenceFor(reconciliation))) fail('m4_cutover_authorization_evidence_incomplete');
  if (!same(preservation.selectorScopeEvidence, m4AuthorityEvidence(scope))
    || !same(preservation.policyBinding, { revision: scope.policyRevision, digest: scope.policyDigest })) fail('m4_cutover_authorization_scope_mismatch');
  if (!timestampWithin(item.authorizedAt, scope.observedAt, scope.validThrough)) fail('m4_cutover_authorization_scope_stale');
  const aliasKey = keyDocument(item.aliasKeyDocument, 'm4_cutover_authorization_alias_key_invalid', 32);
  try { verifiedAliases = verifyM4ConversationExtractorAliases(item.aliasManifest, aliasKey.key); }
  catch { fail('m4_cutover_authorization_alias_invalid'); }
  finally { aliasKey.key.fill(0); }
  const routes = routeConfiguration(item.routeConfiguration, 'm4_cutover_authorization_input_invalid');
  const rollbackRevision = checkpoint(item.rollbackRevision, 'm4_cutover_authorization_input_invalid');
  if (!same(rollbackRevision, canary.observations.rollbackDrill.configurationRevision)) fail('m4_cutover_authorization_rollback_mismatch');
  const loaded = keyDocument(item.authorizationKeyDocument, 'm4_cutover_authorization_key_invalid');
  try {
    const body = payload({ schema: M4_CUTOVER_AUTHORIZATION_SCHEMA, manifestId: item.manifestId, revision: item.revision, state: 'authorized', authorizedAt: item.authorizedAt,
      reconciliationEvidence: evidenceFor(reconciliation), recoveryEvidence: evidenceFor(recovery), legacyRecoveryCopy: recovery.archives[0].recoveryCopy,
      aliasBinding: { coveredThrough: verifiedAliases.coveredThrough, conversationCount: verifiedAliases.archiveBinding.conversationCount,
        conversationDigest: verifiedAliases.archiveBinding.conversationDigest, aliasDigest: verifiedAliases.archiveBinding.aliasDigest,
        manifestDigest: sha(item.aliasManifest) }, canaryEvidence: evidenceFor(canary, 'passed'),
      preservationEvidence: evidenceFor(preservation, 'passed'), selectorScopeEvidence: m4AuthorityEvidence(scope),
      authoritativePolicyBinding: { revision: scope.policyRevision, digest: scope.policyDigest }, routeConfiguration: routes, rollbackRevision }, 'm4_cutover_authorization_input_invalid');
    const payloadDigest = sha(body);
    return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: signatureFor(payloadDigest, loaded) } });
  } finally { loaded.key.fill(0); }
}

export function verifyM4CutoverAuthorization(value, authorizationKeyDocument) {
  let manifest; try { manifest = signed(structuredClone(value), 'm4_cutover_authorization_manifest_invalid'); }
  catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_')) throw error; fail('m4_cutover_authorization_manifest_invalid'); }
  const loaded = keyDocument(structuredClone(authorizationKeyDocument), 'm4_cutover_authorization_key_invalid');
  try {
    if (manifest.integrity.keyId !== loaded.keyId) fail('m4_cutover_authorization_key_id_mismatch');
    const { integrity, ...body } = manifest; const payloadDigest = sha(body);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_cutover_authorization_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_cutover_authorization_signature_mismatch');
    return structuredClone(manifest);
  } finally { loaded.key.fill(0); }
}
