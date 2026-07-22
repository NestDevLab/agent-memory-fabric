import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { m4AuthorityEvidence, timestampWithin, verifyM4CatalogReferenceSnapshot } from './m4-authority-snapshots.mjs';
import { verifyM4CutoverAuthorization } from './m4-cutover-authorization.mjs';
import { verifyM4PreservationProof } from './m4-preservation-proof.mjs';

export const M4_CLEANUP_INVENTORY_SCHEMA = 'amf.m4-cleanup-inventory/v1';

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-cleanup-inventory/v1/integrity';
const MIGRATION_DOMAIN = 'amf.migration-manifest/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SOURCE = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const TARGET_TYPES = new Set(['transcript-row', 'transcript-blob']);
const MAX_TARGETS = 100_000;

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
function evidence(value, code) {
  const item = snapshot(value, ['manifestId', 'digest', 'signature'], code);
  if (typeof item.manifestId !== 'string' || !ID.test(item.manifestId) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || typeof item.signature !== 'string' || !SIGNATURE.test(item.signature)) fail(code);
  return item;
}
function evidenceFor(manifest) { return { manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest, signature: manifest.integrity.signature }; }
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
function migrationSignatureFor(payloadDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key).update(canonicalJson([MIGRATION_DOMAIN, payloadDigest, loadedKey.keyId]), 'utf8').digest('base64url');
}
function target(value, code) {
  const item = snapshot(value, ['id', 'digest', 'objectType', 'sourceInstanceId', 'contentClass', 'referenceCount'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)
    || !TARGET_TYPES.has(item.objectType) || typeof item.sourceInstanceId !== 'string' || !SOURCE.test(item.sourceInstanceId)
    || item.contentClass !== 'conversation' || item.referenceCount !== 0) fail(code);
  return item;
}
function targets(value, code) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_TARGETS) fail(code);
  const result = value.map(item => target(item, code)); const digests = new Set();
  for (let index = 0; index < result.length; index += 1) {
    if ((index > 0 && result[index - 1].id >= result[index].id) || digests.has(result[index].digest)) fail(code);
    digests.add(result[index].digest);
  }
  return result;
}
function payload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'inventoriedAt', 'cutoverEvidence', 'preservationEvidence', 'catalogSnapshotEvidence', 'catalogRevision', 'scanDigest', 'scannedObjectCount', 'scannedReferenceCount', 'targets'], code);
  if (item.schema !== M4_CLEANUP_INVENTORY_SCHEMA || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1 || item.state !== 'ready') fail(code);
  try { if (!timestampWithin(item.inventoriedAt, item.inventoriedAt, item.inventoriedAt)) fail(code); } catch { fail(code); }
  const selectedTargets = targets(item.targets, code);
  if (!DIGEST.test(item.scanDigest) || !Number.isSafeInteger(item.scannedObjectCount) || item.scannedObjectCount < selectedTargets.length
    || !Number.isSafeInteger(item.scannedReferenceCount) || item.scannedReferenceCount < 0) fail(code);
  return { schema: M4_CLEANUP_INVENTORY_SCHEMA, manifestId: item.manifestId, revision: item.revision, state: 'ready', inventoriedAt: item.inventoriedAt,
    cutoverEvidence: evidence(item.cutoverEvidence, code), preservationEvidence: evidence(item.preservationEvidence, code),
    catalogSnapshotEvidence: evidence(item.catalogSnapshotEvidence, code), catalogRevision: checkpoint(item.catalogRevision, code),
    scanDigest: item.scanDigest, scannedObjectCount: item.scannedObjectCount, scannedReferenceCount: item.scannedReferenceCount, targets: selectedTargets };
}
function signed(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'inventoriedAt', 'cutoverEvidence', 'preservationEvidence', 'catalogSnapshotEvidence', 'catalogRevision', 'scanDigest', 'scannedObjectCount', 'scannedReferenceCount', 'targets', 'integrity'], code);
  const body = payload({ schema: item.schema, manifestId: item.manifestId, revision: item.revision, state: item.state,
    inventoriedAt: item.inventoriedAt, cutoverEvidence: item.cutoverEvidence, preservationEvidence: item.preservationEvidence,
    catalogSnapshotEvidence: item.catalogSnapshotEvidence, catalogRevision: item.catalogRevision, scanDigest: item.scanDigest,
    scannedObjectCount: item.scannedObjectCount, scannedReferenceCount: item.scannedReferenceCount, targets: item.targets }, code);
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (integrity.algorithm !== 'hmac-sha256' || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId)
    || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest)
    || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) fail(code);
  return { ...body, integrity };
}
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }

export function createM4CleanupInventory(value, authorities) {
  let input; try { input = structuredClone(value); } catch { fail('m4_cleanup_inventory_input_invalid'); }
  const item = snapshot(input, ['manifestId', 'revision', 'inventoriedAt', 'cutoverManifest', 'cutoverKeyDocument', 'preservationManifest', 'preservationKeyDocument', 'catalogSnapshotManifest', 'targets', 'cleanupKeyDocument'], 'm4_cleanup_inventory_input_invalid');
  let trusted;
  try { trusted = snapshot(structuredClone(authorities), ['catalogSnapshotKeyDocument'], 'm4_cleanup_inventory_authority_invalid'); }
  catch { fail('m4_cleanup_inventory_authority_invalid'); }
  requireIndependentKeys(trusted.catalogSnapshotKeyDocument, [item.cutoverKeyDocument, item.preservationKeyDocument, item.cleanupKeyDocument], 'm4_cleanup_inventory_authority_invalid');
  let cutover; let preservation; let catalogSnapshot;
  try { cutover = verifyM4CutoverAuthorization(item.cutoverManifest, item.cutoverKeyDocument); preservation = verifyM4PreservationProof(item.preservationManifest, item.preservationKeyDocument);
    catalogSnapshot = verifyM4CatalogReferenceSnapshot(item.catalogSnapshotManifest, trusted.catalogSnapshotKeyDocument); }
  catch { fail('m4_cleanup_inventory_evidence_invalid'); }
  if (!same(cutover.preservationEvidence, { ...evidenceFor(preservation), state: 'passed' })) fail('m4_cleanup_inventory_evidence_mismatch');
  const selectedTargets = targets(item.targets, 'm4_cleanup_inventory_input_invalid');
  if (!same(selectedTargets, catalogSnapshot.eligibleTargets)) fail('m4_cleanup_inventory_catalog_mismatch');
  if (!timestampWithin(item.inventoriedAt, catalogSnapshot.observedAt, catalogSnapshot.validThrough)) fail('m4_cleanup_inventory_catalog_stale');
  const selectors = new Map(preservation.dispositions.map(disposition => [disposition.sourceInstanceId, disposition]));
  const counts = new Map();
  for (const selected of selectedTargets) {
    if (!selectors.has(selected.sourceInstanceId)) fail('m4_cleanup_inventory_selector_invalid');
    counts.set(selected.sourceInstanceId, (counts.get(selected.sourceInstanceId) || 0) + 1);
  }
  for (const [sourceInstanceId, disposition] of selectors) {
    if ((counts.get(sourceInstanceId) || 0) !== disposition.cleanupTargetCount) fail('m4_cleanup_inventory_count_mismatch');
  }
  const protectedBindings = [
    ...preservation.dispositions.map(disposition => disposition.binding),
    ...preservation.preservedSharedData.map(entry => entry.binding), preservation.restoreTest.evidence,
  ];
  if (selectedTargets.some(selected => protectedBindings.some(binding => binding.id === selected.id || binding.digest === selected.digest))) {
    fail('m4_cleanup_inventory_preserved_overlap');
  }
  if (selectedTargets.some(selected => [catalogSnapshot.catalogRevision, m4AuthorityEvidence(catalogSnapshot)].some(binding => binding.manifestId === selected.id || binding.id === selected.id || binding.digest === selected.digest))) {
    fail('m4_cleanup_inventory_catalog_overlap');
  }
  const loaded = keyDocument(item.cleanupKeyDocument, 'm4_cleanup_inventory_key_invalid');
  try {
    const body = payload({ schema: M4_CLEANUP_INVENTORY_SCHEMA, manifestId: item.manifestId, revision: item.revision, state: 'ready', inventoriedAt: item.inventoriedAt,
      cutoverEvidence: evidenceFor(cutover), preservationEvidence: evidenceFor(preservation), catalogSnapshotEvidence: m4AuthorityEvidence(catalogSnapshot),
      catalogRevision: catalogSnapshot.catalogRevision, scanDigest: catalogSnapshot.scanDigest, scannedObjectCount: catalogSnapshot.scannedObjectCount,
      scannedReferenceCount: catalogSnapshot.scannedReferenceCount, targets: selectedTargets }, 'm4_cleanup_inventory_input_invalid');
    const payloadDigest = sha(body);
    return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: signatureFor(payloadDigest, loaded) } });
  } finally { loaded.key.fill(0); }
}

export function verifyM4CleanupInventory(value, cleanupKeyDocument) {
  let manifest; try { manifest = signed(structuredClone(value), 'm4_cleanup_inventory_manifest_invalid'); }
  catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_')) throw error; fail('m4_cleanup_inventory_manifest_invalid'); }
  const loaded = keyDocument(structuredClone(cleanupKeyDocument), 'm4_cleanup_inventory_key_invalid');
  try {
    if (manifest.integrity.keyId !== loaded.keyId) fail('m4_cleanup_inventory_key_id_mismatch');
    const { integrity, ...body } = manifest; const payloadDigest = sha(body);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_cleanup_inventory_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_cleanup_inventory_signature_mismatch');
    return structuredClone(manifest);
  } finally { loaded.key.fill(0); }
}

export function m4CleanupManifestEvidence(inventory, cleanupKeyDocument, cutoverAuthorization, cutoverKeyDocument) {
  let verifiedInventory; let verifiedCutover;
  try { verifiedInventory = verifyM4CleanupInventory(inventory, cleanupKeyDocument); verifiedCutover = verifyM4CutoverAuthorization(cutoverAuthorization, cutoverKeyDocument); }
  catch { fail('m4_cleanup_inventory_projection_invalid'); }
  if (!same(verifiedInventory.cutoverEvidence, evidenceFor(verifiedCutover))) fail('m4_cleanup_inventory_evidence_mismatch');
  return {
    reconciliationEvidence: { ...verifiedCutover.reconciliationEvidence, state: 'complete' },
    cutoverCanary: { id: verifiedCutover.canaryEvidence.manifestId, digest: verifiedCutover.canaryEvidence.digest, state: 'passed' },
    catalogUnreferencedProof: evidenceFor(verifiedInventory), recoveryCopy: checkpoint(verifiedCutover.legacyRecoveryCopy, 'm4_cleanup_inventory_cutover_invalid'),
    restoreTest: 'passed', targets: verifiedInventory.targets.map(item => ({ id: item.id, digest: item.digest })),
  };
}

function cleanupBody(value, code) {
  const item = snapshot(value, ['state', 'reconciliationEvidence', 'cutoverCanary', 'catalogUnreferencedProof', 'recoveryCopy', 'restoreTest', 'targets'], code);
  const reconciliationEvidence = snapshot(item.reconciliationEvidence, ['manifestId', 'digest', 'signature', 'state'], code);
  const cutoverCanary = snapshot(item.cutoverCanary, ['id', 'digest', 'state'], code);
  if (item.state !== 'ready' || reconciliationEvidence.state !== 'complete' || cutoverCanary.state !== 'passed'
    || item.restoreTest !== 'passed' || !ID.test(cutoverCanary.id) || !DIGEST.test(cutoverCanary.digest)
    || !Array.isArray(item.targets) || item.targets.length < 1 || item.targets.length > MAX_TARGETS) fail(code);
  const targetCheckpoints = item.targets.map(targetValue => checkpoint(targetValue, code));
  for (let index = 1; index < targetCheckpoints.length; index += 1) if (targetCheckpoints[index - 1].id >= targetCheckpoints[index].id) fail(code);
  return { state: 'ready', reconciliationEvidence: { ...evidence({ manifestId: reconciliationEvidence.manifestId,
    digest: reconciliationEvidence.digest, signature: reconciliationEvidence.signature }, code), state: 'complete' },
    cutoverCanary, catalogUnreferencedProof: evidence(item.catalogUnreferencedProof, code), recoveryCopy: checkpoint(item.recoveryCopy, code),
    restoreTest: 'passed', targets: targetCheckpoints };
}
function cleanupManifestPayload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'phase', 'revision', 'cleanup'], code);
  if (item.schema !== 'amf.migration-manifest/v1' || item.phase !== 'cleanup' || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1) fail(code);
  return { schema: 'amf.migration-manifest/v1', manifestId: item.manifestId, phase: 'cleanup', revision: item.revision, cleanup: cleanupBody(item.cleanup, code) };
}

export function createM4CleanupManifest(value) {
  let input; try { input = structuredClone(value); } catch { fail('m4_cleanup_manifest_input_invalid'); }
  const item = snapshot(input, ['manifestId', 'revision', 'inventory', 'inventoryKeyDocument', 'cutoverAuthorization', 'cutoverKeyDocument', 'migrationKeyDocument'], 'm4_cleanup_manifest_input_invalid');
  const cleanup = m4CleanupManifestEvidence(item.inventory, item.inventoryKeyDocument, item.cutoverAuthorization, item.cutoverKeyDocument);
  const loaded = keyDocument(item.migrationKeyDocument, 'm4_cleanup_manifest_key_invalid');
  try {
    const body = cleanupManifestPayload({ schema: 'amf.migration-manifest/v1', manifestId: item.manifestId, phase: 'cleanup', revision: item.revision,
      cleanup: { state: 'ready', ...cleanup } }, 'm4_cleanup_manifest_input_invalid');
    const payloadDigest = sha(body);
    return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: migrationSignatureFor(payloadDigest, loaded) } });
  } finally { loaded.key.fill(0); }
}

export function verifyM4CleanupManifest(value, migrationKeyDocument) {
  let item;
  try { item = snapshot(structuredClone(value), ['schema', 'manifestId', 'phase', 'revision', 'cleanup', 'integrity'], 'm4_cleanup_manifest_invalid'); }
  catch (error) { if (typeof error?.code === 'string' && error.code.startsWith('m4_')) throw error; fail('m4_cleanup_manifest_invalid'); }
  const body = cleanupManifestPayload({ schema: item.schema, manifestId: item.manifestId, phase: item.phase, revision: item.revision, cleanup: item.cleanup }, 'm4_cleanup_manifest_invalid');
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], 'm4_cleanup_manifest_invalid');
  if (integrity.algorithm !== 'hmac-sha256' || !ID.test(integrity.keyId) || !DIGEST.test(integrity.payloadDigest) || !SIGNATURE.test(integrity.signature)) fail('m4_cleanup_manifest_invalid');
  const loaded = keyDocument(structuredClone(migrationKeyDocument), 'm4_cleanup_manifest_key_invalid');
  try {
    if (integrity.keyId !== loaded.keyId) fail('m4_cleanup_manifest_key_id_mismatch');
    const payloadDigest = sha(body); if (payloadDigest !== integrity.payloadDigest) fail('m4_cleanup_manifest_digest_mismatch');
    const expected = Buffer.from(migrationSignatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_cleanup_manifest_signature_mismatch');
    return structuredClone({ ...body, integrity });
  } finally { loaded.key.fill(0); }
}
