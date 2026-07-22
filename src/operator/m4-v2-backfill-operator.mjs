import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { PostgresConversationArchive, SqliteConversationArchive } from '../conversation-archive-v1.mjs';
import { createFabricStoreFromEnv } from '../fabric-store.mjs';
import { ConversationEventPlaintextOutbox } from '../ingest/conversation-event-v3-outbox.mjs';
import { BackfillLease } from '../ingest/transcripts/backfill.mjs';
import { normalizeIngestKeyRing } from '../ingest/raw-event-contract.mjs';
import { M4ProgressStore } from '../migration/m4-progress-store.mjs';
import { createM4V2ArchiveSource } from '../migration/m4-v2-archive-source.mjs';
import { attestM4V2CatalogRevision, verifyM4V2CatalogRevisionAttestation } from '../migration/m4-v2-catalog-revision-attestation.mjs';
import { createM4V2ArchiveBackfillCompletion } from '../migration/m4-v2-backfill-completion.mjs';
import { planM4V2Backfill, runM4V2Backfill } from '../migration/m4-v2-backfill-runner.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { artifactPath, readPrivateJson, validateArtifactRoot, writePrivateArtifact } from './private-artifacts.mjs';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const B64 = /^[A-Za-z0-9+/]{43}=$/;
const ENV_KEYS = new Set(['AMF_DATA_PATH', 'AMF_CATALOG_KIND', 'AMF_CATALOG_PATH', 'AMF_CATALOG_DATABASE_URL', 'AMF_CATALOG_POOL_MAX', 'AMF_CATALOG_SSL_MODE', 'AMF_CATALOG_CONNECT_TIMEOUT_MS', 'AMF_CATALOG_QUERY_TIMEOUT_MS', 'AMF_CATALOG_STATEMENT_TIMEOUT_MS', 'AMF_RAW_ENCRYPTION_KEY', 'AMF_RAW_ENCRYPTION_KEY_ID', 'AMF_RAW_KEY_RING_PATH', 'AMF_RAW_KEY_RING_JSON', 'AMF_INGEST_KEY_RING_PATH', 'AMF_INGEST_KEY_RING_JSON', 'AMF_RAW_V2_CUTOVER']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function validated(code, callback) { try { return callback(); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function absolute(value, code) { if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) fail(code); return value; }
function noSymlinks(target, code) {
  const value = absolute(target, code); const parsed = path.parse(value); const parts = value.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  for (let index = 0; index < parts.length; index += 1) {
    current = path.join(current, parts[index]);
    let stat; try { stat = fs.lstatSync(current); } catch (error) { if (error?.code === 'ENOENT') return value; fail(code); }
    if (stat.isSymbolicLink()) fail(code);
  }
  return value;
}
function privateJson(filePath, code) {
  const file = noSymlinks(filePath, code); let descriptor;
  try {
    const uid = typeof process.geteuid === 'function' ? process.geteuid() : (typeof process.getuid === 'function' ? process.getuid() : null);
    const before = fs.lstatSync(file); if (!before.isFile() || before.isSymbolicLink() || (uid !== null && before.uid !== uid) || (before.mode & 0o077) !== 0 || before.size > 1024 * 1024) fail(code);
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor); if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) fail(code);
    const value = JSON.parse(fs.readFileSync(descriptor, 'utf8')); const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) fail(code);
    return { value, fileDigest: digest(value) };
  } catch { fail(code); } finally { if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {} }
}
function configShape(value) {
  const v1 = ['schema', 'gate', 'fabricConfigPath', 'deliveryKeyRingPath', 'archiveConfigPath', 'leasePath', 'outboxRoot', 'progressRoot'];
  const v2 = [...v1, 'artifactRoot', 'manifestId', 'revision', 'catalogAttestationKeyPath', 'completionKeyPath'];
  if (!((value.schema === 'amf.m4-v2-backfill-operator/v1' && exact(value, v1))
    || (value.schema === 'amf.m4-v2-backfill-operator/v2' && exact(value, v2)))
    || !exact(value.gate, ['pauseManifestPath', 'pauseKeyPath', 'rollbackManifestPath', 'rollbackKeyPath'])) fail('m4_operator_config_invalid');
  for (const key of ['fabricConfigPath', 'deliveryKeyRingPath', 'archiveConfigPath', 'leasePath', 'outboxRoot', 'progressRoot']) absolute(value[key], 'm4_operator_config_invalid');
  for (const key of Object.keys(value.gate)) absolute(value.gate[key], 'm4_operator_config_invalid');
  if (value.schema === 'amf.m4-v2-backfill-operator/v1') return { ...structuredClone(value), completion: null };
  for (const key of ['catalogAttestationKeyPath', 'completionKeyPath']) absolute(value[key], 'm4_operator_config_invalid');
  if (typeof value.manifestId !== 'string' || !/^[a-z][a-z0-9-]{2,79}$/.test(value.manifestId)
    || !Number.isSafeInteger(value.revision) || value.revision < 1) fail('m4_operator_config_invalid');
  validateArtifactRoot(value.artifactRoot, 'm4_operator_config_invalid');
  const result = structuredClone(value);
  result.completion = { artifactRoot: result.artifactRoot, manifestId: result.manifestId, revision: result.revision,
    catalogAttestationKeyPath: result.catalogAttestationKeyPath, completionKeyPath: result.completionKeyPath };
  return result;
}
function fabricShape(value) {
  if (!exact(value, ['schema', 'rootPath', 'env']) || value.schema !== 'amf.m4-v2-backfill-fabric/v1' || !plain(value.env)) fail('m4_operator_reference_invalid');
  absolute(value.rootPath, 'm4_operator_reference_invalid');
  if (Object.keys(value.env).some(key => !ENV_KEYS.has(key) || typeof value.env[key] !== 'string')) fail('m4_operator_reference_invalid');
  for (const key of ['AMF_DATA_PATH', 'AMF_CATALOG_PATH', 'AMF_RAW_KEY_RING_PATH', 'AMF_INGEST_KEY_RING_PATH']) if (value.env[key] !== undefined) absolute(value.env[key], 'm4_operator_reference_invalid');
  const env = value.env; if (!env.AMF_DATA_PATH || !['sqlite', 'postgres'].includes(env.AMF_CATALOG_KIND) || !['true', 'false'].includes(env.AMF_RAW_V2_CUTOVER)) fail('m4_operator_reference_invalid');
  const rawRing = env.AMF_RAW_KEY_RING_PATH !== undefined || env.AMF_RAW_KEY_RING_JSON !== undefined; if (rawRing === (env.AMF_RAW_ENCRYPTION_KEY !== undefined) || (rawRing && env.AMF_RAW_ENCRYPTION_KEY_ID !== undefined)) fail('m4_operator_reference_invalid');
  if (env.AMF_RAW_ENCRYPTION_KEY !== undefined && (!B64.test(env.AMF_RAW_ENCRYPTION_KEY) || typeof env.AMF_RAW_ENCRYPTION_KEY_ID !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(env.AMF_RAW_ENCRYPTION_KEY_ID))) fail('m4_operator_reference_invalid');
  if (env.AMF_CATALOG_KIND === 'sqlite' && (!env.AMF_CATALOG_PATH || env.AMF_CATALOG_DATABASE_URL !== undefined)) fail('m4_operator_reference_invalid');
  if (env.AMF_CATALOG_KIND === 'postgres' && (env.AMF_CATALOG_PATH !== undefined || !/^postgres(?:ql)?:\/\/[^\s\x00-\x1f]{1,4096}$/.test(env.AMF_CATALOG_DATABASE_URL || ''))) fail('m4_operator_reference_invalid');
  for (const key of ['AMF_CATALOG_POOL_MAX', 'AMF_CATALOG_CONNECT_TIMEOUT_MS', 'AMF_CATALOG_QUERY_TIMEOUT_MS', 'AMF_CATALOG_STATEMENT_TIMEOUT_MS']) if (env[key] !== undefined) { const number = Number(env[key]); const minimum = key === 'AMF_CATALOG_POOL_MAX' ? 1 : 100; if (!Number.isInteger(number) || number < minimum || number > (key === 'AMF_CATALOG_POOL_MAX' ? 100 : 120000)) fail('m4_operator_reference_invalid'); }
  if (env.AMF_CATALOG_SSL_MODE !== undefined && !['disable', 'require', 'verify-full'].includes(env.AMF_CATALOG_SSL_MODE)) fail('m4_operator_reference_invalid');
  if (env.AMF_CATALOG_KIND === 'sqlite' && ['AMF_CATALOG_POOL_MAX', 'AMF_CATALOG_SSL_MODE'].some(key => env[key] !== undefined)) fail('m4_operator_reference_invalid');
  return structuredClone(value);
}
function deliveryShape(value) {
  if (!exact(value, ['schema', 'currentKeyId', 'keys', 'cursorKey', 'retentionDays']) || value.schema !== 'amf.m4-v2-delivery-key-ring/v1' || typeof value.currentKeyId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.currentKeyId) || !plain(value.keys) || !B64.test(value.cursorKey) || !Number.isSafeInteger(value.retentionDays) || value.retentionDays < 1 || value.retentionDays > 3650) fail('m4_operator_reference_invalid');
  if (Object.keys(value.keys).length < 1 || Object.keys(value.keys).length > 32 || !Object.hasOwn(value.keys, value.currentKeyId) || Object.entries(value.keys).some(([id, key]) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id) || !B64.test(key))) fail('m4_operator_reference_invalid');
  return structuredClone(value);
}
function archiveShape(value) {
  if (!plain(value) || value.schema !== 'amf.m4-v2-backfill-archive/v1') fail('m4_operator_reference_invalid');
  if (exact(value, ['schema', 'kind', 'filename']) && value.kind === 'sqlite') { absolute(value.filename, 'm4_operator_reference_invalid'); return structuredClone(value); }
  if (exact(value, ['schema', 'kind', 'connectionString']) && value.kind === 'postgres' && /^postgres(?:ql)?:\/\/[^\s\x00-\x1f]{1,4096}$/.test(value.connectionString)) return structuredClone(value);
  fail('m4_operator_reference_invalid');
}
function normalizeFabricFiles(fabric, references) {
  const env = { ...fabric.env }; const files = [];
  for (const [pathKey, jsonKey] of [['AMF_RAW_KEY_RING_PATH', 'AMF_RAW_KEY_RING_JSON'], ['AMF_INGEST_KEY_RING_PATH', 'AMF_INGEST_KEY_RING_JSON']]) {
    if (env[pathKey] !== undefined && env[jsonKey] !== undefined) fail('m4_operator_reference_invalid');
    if (env[pathKey] !== undefined) {
      absolute(env[pathKey], 'm4_operator_reference_invalid'); const loaded = privateJson(env[pathKey], 'm4_operator_reference_invalid'); references.push([pathKey, loaded.fileDigest]); files.push(env[pathKey]);
      env[jsonKey] = canonicalJson(loaded.value); delete env[pathKey];
    }
  }
  if (!env.AMF_INGEST_KEY_RING_JSON) fail('m4_operator_reference_invalid');
  let ingest; try { ingest = JSON.parse(env.AMF_INGEST_KEY_RING_JSON); normalizeIngestKeyRing(ingest); } catch { fail('m4_operator_reference_invalid'); }
  if (env.AMF_RAW_KEY_RING_JSON !== undefined) {
    try { const raw = JSON.parse(env.AMF_RAW_KEY_RING_JSON); const entries = Object.entries(raw.keys || {}); if (!exact(raw, ['currentKeyId', 'keys']) || typeof raw.currentKeyId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(raw.currentKeyId) || entries.length < 1 || entries.length > 32 || !Object.hasOwn(raw.keys, raw.currentKeyId) || entries.some(([id, key]) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id) || !B64.test(key))) throw new Error(); } catch { fail('m4_operator_reference_invalid'); }
  }
  return { rootPath: fabric.rootPath, env, ingestKeys: structuredClone(ingest), files };
}
function gateInput(values) {
  try {
    const pauseManifest = values.pauseManifest;
    const runId = `m4-${crypto.createHash('sha256').update(canonicalJson(['amf.m4-v2-backfill-operator/run-id/v1', pauseManifest.manifestId, pauseManifest.revision]), 'utf8').digest('hex')}`;
    return { runId, phase: 'v2-archive', pauseManifest, pauseKeyDocument: values.pauseKeyDocument, rollbackManifest: values.rollbackManifest, rollbackKeyDocument: values.rollbackKeyDocument };
  } catch { fail('m4_operator_gate_invalid'); }
}
function safeRunId(gate) { return gate.runId; }
function expiry(days) { return event => { const at = Date.parse(event.sourceOccurredAt); if (!Number.isFinite(at)) throw new Error(); return new Date(at + days * 86400000).toISOString(); }; }
function deliveryAdapter(ring, { nonceFactory = () => crypto.randomBytes(18).toString('base64url'), deliveryClock = () => new Date() } = {}) {
  const keys = new Map(Object.entries(ring.keys).map(([id, key]) => [id, Buffer.from(key, 'base64')]));
  const resolveIntegrityKey = keyId => keys.get(keyId) || null;
  return { resolveIntegrityKey, resolveExpiresAt: expiry(ring.retentionDays), integrityFor: async () => ({ keyId: ring.currentKeyId, key: keys.get(ring.currentKeyId), sentAt: deliveryClock().toISOString(), nonce: nonceFactory() }), cursorKey: Buffer.from(ring.cursorKey, 'base64') };
}
function revalidate(prepared) {
  for (const file of prepared.files) noSymlinks(file, 'm4_operator_resource_unsafe');
  const fabricTargets = [prepared.fabric.rootPath, prepared.fabric.env.AMF_DATA_PATH];
  if (prepared.fabric.env.AMF_CATALOG_KIND === 'sqlite') fabricTargets.push(prepared.fabric.env.AMF_CATALOG_PATH);
  for (const target of [prepared.config.leasePath, prepared.config.outboxRoot, prepared.config.progressRoot, ...fabricTargets]) noSymlinks(target, 'm4_operator_resource_unsafe');
  if (prepared.archive.kind === 'sqlite') noSymlinks(prepared.archive.filename, 'm4_operator_resource_unsafe');
}

function independentCompletionKeys(catalogDocument, completionDocument) {
  let left; let right; let leftBlock; let rightBlock;
  try {
    if (!plain(catalogDocument) || !plain(completionDocument) || typeof catalogDocument.keyId !== 'string'
      || typeof completionDocument.keyId !== 'string' || typeof catalogDocument.key !== 'string' || typeof completionDocument.key !== 'string') fail('m4_operator_reference_invalid');
    left = Buffer.from(catalogDocument.key, 'base64'); right = Buffer.from(completionDocument.key, 'base64');
    if (left.length < 32 || left.length > 64 || right.length < 32 || right.length > 64
      || left.toString('base64') !== catalogDocument.key || right.toString('base64') !== completionDocument.key
      || catalogDocument.keyId === completionDocument.keyId) fail('m4_operator_reference_invalid');
    leftBlock = Buffer.alloc(64); rightBlock = Buffer.alloc(64); left.copy(leftBlock); right.copy(rightBlock);
    if (crypto.timingSafeEqual(leftBlock, rightBlock)) fail('m4_operator_reference_invalid');
  } catch (error) { if (error?.code === 'm4_operator_reference_invalid') throw error; fail('m4_operator_reference_invalid'); }
  finally { left?.fill(0); right?.fill(0); leftBlock?.fill(0); rightBlock?.fill(0); }
}

async function preparedInput({ configPath, maxEvents }) {
  if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > 1000) fail('m4_operator_plan_input_invalid');
  const configLoaded = privateJson(configPath, 'm4_operator_config_invalid'); const config = configShape(configLoaded.value); const references = [['config', configLoaded.fileDigest]];
  const fabricLoaded = privateJson(config.fabricConfigPath, 'm4_operator_reference_invalid'); const fabric = normalizeFabricFiles(fabricShape(fabricLoaded.value), references); references.push(['fabric', fabricLoaded.fileDigest]);
  const deliveryLoaded = privateJson(config.deliveryKeyRingPath, 'm4_operator_reference_invalid'); const delivery = deliveryShape(deliveryLoaded.value); references.push(['delivery', deliveryLoaded.fileDigest]);
  const archiveLoaded = privateJson(config.archiveConfigPath, 'm4_operator_reference_invalid'); const archive = archiveShape(archiveLoaded.value); references.push(['archive', archiveLoaded.fileDigest]);
  const gateFiles = { pauseManifest: privateJson(config.gate.pauseManifestPath, 'm4_operator_reference_invalid'), pauseKeyDocument: privateJson(config.gate.pauseKeyPath, 'm4_operator_reference_invalid'), rollbackManifest: privateJson(config.gate.rollbackManifestPath, 'm4_operator_reference_invalid'), rollbackKeyDocument: privateJson(config.gate.rollbackKeyPath, 'm4_operator_reference_invalid') };
  for (const [role, loaded] of Object.entries(gateFiles)) references.push([role, loaded.fileDigest]);
  let completion = null;
  if (config.completion !== null) {
    const catalogKey = privateJson(config.completion.catalogAttestationKeyPath, 'm4_operator_reference_invalid');
    const completionKey = privateJson(config.completion.completionKeyPath, 'm4_operator_reference_invalid');
    independentCompletionKeys(catalogKey.value, completionKey.value);
    completion = { ...config.completion, catalogAttestationKeyDocument: catalogKey.value, completionKeyDocument: completionKey.value };
    references.push(['catalog-attestation-key', catalogKey.fileDigest], ['completion-key', completionKey.fileDigest]);
  }
  references.sort((left, right) => left[0].localeCompare(right[0]) || left[1].localeCompare(right[1]));
  const gate = gateInput(Object.fromEntries(Object.entries(gateFiles).map(([role, loaded]) => [role, loaded.value]))); const runnerPlan = await planM4V2Backfill({ gateInput: gate, maxEvents });
  const selection = { archive: archive.kind === 'sqlite' ? { kind: archive.kind, filename: archive.filename } : { kind: archive.kind, connectionString: archive.connectionString }, fabric: { rootPath: fabric.rootPath, dataPath: fabric.env.AMF_DATA_PATH, kind: fabric.env.AMF_CATALOG_KIND, catalogTarget: fabric.env.AMF_CATALOG_KIND === 'sqlite' ? fabric.env.AMF_CATALOG_PATH : fabric.env.AMF_CATALOG_DATABASE_URL }, leasePath: config.leasePath, outboxRoot: config.outboxRoot, progressRoot: config.progressRoot };
  const confirmationDigest = digest({ schema: 'amf.m4-v2-backfill-operator-confirmation/v1', runnerPlan, configDigest: configLoaded.fileDigest, referenceDigests: references, resourceSelectionDigest: digest(selection), runIdDerivation: { schema: 'amf.m4-v2-backfill-operator/run-id/v1', manifestId: digest({ manifestId: gate.pauseManifest.manifestId }), revision: gate.pauseManifest.revision } });
  return { config, fabric, delivery, archive, gate, runnerPlan, completion, confirmationDigest, files: [configPath, config.fabricConfigPath, config.deliveryKeyRingPath, config.archiveConfigPath, ...Object.values(config.gate), ...fabric.files, ...(completion === null ? [] : [completion.catalogAttestationKeyPath, completion.completionKeyPath])] };
}

async function catalogAttestation(prepared, deps) {
  let store;
  try {
    store = deps.createFabricStoreFromEnv({ rootPath: prepared.fabric.rootPath, env: prepared.fabric.env });
    return await attestM4V2CatalogRevision({ catalog: store.catalog,
      keyDocument: prepared.completion.catalogAttestationKeyDocument, pageLimit: 50 });
  } catch (error) { if (error?.code?.startsWith?.('m4_v2_catalog_attestation_')) throw error; fail('m4_operator_catalog_attestation_failed'); }
  finally { try { await store?.close?.(); } catch { fail('m4_operator_catalog_attestation_failed'); } }
}

function baselineArtifactId(manifestId) {
  return `v2catalog-${crypto.createHash('sha256').update(canonicalJson(['amf.m4-v2-backfill/catalog-baseline/v1', manifestId]), 'utf8').digest('hex')}`;
}

function catalogDigest(value) { return digest(value); }

async function catalogBaseline(prepared, deps) {
  const { artifactRoot, manifestId, revision, catalogAttestationKeyDocument } = prepared.completion;
  const target = artifactPath(artifactRoot, 'v2-backfill', baselineArtifactId(manifestId), revision);
  let existing = null;
  try { existing = readPrivateJson(target, 'm4_operator_catalog_baseline_missing'); }
  catch (error) { if (error?.code !== 'm4_operator_catalog_baseline_missing') fail('m4_operator_catalog_baseline_invalid'); }
  if (existing === null) {
    const candidate = await catalogAttestation(prepared, deps);
    try { writePrivateArtifact(artifactRoot, 'v2-backfill', baselineArtifactId(manifestId), revision, candidate); }
    catch (error) { if (error?.code !== 'private_artifact_target_exists') throw error; }
    try { existing = readPrivateJson(target, 'm4_operator_catalog_baseline_invalid'); }
    catch { fail('m4_operator_catalog_baseline_invalid'); }
  }
  try { return verifyM4V2CatalogRevisionAttestation(existing, catalogAttestationKeyDocument); }
  catch { fail('m4_operator_catalog_baseline_invalid'); }
}

function requireCatalogBaseline(baseline, current) {
  if (catalogDigest(baseline) !== catalogDigest(current)) fail('m4_operator_catalog_baseline_mismatch');
}

function operatorResult(result, completion = null) {
  if (completion === null) return { schema: 'amf.m4-v2-backfill-operator-result/v1', operation: 'run', runId: result.runId, phase: result.phase, processed: result.processed, duplicates: result.duplicates, complete: result.complete };
  return { schema: 'amf.m4-v2-backfill-operator-result/v2', operation: 'run', runId: result.runId, phase: result.phase, processed: result.processed, duplicates: result.duplicates, complete: result.complete,
    completion: result.complete ? { state: 'published', digest: `sha256:${crypto.createHash('sha256').update(canonicalJson(completion), 'utf8').digest('hex')}` } : { state: 'pending', digest: null } };
}

export async function planM4V2BackfillOperator(input = {}) {
  const request = validated('m4_operator_plan_input_invalid', () => { if (!exact(input, ['configPath', 'maxEvents'])) fail('m4_operator_plan_input_invalid'); const snapshot = { configPath: input.configPath, maxEvents: input.maxEvents }; if (!Number.isSafeInteger(snapshot.maxEvents) || snapshot.maxEvents < 1 || snapshot.maxEvents > 1000) fail('m4_operator_plan_input_invalid'); return snapshot; });
  let prepared; try { prepared = await preparedInput(request); } catch (error) { if (error?.code?.startsWith?.('m4_operator_')) throw error; fail('m4_operator_prepare_failed'); }
  return { schema: 'amf.m4-v2-backfill-operator-plan/v1', operation: 'plan', runId: safeRunId(prepared.gate), phase: 'v2-archive', confirmationDigest: prepared.confirmationDigest };
}

export async function runM4V2BackfillOperator(input = {}, options = {}) {
  const request = validated('m4_operator_run_input_invalid', () => { if (!exact(input, ['configPath', 'maxEvents', 'confirmedPlanDigest'])) fail('m4_operator_run_input_invalid'); const snapshot = { configPath: input.configPath, maxEvents: input.maxEvents, confirmedPlanDigest: input.confirmedPlanDigest }; if (!Number.isSafeInteger(snapshot.maxEvents) || snapshot.maxEvents < 1 || snapshot.maxEvents > 1000 || typeof snapshot.confirmedPlanDigest !== 'string' || !DIGEST.test(snapshot.confirmedPlanDigest)) fail('m4_operator_run_input_invalid'); return snapshot; });
  let prepared; try { prepared = await preparedInput(request); } catch (error) { if (error?.code?.startsWith?.('m4_operator_')) throw error; fail('m4_operator_prepare_failed'); }
  if (prepared.confirmationDigest !== request.confirmedPlanDigest) fail('m4_operator_confirmation_invalid');
  revalidate(prepared);
  const deps = options.dependencies || { createFabricStoreFromEnv, BackfillLease, ConversationEventPlaintextOutbox, SqliteConversationArchive, PostgresConversationArchive, M4ProgressStore };
  const baseline = prepared.completion === null ? null : await catalogBaseline(prepared, deps);
  const beforeCatalog = prepared.completion === null ? null : await catalogAttestation(prepared, deps);
  if (baseline !== null) requireCatalogBaseline(baseline, beforeCatalog);
  const delivery = deliveryAdapter(prepared.delivery, options);
  const deliveryClock = options.deliveryClock || (() => new Date());
  const factories = {
    lease: async () => { revalidate(prepared); const lease = new deps.BackfillLease({ leasePath: prepared.config.leasePath }); await lease.acquire(); let held = true; const release = async () => { if (!held) return; await lease.release(); held = false; }; return { async acquire() { if (!held) throw new Error('m4_operator_lease_not_held'); }, async heartbeat() { if (!held) throw new Error('m4_operator_lease_not_held'); return lease.heartbeat(); }, release, close: release }; },
    source: async ({ sourceCheckpoint }) => { revalidate(prepared); const store = deps.createFabricStoreFromEnv({ rootPath: prepared.fabric.rootPath, env: prepared.fabric.env }); try { const source = createM4V2ArchiveSource({ catalog: store.catalog, rawStore: store.rawStore, ingestKeys: prepared.fabric.ingestKeys, startCheckpoint: sourceCheckpoint,
      verifyCatalogBinding: async value => ({ owner: store.rawStore.opaqueTags('raw-owner', value.actorId).includes(value.ownerTag), source: store.rawStore.opaqueTags('raw-source', value.sourceInstanceId).includes(value.sourceTag) }),
      auditDecrypt: async value => { await store.audit({ actor: 'm4-backfill-operator', action: 'raw_redacted_decrypt_intent', outcome: 'authorized', targetId: value.eventId, details: { transport: 'm4-v2-backfill' } }); return { recorded: true, eventId: value.eventId, contentId: value.contentId }; }, integrityFor: delivery.integrityFor });
      return { open: source.open.bind(source), close: () => store.close() }; } catch (error) { try { await store.close?.(); } catch {} throw error; } },
    outbox: async () => { revalidate(prepared); return new deps.ConversationEventPlaintextOutbox({ rootPath: prepared.config.outboxRoot, resolveIntegrityKey: delivery.resolveIntegrityKey, clock: () => deliveryClock().getTime(), ...(options.nonceFactory ? { nonceFactory: options.nonceFactory } : {}) }); },
    archive: async () => { revalidate(prepared); const archive = prepared.archive.kind === 'sqlite' ? new deps.SqliteConversationArchive({ filename: prepared.archive.filename, resolveIntegrityKey: delivery.resolveIntegrityKey, resolveExpiresAt: delivery.resolveExpiresAt, cursorKey: delivery.cursorKey }) : new deps.PostgresConversationArchive({ connectionString: prepared.archive.connectionString, resolveIntegrityKey: delivery.resolveIntegrityKey, resolveExpiresAt: delivery.resolveExpiresAt, cursorKey: delivery.cursorKey }); return { archive, resolveIntegrityKey: delivery.resolveIntegrityKey }; },
    checkpointStore: async ({ runId, phase, planDigest }) => { revalidate(prepared); return new deps.M4ProgressStore({ rootPath: prepared.config.progressRoot, runId, phase, planDigest }); },
  };
  const result = await runM4V2Backfill({ gateInput: prepared.gate, maxEvents: request.maxEvents, confirmedPlanDigest: prepared.runnerPlan.planDigest, factories });
  if (prepared.completion === null) return operatorResult(result, null);
  const afterCatalog = await catalogAttestation(prepared, deps);
  requireCatalogBaseline(baseline, afterCatalog);
  if (!result.complete) return operatorResult(result, prepared.completion);
  let completion;
  try {
    completion = await createM4V2ArchiveBackfillCompletion({ manifestId: prepared.completion.manifestId, revision: prepared.completion.revision,
      gateInput: prepared.gate, runnerPlan: prepared.runnerPlan, result, preCatalogAttestation: baseline,
      postCatalogAttestation: afterCatalog, catalogAttestationKeyDocument: prepared.completion.catalogAttestationKeyDocument,
      completionKeyDocument: prepared.completion.completionKeyDocument });
    writePrivateArtifact(prepared.completion.artifactRoot, 'v2-backfill', prepared.completion.manifestId, prepared.completion.revision, completion);
  } catch (error) { if (error?.code === 'private_artifact_target_exists') fail('m4_operator_completion_artifact_exists'); if (error?.code?.startsWith?.('m4_')) throw error; fail('m4_operator_completion_failed'); }
  return operatorResult(result, completion);
}
