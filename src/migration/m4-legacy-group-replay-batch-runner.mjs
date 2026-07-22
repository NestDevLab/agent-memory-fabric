import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4BackfillGate } from './m4-backfill-gate.mjs';
import {
  M4_PRESERVED_GROUP_MAX_GROUPS,
  M4_PRESERVED_GROUP_MAX_OBSERVATIONS,
  M4_PRESERVED_GROUP_MAX_OUTPUT_EVENTS,
  runM4PreservedGroupReplay,
} from './m4-preserved-group-replay.mjs';
import { prepareM4PreservedUnifiedIndex } from './m4-preserved-unified-index.mjs';
import { prepareM4UnifiedLogicalGroupSource } from './m4-unified-logical-group-source.mjs';
import { prepareM4V2UnifiedIndex } from './m4-v2-unified-index.mjs';

const AUTHORITY_SCHEMA = 'amf.m4-group-replay-authority/v1';
const COMPLETION_SCHEMA = 'amf.m4-legacy-group-replay-completion/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const PLAN_SCHEMA = 'amf.m4-legacy-group-replay-batch-plan/v1';
const RESULT_SCHEMA = 'amf.m4-legacy-group-replay-batch-result/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const FACTORY_NAMES = ['v2Index', 'preservedIndex', 'replay', 'completionKey'];
const LIMIT_NAMES = ['maxGroups', 'maxObservations', 'maxOutputEvents'];

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && (typeof value === 'object' || typeof value === 'function'); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }

function authority(value, code = 'm4_legacy_batch_authority_invalid') {
  if (!exact(value, ['schema', 'authorityDigest']) || value.schema !== AUTHORITY_SCHEMA
    || typeof value.authorityDigest !== 'string' || !DIGEST.test(value.authorityDigest)) fail(code);
  return { schema: AUTHORITY_SCHEMA, authorityDigest: value.authorityDigest };
}

function checkpoint(value, code, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function groupCheckpoint(value, authorityDigest, code, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (!exact(value, ['schema', 'authorityDigest', 'sequence', 'groupDigest', 'outcomeDigest'])
    || value.schema !== 'amf.m4-group-replay-checkpoint/v1' || value.authorityDigest !== authorityDigest
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1
    || typeof value.groupDigest !== 'string' || !DIGEST.test(value.groupDigest)
    || typeof value.outcomeDigest !== 'string' || !DIGEST.test(value.outcomeDigest)) fail(code);
  return clone(value, code);
}

function evidence(value, code) {
  if (!exact(value, ['manifestId', 'digest', 'signature']) || typeof value.manifestId !== 'string'
    || !ID.test(value.manifestId) || typeof value.digest !== 'string' || !DIGEST.test(value.digest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return { manifestId: value.manifestId, digest: value.digest, signature: value.signature };
}

function limits(value, code = 'm4_legacy_batch_limits_invalid') {
  if (!exact(value, LIMIT_NAMES)) fail(code);
  const safe = { maxGroups: value.maxGroups, maxObservations: value.maxObservations,
    maxOutputEvents: value.maxOutputEvents };
  if (!Number.isSafeInteger(safe.maxGroups) || safe.maxGroups < 1 || safe.maxGroups > M4_PRESERVED_GROUP_MAX_GROUPS
    || !Number.isSafeInteger(safe.maxObservations) || safe.maxObservations < 1
    || safe.maxObservations > M4_PRESERVED_GROUP_MAX_OBSERVATIONS
    || !Number.isSafeInteger(safe.maxOutputEvents) || safe.maxOutputEvents < 1
    || safe.maxOutputEvents > M4_PRESERVED_GROUP_MAX_OUTPUT_EVENTS) fail(code);
  return safe;
}

function identity(value, code = 'm4_legacy_batch_identity_invalid') {
  if (!exact(value, ['authority', 'limits', 'maxBatches', 'completionManifestId', 'completionKeyId'])) fail(code);
  const safeAuthority = authority(value.authority, code); const safeLimits = limits(value.limits, code);
  if (!Number.isSafeInteger(value.maxBatches) || value.maxBatches < 1 || value.maxBatches > 1_000
    || typeof value.completionManifestId !== 'string' || !ID.test(value.completionManifestId)
    || typeof value.completionKeyId !== 'string' || !ID.test(value.completionKeyId)) fail(code);
  return { authority: safeAuthority, limits: safeLimits, maxBatches: value.maxBatches,
    completionManifestId: value.completionManifestId, completionKeyId: value.completionKeyId };
}

export function deriveM4LegacyGroupReplayRunId(value) {
  const accepted = identity(value);
  return `m4-legacy-${digest(['amf.m4-legacy-group-replay/run-id/v1', accepted]).slice(7)}`;
}

function request(value, run = false) {
  const serialKeys = ['gateInput', 'authority', 'limits', 'maxBatches', 'completionManifestId', 'completionKeyId'];
  const keys = run ? [...serialKeys, 'confirmedPlanDigest', 'verifyV2Snapshot', 'resolveCanonicalLogicalId', 'factories'] : serialKeys;
  const code = run ? 'm4_legacy_batch_run_input_invalid' : 'm4_legacy_batch_plan_input_invalid';
  try {
    if (!exact(value, keys)) fail(code);
    const serial = identity({ authority: clone(value.authority, code), limits: clone(value.limits, code),
      maxBatches: value.maxBatches, completionManifestId: value.completionManifestId,
      completionKeyId: value.completionKeyId }, code);
    const confirmedPlanDigest = run ? value.confirmedPlanDigest : null;
    if (run && (typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest))) fail(code);
    return { gateInput: clone(value.gateInput, code), ...serial,
      ...(run ? { confirmedPlanDigest, runtimeInput: value } : {}) };
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}

async function prepared(value) {
  let gate;
  try { gate = verifyM4BackfillGate(value.gateInput); }
  catch { fail('m4_legacy_batch_gate_invalid'); }
  const runId = deriveM4LegacyGroupReplayRunId({ authority: value.authority, limits: value.limits,
    maxBatches: value.maxBatches, completionManifestId: value.completionManifestId,
    completionKeyId: value.completionKeyId });
  if (gate.phase !== 'v2-archive' || gate.runId !== runId) fail('m4_legacy_batch_gate_mismatch');
  const authorityDigest = value.authority.authorityDigest; const gateDigest = digest(gate);
  const confirmationDigest = digest({ schema: 'amf.m4-legacy-group-replay-confirmation/v1', runId,
    authorityDigest, gateDigest, limits: value.limits, maxBatches: value.maxBatches,
    completionManifestId: value.completionManifestId, completionKeyId: value.completionKeyId });
  return { gate, plan: { schema: PLAN_SCHEMA, operation: 'plan', runId, phase: 'legacy-group-replay',
    authorityDigest, gateDigest, limits: clone(value.limits, 'm4_legacy_batch_plan_invalid'),
    maxBatches: value.maxBatches, completionManifestId: value.completionManifestId,
    completionKeyId: value.completionKeyId, confirmationDigest } };
}

function runtime(value) {
  try {
    const verifyV2Snapshot = value.verifyV2Snapshot;
    const resolveCanonicalLogicalId = value.resolveCanonicalLogicalId; const rawFactories = value.factories;
    if (typeof verifyV2Snapshot !== 'function' || typeof resolveCanonicalLogicalId !== 'function'
      || !exact(rawFactories, FACTORY_NAMES)) {
      fail('m4_legacy_batch_dependency_invalid');
    }
    const factories = {};
    for (const name of FACTORY_NAMES) {
      const factory = rawFactories[name];
      if (typeof factory !== 'function') fail('m4_legacy_batch_dependency_invalid');
      factories[name] = factory;
    }
    return { verifyV2Snapshot, resolveCanonicalLogicalId, factories };
  } catch (error) {
    if (error?.code === 'm4_legacy_batch_dependency_invalid') throw error;
    fail('m4_legacy_batch_dependency_invalid');
  }
}

function v2Attestation(value, authorityDigest, code) {
  if (!exact(value, ['schema', 'authorityDigest', 'archiveDigest', 'totalEntries', 'totalBytes'])
    || value.schema !== 'amf.m4-v2-unified-index-attestation/v1' || value.authorityDigest !== authorityDigest
    || typeof value.archiveDigest !== 'string' || !DIGEST.test(value.archiveDigest)
    || !Number.isSafeInteger(value.totalEntries) || value.totalEntries < 0
    || !Number.isSafeInteger(value.totalBytes) || value.totalBytes < 0) fail(code);
  return clone(value, code);
}

async function preflightV2Snapshot(verifyV2Snapshot, gate, actualAttestation, authorityDigest) {
  let raw;
  try { raw = await verifyV2Snapshot(clone(actualAttestation, 'm4_legacy_batch_v2_snapshot_unverified')); }
  catch { fail('m4_legacy_batch_v2_snapshot_unverified'); }
  let safe;
  try {
    const value = clone(raw, 'm4_legacy_batch_v2_snapshot_unverified');
    if (!exact(value, ['sourceCheckpoint', 'targetCheckpoint', 'indexAttestation'])) fail('m4_legacy_batch_v2_snapshot_unverified');
    safe = { sourceCheckpoint: checkpoint(value.sourceCheckpoint, 'm4_legacy_batch_v2_snapshot_unverified'),
      targetCheckpoint: checkpoint(value.targetCheckpoint, 'm4_legacy_batch_v2_snapshot_unverified'),
      indexAttestation: v2Attestation(value.indexAttestation, authorityDigest,
        'm4_legacy_batch_v2_snapshot_unverified') };
  } catch { fail('m4_legacy_batch_v2_snapshot_unverified'); }
  if (!same(safe.sourceCheckpoint, gate.sourceCheckpoint)
    || !same(safe.targetCheckpoint, gate.targetCheckpoint)
    || !same(safe.indexAttestation, actualAttestation)) fail('m4_legacy_batch_v2_snapshot_mismatch');
}

async function callFactory(factory, name, context) {
  let raw;
  try { raw = await factory(clone(context, `m4_legacy_batch_${name}_factory_failed`)); }
  catch { fail(`m4_legacy_batch_${name}_factory_failed`); }
  try {
    if (!exact(raw, ['value', 'close'])) fail('m4_legacy_batch_factory_result_invalid');
    const value = raw.value; const close = raw.close;
    if (!(close === null || typeof close === 'function')) fail('m4_legacy_batch_factory_result_invalid');
    return { value, close: close === null ? null : close.bind(raw) };
  } catch (error) {
    if (error?.code === 'm4_legacy_batch_factory_result_invalid') throw error;
    fail('m4_legacy_batch_factory_result_invalid');
  }
}

function withoutAuthority(value, code) {
  try {
    if (!plain(value) || Object.hasOwn(value, 'authority')) fail(code);
    return Object.fromEntries(Object.keys(value).map(key => [key, value[key]]));
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}

async function bindPreservedInput(value, pause) {
  const input = withoutAuthority(value, 'm4_legacy_batch_preserved_index_input_invalid');
  let reader; let authorityMethod; let open; let openPositions; let attested;
  try {
    reader = input.reader; authorityMethod = reader?.authority; open = reader?.open; openPositions = reader?.openPositions;
    if (!object(reader) || typeof authorityMethod !== 'function' || typeof open !== 'function'
      || typeof openPositions !== 'function') fail('m4_legacy_batch_preserved_authority_invalid');
    attested = clone(await authorityMethod.call(reader), 'm4_legacy_batch_preserved_authority_invalid');
    if (!exact(attested, ['acknowledgements', 'sources']) || !exact(attested.sources, ['outbox', 'deadletter'])
      || !same(attested.acknowledgements, pause.acknowledgements)
      || !same(attested.sources.outbox?.pauseCheckpoint, pause.pendingOutbox)
      || !same(attested.sources.deadletter?.pauseCheckpoint, pause.deadLetters)) {
      fail('m4_legacy_batch_preserved_authority_mismatch');
    }
  } catch (error) {
    if (error?.code === 'm4_legacy_batch_preserved_authority_mismatch') throw error;
    fail('m4_legacy_batch_preserved_authority_invalid');
  }
  return { ...input, reader: { authority: () => clone(attested, 'm4_legacy_batch_preserved_authority_invalid'),
    open: open.bind(reader), openPositions: openPositions.bind(reader) } };
}

function replayResources(value) {
  try {
    if (!exact(value, ['outbox', 'sink', 'checkpointStore', 'integrityFor'])) fail('m4_legacy_batch_replay_resource_invalid');
    const safe = { outbox: value.outbox, sink: value.sink, checkpointStore: value.checkpointStore,
      integrityFor: value.integrityFor };
    if (!object(safe.outbox) || !object(safe.sink) || !object(safe.checkpointStore)
      || typeof safe.integrityFor !== 'function') fail('m4_legacy_batch_replay_resource_invalid');
    return safe;
  } catch (error) {
    if (error?.code === 'm4_legacy_batch_replay_resource_invalid') throw error;
    fail('m4_legacy_batch_replay_resource_invalid');
  }
}

function signingKey(value, code = 'm4_legacy_batch_completion_key_invalid') {
  if (!exact(value, ['schema', 'keyId', 'key']) || value.schema !== KEY_SCHEMA
    || typeof value.keyId !== 'string' || !ID.test(value.keyId)
    || typeof value.key !== 'string' || !BASE64.test(value.key)) fail(code);
  const key = Buffer.from(value.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== value.key) { key.fill(0); fail(code); }
  return { keyId: value.keyId, key };
}

function signatureFor(valueDigest, key) {
  return crypto.createHmac('sha256', key.key)
    .update(canonicalJson(['amf.m4-legacy-group-replay-completion/v1/integrity', valueDigest, key.keyId]), 'utf8')
    .digest('base64url');
}

function completionFor({ manifestId, authorityDigest, lastCheckpoint, gate, keyDocument, expectedKeyId }) {
  const key = signingKey(keyDocument);
  try {
    if (key.keyId !== expectedKeyId) fail('m4_legacy_batch_completion_key_mismatch');
    const checkpointDigest = digest({ schema: 'amf.m4-legacy-group-replay-final-checkpoint/v1',
      authorityDigest, lastCheckpoint, pauseEvidence: gate.pauseEvidence, rollbackEvidence: gate.rollbackEvidence,
      sourceCheckpoint: gate.sourceCheckpoint, targetCheckpoint: gate.targetCheckpoint });
    const finalCheckpoint = { id: `m4legacy-${checkpointDigest.slice(7)}`, digest: checkpointDigest };
    const payload = { schema: COMPLETION_SCHEMA, state: 'complete', authorityDigest, checkpoint: finalCheckpoint };
    const evidenceDigest = digest({ schema: 'amf.m4-legacy-group-replay-completion-evidence/v1',
      manifestId, keyId: key.keyId, completion: payload });
    return { ...payload, evidence: { manifestId, digest: evidenceDigest,
      signature: signatureFor(evidenceDigest, key) } };
  } finally { key.key.fill(0); }
}

export function verifyM4LegacyGroupReplayCompletion(value, keyDocument) {
  const key = signingKey(keyDocument);
  try {
    if (!exact(value, ['schema', 'state', 'authorityDigest', 'checkpoint', 'evidence'])
      || value.schema !== COMPLETION_SCHEMA || value.state !== 'complete'
      || typeof value.authorityDigest !== 'string' || !DIGEST.test(value.authorityDigest)) {
      fail('m4_legacy_completion_invalid');
    }
    const safe = { schema: COMPLETION_SCHEMA, state: 'complete', authorityDigest: value.authorityDigest,
      checkpoint: checkpoint(value.checkpoint, 'm4_legacy_completion_invalid'),
      evidence: evidence(value.evidence, 'm4_legacy_completion_invalid') };
    const payload = { schema: safe.schema, state: safe.state, authorityDigest: safe.authorityDigest,
      checkpoint: safe.checkpoint };
    const expectedDigest = digest({ schema: 'amf.m4-legacy-group-replay-completion-evidence/v1',
      manifestId: safe.evidence.manifestId, keyId: key.keyId, completion: payload });
    if (safe.evidence.digest !== expectedDigest) fail('m4_legacy_completion_digest_mismatch');
    const expected = Buffer.from(signatureFor(expectedDigest, key), 'base64url');
    const received = Buffer.from(safe.evidence.signature, 'base64url');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      fail('m4_legacy_completion_signature_mismatch');
    }
    return clone(safe, 'm4_legacy_completion_invalid');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_legacy_completion_')) throw error;
    fail('m4_legacy_completion_invalid');
  } finally { key.key.fill(0); }
}

function replayResult(value, authorityDigest) {
  if (!exact(value, ['schema', 'authorityDigest', 'groups', 'observations', 'outputEvents', 'lastCheckpoint', 'complete'])
    || value.schema !== 'amf.m4-group-replay-result/v1' || value.authorityDigest !== authorityDigest
    || ![value.groups, value.observations, value.outputEvents].every(item => Number.isSafeInteger(item) && item >= 0)
    || typeof value.complete !== 'boolean') fail('m4_legacy_batch_result_invalid');
  return { groups: value.groups, observations: value.observations, outputEvents: value.outputEvents,
    lastCheckpoint: groupCheckpoint(value.lastCheckpoint, authorityDigest, 'm4_legacy_batch_result_invalid', { nullable: true }),
    complete: value.complete };
}

async function closeResources(resources) {
  let failed = false;
  for (const resource of [...resources].reverse()) {
    try { await resource.close?.(); } catch { failed = true; }
  }
  return failed;
}

export async function planM4LegacyGroupReplayBatch(input = {}) {
  const accepted = request(input); return clone((await prepared(accepted)).plan, 'm4_legacy_batch_plan_invalid');
}

export async function runM4LegacyGroupReplayBatch(input = {}) {
  const accepted = request(input, true); const planned = await prepared(accepted);
  if (accepted.confirmedPlanDigest !== planned.plan.confirmationDigest) fail('m4_legacy_batch_confirmation_invalid');
  const dependencies = runtime(accepted.runtimeInput); const resources = []; let primary = null;
  try {
    const context = { runId: planned.plan.runId, authorityDigest: accepted.authority.authorityDigest,
      gateDigest: planned.plan.gateDigest };
    const preservedResource = await callFactory(dependencies.factories.preservedIndex, 'preservedIndex', context);
    resources.push(preservedResource);
    const preservedInput = await bindPreservedInput(preservedResource.value, accepted.gateInput.pauseManifest.pause);
    const v2Resource = await callFactory(dependencies.factories.v2Index, 'v2Index', context); resources.push(v2Resource);
    const v2 = await prepareM4V2UnifiedIndex({ ...withoutAuthority(v2Resource.value,
      'm4_legacy_batch_v2_index_input_invalid'), authority: accepted.authority });
    const actualV2Attestation = v2Attestation(v2.attestation, accepted.authority.authorityDigest,
      'm4_legacy_batch_v2_index_attestation_invalid');
    await preflightV2Snapshot(dependencies.verifyV2Snapshot, planned.gate, actualV2Attestation,
      accepted.authority.authorityDigest);
    const preserved = await prepareM4PreservedUnifiedIndex({ ...preservedInput, authority: accepted.authority });
    const source = await prepareM4UnifiedLogicalGroupSource({ authority: accepted.authority,
      indexes: { 'v2-archive': v2.index, ...preserved.indexes },
      materializers: { 'v2-archive': v2.materializer, ...preserved.materializers },
      resolveCanonicalLogicalId: dependencies.resolveCanonicalLogicalId });
    const replayResource = await callFactory(dependencies.factories.replay, 'replay', context); resources.push(replayResource);
    const replay = replayResources(replayResource.value);
    let batches = 0; let groups = 0; let observations = 0; let outputEvents = 0;
    let lastCheckpoint = null; let complete = false; let completion = null;
    while (batches < accepted.maxBatches) {
      let raw;
      try { raw = await runM4PreservedGroupReplay({ authority: accepted.authority, source,
        ...replay, ...accepted.limits }); }
      catch (error) { if (error?.code?.startsWith?.('m4_')) throw error; fail('m4_legacy_batch_execution_failed'); }
      const result = replayResult(raw, accepted.authority.authorityDigest);
      batches += 1; groups += result.groups; observations += result.observations;
      outputEvents += result.outputEvents; lastCheckpoint = result.lastCheckpoint;
      if (result.complete) {
        const keyResource = await callFactory(dependencies.factories.completionKey, 'completionKey', context);
        resources.push(keyResource);
        completion = completionFor({ manifestId: accepted.completionManifestId,
          authorityDigest: accepted.authority.authorityDigest, lastCheckpoint, gate: planned.gate,
          keyDocument: keyResource.value, expectedKeyId: accepted.completionKeyId });
        complete = true; break;
      }
      if (result.groups === 0) fail('m4_legacy_batch_no_progress');
    }
    return { schema: RESULT_SCHEMA, operation: 'run', runId: planned.plan.runId,
      authorityDigest: accepted.authority.authorityDigest, batches, groups, observations, outputEvents,
      lastCheckpoint, complete, completion };
  } catch (error) { primary = error; throw error; }
  finally {
    const cleanupFailed = await closeResources(resources);
    if (primary === null && cleanupFailed) fail('m4_legacy_batch_cleanup_failed');
  }
}
