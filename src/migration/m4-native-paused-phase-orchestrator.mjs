import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4BackfillGate } from './m4-backfill-gate.mjs';
import {
  deriveM4NativePausedRunId,
  planM4NativePausedBatch,
  runM4NativePausedBatch,
} from './m4-native-paused-batch-runner.mjs';
import { M4NativePausedPhaseStore } from './m4-native-paused-phase-store.mjs';

const CATALOG_SCHEMA = 'amf.m4-native-paused-shard-catalog/v1';
const PLAN_SCHEMA = 'amf.m4-native-paused-phase-plan/v1';
const RESULT_SCHEMA = 'amf.m4-native-paused-phase-result/v1';
const RECEIPT_SCHEMA = 'amf.m4-native-paused-phase-receipt/v1';
const COMPLETION_SCHEMA = 'amf.m4-native-paused-phase-completion/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SOURCE_BINDING = /^hmac-sha256:source-v1:[a-f0-9]{64}$/;
const MAX_SHARDS = 1_000;
const MAX_CALLS_PER_SHARD = 1_000;
const MAX_TOTAL_CALLS = 100_000;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function object(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

function exact(value, keys) {
  return plain(value) && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function clone(value, code) {
  try { return structuredClone(value); } catch { fail(code); }
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function evidence(value, code) {
  if (!exact(value, ['manifestId', 'digest', 'signature'])
    || typeof value.manifestId !== 'string' || !ID.test(value.manifestId)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return { manifestId: value.manifestId, digest: value.digest, signature: value.signature };
}

function interval(value, code) {
  if (!exact(value, ['startExclusive', 'endInclusive', 'chain'])
    || !Number.isSafeInteger(value.startExclusive) || value.startExclusive < 0
    || !Number.isSafeInteger(value.endInclusive) || value.endInclusive <= value.startExclusive) fail(code);
  return { startExclusive: value.startExclusive, endInclusive: value.endInclusive,
    chain: checkpoint(value.chain, code) };
}

function projectionBinding(value, code) {
  if (!exact(value, ['schema', 'runtime', 'sourceId', 'digest'])
    || value.schema !== 'amf.m4-paused-projection-binding/v1'
    || !['codex', 'claude', 'hermes', 'openclaw'].includes(value.runtime)
    || typeof value.sourceId !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.sourceId)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { schema: value.schema, runtime: value.runtime, sourceId: value.sourceId, digest: value.digest };
}

function authority(value, code) {
  const keys = ['schema', 'pauseEvidence', 'source', 'sourceBinding', 'projectionBinding', 'interval', 'initialCheckpoint'];
  if (!exact(value, keys) || value.schema !== 'amf.m4-native-paused-interval-authority/v1'
    || typeof value.sourceBinding !== 'string' || !SOURCE_BINDING.test(value.sourceBinding)) fail(code);
  return {
    schema: value.schema,
    pauseEvidence: evidence(value.pauseEvidence, code),
    source: checkpoint(value.source, code),
    sourceBinding: value.sourceBinding,
    projectionBinding: projectionBinding(value.projectionBinding, code),
    interval: interval(value.interval, code),
    initialCheckpoint: checkpoint(value.initialCheckpoint, code),
  };
}

function legacyCompletion(value, code) {
  const keys = ['schema', 'state', 'authorityDigest', 'checkpoint', 'evidence'];
  if (!exact(value, keys) || value.schema !== 'amf.m4-legacy-group-replay-completion/v1'
    || value.state !== 'complete' || typeof value.authorityDigest !== 'string'
    || !DIGEST.test(value.authorityDigest)) fail(code);
  return {
    schema: value.schema,
    state: 'complete',
    authorityDigest: value.authorityDigest,
    checkpoint: checkpoint(value.checkpoint, code),
    evidence: evidence(value.evidence, code),
  };
}

function signingKey(value, code) {
  if (!exact(value, ['schema', 'keyId', 'key']) || value.schema !== KEY_SCHEMA
    || typeof value.keyId !== 'string' || !ID.test(value.keyId)
    || typeof value.key !== 'string' || !BASE64.test(value.key)) fail(code);
  const key = Buffer.from(value.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== value.key) {
    key.fill(0);
    fail(code);
  }
  return { keyId: value.keyId, key };
}

function equivalentHmacSha256Keys(left, right) {
  const leftBlock = Buffer.alloc(64);
  const rightBlock = Buffer.alloc(64);
  try {
    left.copy(leftBlock);
    right.copy(rightBlock);
    return crypto.timingSafeEqual(leftBlock, rightBlock);
  } finally {
    leftBlock.fill(0);
    rightBlock.fill(0);
  }
}

function signatureFor(domain, valueDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key)
    .update(canonicalJson([domain, valueDigest, loadedKey.keyId]), 'utf8')
    .digest('base64url');
}

function equalSignature(received, expected) {
  const left = Buffer.from(received, 'base64url');
  const right = Buffer.from(expected, 'base64url');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function shard(value, ordinal, code) {
  if (!exact(value, ['ordinal', 'authority', 'maxEvents']) || value.ordinal !== ordinal
    || !Number.isSafeInteger(value.maxEvents) || value.maxEvents < 1 || value.maxEvents > 10_000) {
    fail(code);
  }
  return { ordinal, authority: authority(value.authority, code), maxEvents: value.maxEvents };
}

function catalogPayload(value, code) {
  const keys = ['schema', 'pauseEvidence', 'source', 'initialCheckpoint', 'shards'];
  if (!exact(value, keys) || value.schema !== CATALOG_SCHEMA || !Array.isArray(value.shards)
    || value.shards.length < 1 || value.shards.length > MAX_SHARDS) fail(code);
  const safe = {
    schema: CATALOG_SCHEMA,
    pauseEvidence: evidence(value.pauseEvidence, code),
    source: checkpoint(value.source, code),
    initialCheckpoint: checkpoint(value.initialCheckpoint, code),
    shards: value.shards.map((item, ordinal) => shard(item, ordinal, code)),
  };
  const authorityDigests = new Set();
  const closedBindings = new Set();
  let activeBinding = null;
  let priorAuthority = null;
  for (const item of safe.shards) {
    if (!same(item.authority.pauseEvidence, safe.pauseEvidence)
      || !same(item.authority.source, safe.source)
      || !same(item.authority.initialCheckpoint, safe.initialCheckpoint)) fail(code);
    const authorityDigest = digest(item.authority);
    if (authorityDigests.has(authorityDigest)) fail(code);
    authorityDigests.add(authorityDigest);
    if (item.authority.sourceBinding !== activeBinding) {
      if (activeBinding !== null) closedBindings.add(activeBinding);
      if (closedBindings.has(item.authority.sourceBinding)) fail(code);
      activeBinding = item.authority.sourceBinding;
      priorAuthority = null;
    }
    if (priorAuthority !== null
      && priorAuthority.interval.endInclusive !== item.authority.interval.startExclusive) fail(code);
    priorAuthority = item.authority;
  }
  return safe;
}

function catalogDocument(value, code) {
  const keys = ['schema', 'pauseEvidence', 'source', 'initialCheckpoint', 'shards', 'integrity'];
  if (!exact(value, keys) || !exact(value.integrity,
    ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || value.integrity.algorithm !== 'hmac-sha256'
    || typeof value.integrity.keyId !== 'string' || !ID.test(value.integrity.keyId)
    || typeof value.integrity.payloadDigest !== 'string' || !DIGEST.test(value.integrity.payloadDigest)
    || typeof value.integrity.signature !== 'string' || !SIGNATURE.test(value.integrity.signature)) fail(code);
  const payload = catalogPayload({
    schema: value.schema,
    pauseEvidence: clone(value.pauseEvidence, code),
    source: clone(value.source, code),
    initialCheckpoint: clone(value.initialCheckpoint, code),
    shards: clone(value.shards, code),
  }, code);
  return { ...payload, integrity: clone(value.integrity, code) };
}

export function createM4NativePausedShardCatalog(input = {}) {
  const keys = ['pauseEvidence', 'source', 'initialCheckpoint', 'shards', 'keyDocument'];
  if (!exact(input, keys)) fail('m4_native_phase_catalog_input_invalid');
  const loadedKey = signingKey(input.keyDocument, 'm4_native_phase_catalog_key_invalid');
  try {
    const payload = catalogPayload({
      schema: CATALOG_SCHEMA,
      pauseEvidence: clone(input.pauseEvidence, 'm4_native_phase_catalog_input_invalid'),
      source: clone(input.source, 'm4_native_phase_catalog_input_invalid'),
      initialCheckpoint: clone(input.initialCheckpoint, 'm4_native_phase_catalog_input_invalid'),
      shards: clone(input.shards, 'm4_native_phase_catalog_input_invalid'),
    }, 'm4_native_phase_catalog_invalid');
    const payloadDigest = digest(payload);
    return {
      ...payload,
      integrity: {
        algorithm: 'hmac-sha256',
        keyId: loadedKey.keyId,
        payloadDigest,
        signature: signatureFor('amf.m4-native-paused-shard-catalog/v1/integrity',
          payloadDigest, loadedKey),
      },
    };
  } finally {
    loadedKey.key.fill(0);
  }
}

export function verifyM4NativePausedShardCatalog(value, keyDocument) {
  const catalog = catalogDocument(value, 'm4_native_phase_catalog_invalid');
  const loadedKey = signingKey(keyDocument, 'm4_native_phase_catalog_key_invalid');
  try {
    if (catalog.integrity.keyId !== loadedKey.keyId) fail('m4_native_phase_catalog_key_mismatch');
    const { integrity, ...payload } = catalog;
    const payloadDigest = digest(payload);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_native_phase_catalog_digest_mismatch');
    const expected = signatureFor('amf.m4-native-paused-shard-catalog/v1/integrity',
      payloadDigest, loadedKey);
    if (!equalSignature(integrity.signature, expected)) fail('m4_native_phase_catalog_signature_mismatch');
    return clone(catalog, 'm4_native_phase_catalog_invalid');
  } finally {
    loadedKey.key.fill(0);
  }
}

function childPlan(value, ordinal, code) {
  const keys = ['ordinal', 'runId', 'confirmationDigest', 'authorityDigest', 'legacyCompletionDigest'];
  if (!exact(value, keys) || value.ordinal !== ordinal
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || ![value.confirmationDigest, value.authorityDigest, value.legacyCompletionDigest]
      .every(item => typeof item === 'string' && DIGEST.test(item))) fail(code);
  return clone(value, code);
}

function phaseIdentity(value, code) {
  const keys = ['gateEvidenceDigest', 'catalogDigest', 'legacyCompletionDigest', 'childPlans',
    'maxCallsPerInvocationPerShard', 'maxCallsPerInvocationTotal', 'receiptKeyId',
    'completionManifestId', 'completionKeyId', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'];
  if (!exact(value, keys) || typeof value.gateEvidenceDigest !== 'string'
    || !DIGEST.test(value.gateEvidenceDigest) || typeof value.catalogDigest !== 'string'
    || !DIGEST.test(value.catalogDigest) || typeof value.legacyCompletionDigest !== 'string'
    || !DIGEST.test(value.legacyCompletionDigest) || !Array.isArray(value.childPlans)
    || value.childPlans.length < 1 || value.childPlans.length > MAX_SHARDS
    || !Number.isSafeInteger(value.maxCallsPerInvocationPerShard)
    || value.maxCallsPerInvocationPerShard < 1
    || value.maxCallsPerInvocationPerShard > MAX_CALLS_PER_SHARD
    || !Number.isSafeInteger(value.maxCallsPerInvocationTotal)
    || value.maxCallsPerInvocationTotal < 1
    || value.maxCallsPerInvocationTotal > MAX_TOTAL_CALLS
    || typeof value.receiptKeyId !== 'string' || !ID.test(value.receiptKeyId)
    || typeof value.completionManifestId !== 'string' || !ID.test(value.completionManifestId)
    || typeof value.completionKeyId !== 'string' || !ID.test(value.completionKeyId)
    || typeof value.registryAuthorityDigest !== 'string' || !DIGEST.test(value.registryAuthorityDigest)
    || typeof value.sourceTagAuthorityDigest !== 'string' || !DIGEST.test(value.sourceTagAuthorityDigest)) fail(code);
  return {
    gateEvidenceDigest: value.gateEvidenceDigest,
    catalogDigest: value.catalogDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    childPlans: value.childPlans.map((item, ordinal) => childPlan(item, ordinal, code)),
    maxCallsPerInvocationPerShard: value.maxCallsPerInvocationPerShard,
    maxCallsPerInvocationTotal: value.maxCallsPerInvocationTotal,
    receiptKeyId: value.receiptKeyId,
    completionManifestId: value.completionManifestId,
    completionKeyId: value.completionKeyId,
    registryAuthorityDigest: value.registryAuthorityDigest,
    sourceTagAuthorityDigest: value.sourceTagAuthorityDigest,
  };
}

export function deriveM4NativePausedPhaseRunId(value) {
  const identity = phaseIdentity(clone(value, 'm4_native_phase_identity_invalid'),
    'm4_native_phase_identity_invalid');
  return `m4-phase-${digest(['amf.m4-native-paused-phase/run-id/v1', identity]).slice(7)}`;
}

function serialRequest(value, code) {
  const keys = ['gateInput', 'catalog', 'catalogKey', 'legacyCompletion',
    'maxCallsPerInvocationPerShard', 'maxCallsPerInvocationTotal', 'receiptKeyId',
    'completionManifestId', 'completionKeyId', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'];
  try {
    if (!exact(value, keys)) fail(code);
    const catalogKey = clone(value.catalogKey, code);
    const catalog = verifyM4NativePausedShardCatalog(clone(value.catalog, code), catalogKey);
    const prerequisite = legacyCompletion(clone(value.legacyCompletion, code), code);
    if (!Number.isSafeInteger(value.maxCallsPerInvocationPerShard)
      || value.maxCallsPerInvocationPerShard < 1
      || value.maxCallsPerInvocationPerShard > MAX_CALLS_PER_SHARD
      || !Number.isSafeInteger(value.maxCallsPerInvocationTotal)
      || value.maxCallsPerInvocationTotal < 1
      || value.maxCallsPerInvocationTotal > MAX_TOTAL_CALLS
      || typeof value.receiptKeyId !== 'string' || !ID.test(value.receiptKeyId)
      || typeof value.completionManifestId !== 'string' || !ID.test(value.completionManifestId)
      || typeof value.completionKeyId !== 'string' || !ID.test(value.completionKeyId)
      || typeof value.registryAuthorityDigest !== 'string' || !DIGEST.test(value.registryAuthorityDigest)
      || typeof value.sourceTagAuthorityDigest !== 'string' || !DIGEST.test(value.sourceTagAuthorityDigest)) fail(code);
    if (value.receiptKeyId === catalog.integrity.keyId) {
      fail('m4_native_phase_key_separation_invalid');
    }
    return {
      gateInput: clone(value.gateInput, code),
      catalog,
      catalogKey,
      prerequisite,
      maxCallsPerInvocationPerShard: value.maxCallsPerInvocationPerShard,
      maxCallsPerInvocationTotal: value.maxCallsPerInvocationTotal,
      receiptKeyId: value.receiptKeyId,
      completionManifestId: value.completionManifestId,
      completionKeyId: value.completionKeyId,
      registryAuthorityDigest: value.registryAuthorityDigest,
      sourceTagAuthorityDigest: value.sourceTagAuthorityDigest,
    };
  } catch (error) {
    if (error?.code === code || error?.code?.startsWith?.('m4_native_phase_catalog_')
      || error?.code === 'm4_native_phase_key_separation_invalid') throw error;
    fail(code);
  }
}

async function planFor(serial) {
  const childPlans = [];
  let verifiedGate = null;
  for (const item of serial.catalog.shards) {
    const authorityDigests = {
      registryAuthorityDigest: serial.registryAuthorityDigest,
      sourceTagAuthorityDigest: serial.sourceTagAuthorityDigest,
    };
    const runId = deriveM4NativePausedRunId(item.authority, serial.prerequisite, authorityDigests);
    const gateInput = { ...serial.gateInput, runId, phase: 'paused-native' };
    let planned;
    try {
      planned = await planM4NativePausedBatch({
        gateInput,
        maxEvents: item.maxEvents,
        authority: item.authority,
        legacyCompletion: serial.prerequisite,
        ...authorityDigests,
      });
      if (verifiedGate === null) verifiedGate = verifyM4BackfillGate(gateInput);
    } catch {
      fail('m4_native_phase_gate_invalid');
    }
    childPlans.push(childPlan({
      ordinal: item.ordinal,
      runId: planned.runId,
      confirmationDigest: planned.confirmationDigest,
      authorityDigest: planned.authorityDigest,
      legacyCompletionDigest: planned.legacyCompletionDigest,
    }, item.ordinal, 'm4_native_phase_child_plan_invalid'));
  }
  const gateEvidenceDigest = digest({
    schema: 'amf.m4-native-paused-phase-gate-evidence/v1',
    pauseEvidence: verifiedGate.pauseEvidence,
    rollbackEvidence: verifiedGate.rollbackEvidence,
    sourceCheckpoint: verifiedGate.sourceCheckpoint,
    targetCheckpoint: verifiedGate.targetCheckpoint,
  });
  const identity = phaseIdentity({
    gateEvidenceDigest,
    catalogDigest: digest(serial.catalog),
    legacyCompletionDigest: digest(serial.prerequisite),
    childPlans,
    maxCallsPerInvocationPerShard: serial.maxCallsPerInvocationPerShard,
    maxCallsPerInvocationTotal: serial.maxCallsPerInvocationTotal,
    receiptKeyId: serial.receiptKeyId,
    completionManifestId: serial.completionManifestId,
    completionKeyId: serial.completionKeyId,
    registryAuthorityDigest: serial.registryAuthorityDigest,
    sourceTagAuthorityDigest: serial.sourceTagAuthorityDigest,
  }, 'm4_native_phase_plan_invalid');
  const runId = deriveM4NativePausedPhaseRunId(identity);
  const confirmationDigest = digest({
    schema: 'amf.m4-native-paused-phase-confirmation/v1',
    runId,
    ...identity,
  });
  return {
    schema: PLAN_SCHEMA,
    operation: 'plan',
    runId,
    ...identity,
    confirmationDigest,
  };
}

export async function planM4NativePausedPhase(input = {}) {
  const serial = serialRequest(input, 'm4_native_phase_plan_input_invalid');
  return clone(await planFor(serial), 'm4_native_phase_plan_invalid');
}

function runtimeDependencies(input) {
  try {
    const verifyCurrentCatalog = input.verifyCurrentCatalog;
    const verifyLegacyCompletion = input.verifyLegacyCompletion;
    const rawFactories = input.factories;
    const factoryNames = ['receiptKey', 'phaseLease', 'phaseStore', 'shard', 'completionKey'];
    if (typeof verifyCurrentCatalog !== 'function' || typeof verifyLegacyCompletion !== 'function'
      || !exact(rawFactories, factoryNames)) fail('m4_native_phase_dependency_invalid');
    const factories = {};
    for (const name of factoryNames) {
      const factory = rawFactories[name];
      if (typeof factory !== 'function') fail('m4_native_phase_dependency_invalid');
      factories[name] = factory;
    }
    return { verifyCurrentCatalog, verifyLegacyCompletion, factories };
  } catch (error) {
    if (error?.code === 'm4_native_phase_dependency_invalid') throw error;
    fail('m4_native_phase_dependency_invalid');
  }
}

async function currentPrerequisites(dependencies, serial) {
  let catalogValue;
  let legacyValue;
  try {
    catalogValue = await dependencies.verifyCurrentCatalog();
    legacyValue = await dependencies.verifyLegacyCompletion();
  } catch {
    fail('m4_native_phase_prerequisite_unverified');
  }
  let catalog;
  let prerequisite;
  try {
    catalog = verifyM4NativePausedShardCatalog(
      clone(catalogValue, 'm4_native_phase_prerequisite_unverified'), serial.catalogKey);
    prerequisite = legacyCompletion(
      clone(legacyValue, 'm4_native_phase_prerequisite_unverified'),
      'm4_native_phase_prerequisite_unverified');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_native_phase_catalog_')) {
      fail('m4_native_phase_catalog_unverified');
    }
    fail('m4_native_phase_prerequisite_unverified');
  }
  if (!same(catalog, serial.catalog)) fail('m4_native_phase_catalog_mismatch');
  if (!same(prerequisite, serial.prerequisite)) fail('m4_native_phase_legacy_mismatch');
}

async function callResourceFactory(factory, context, code) {
  let raw;
  try { raw = await factory(clone(context, code)); }
  catch { fail(code); }
  try {
    if (!exact(raw, ['value', 'close'])
      || !(raw.close === null || typeof raw.close === 'function')) fail(`${code}_result_invalid`);
    return { value: raw.value, close: raw.close === null ? null : raw.close.bind(raw) };
  } catch (error) {
    if (error?.code === `${code}_result_invalid`) throw error;
    fail(`${code}_result_invalid`);
  }
}

async function closeOne(resource, primary) {
  try { await resource?.close?.(); }
  catch {
    if (primary === null) fail('m4_native_phase_cleanup_failed');
  }
}

function phaseLease(value, code) {
  try {
    const acquire = value?.acquire;
    const heartbeat = value?.heartbeat;
    const release = value?.release;
    if (!object(value) || typeof acquire !== 'function' || typeof heartbeat !== 'function'
      || typeof release !== 'function') fail(code);
    return { acquire: acquire.bind(value), heartbeat: heartbeat.bind(value), release: release.bind(value) };
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

async function leaseCall(action, context, code) {
  try { await action(clone(context, code)); }
  catch { fail(code); }
}

function batchRuntime(value, code) {
  const keys = ['gateInput', 'reader', 'derivationKey', 'derivationKeyId', 'verifyPauseEvidence',
    'verifyLegacyCompletion', 'integrityFor', 'projectionIdentityResolver', 'factories'];
  try {
    if (!exact(value, keys)) fail(code);
    return {
      gateInput: clone(value.gateInput, code),
      reader: value.reader,
      derivationKey: value.derivationKey,
      derivationKeyId: value.derivationKeyId,
      verifyPauseEvidence: value.verifyPauseEvidence,
      verifyLegacyCompletion: value.verifyLegacyCompletion,
      integrityFor: value.integrityFor,
      projectionIdentityResolver: value.projectionIdentityResolver,
      factories: value.factories,
    };
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

function batchResult(value, expected, code) {
  const keys = ['schema', 'operation', 'runId', 'phase', 'authorityDigest',
    'legacyCompletionDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest',
    'processed', 'duplicates', 'lastCheckpoint', 'complete'];
  if (!exact(value, keys) || value.schema !== 'amf.m4-native-paused-batch-result/v1'
    || value.operation !== 'run' || value.runId !== expected.runId || value.phase !== 'paused-native'
    || value.authorityDigest !== expected.authorityDigest
    || value.legacyCompletionDigest !== expected.legacyCompletionDigest
    || value.registryAuthorityDigest !== expected.registryAuthorityDigest
    || value.sourceTagAuthorityDigest !== expected.sourceTagAuthorityDigest
    || !Number.isSafeInteger(value.processed) || value.processed < 0
    || !Number.isSafeInteger(value.duplicates) || value.duplicates < 0
    || value.duplicates > value.processed || typeof value.complete !== 'boolean') fail(code);
  return {
    schema: value.schema,
    operation: 'run',
    runId: value.runId,
    phase: 'paused-native',
    authorityDigest: value.authorityDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    registryAuthorityDigest: value.registryAuthorityDigest,
    sourceTagAuthorityDigest: value.sourceTagAuthorityDigest,
    processed: value.processed,
    duplicates: value.duplicates,
    lastCheckpoint: checkpoint(value.lastCheckpoint, code),
    complete: value.complete,
  };
}

export function verifyM4NativePausedPhaseChildResult(value, expected) {
  const code = 'm4_native_phase_child_result_invalid';
  try {
    const snapshot = clone(expected, code);
    const keys = ['ordinal', 'runId', 'confirmationDigest', 'authorityDigest',
      'legacyCompletionDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'];
    if (!exact(snapshot, keys) || typeof snapshot.registryAuthorityDigest !== 'string'
      || !DIGEST.test(snapshot.registryAuthorityDigest)
      || typeof snapshot.sourceTagAuthorityDigest !== 'string'
      || !DIGEST.test(snapshot.sourceTagAuthorityDigest)) fail(code);
    const { registryAuthorityDigest, sourceTagAuthorityDigest, ...child } = snapshot;
    return batchResult(clone(value, code), {
      ...childPlan(child, child.ordinal, code),
      registryAuthorityDigest,
      sourceTagAuthorityDigest,
    }, code);
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

function receiptPayload(value, code) {
  const keys = ['schema', 'ordinal', 'runId', 'planConfirmationDigest', 'authorityDigest',
    'legacyCompletionDigest', 'terminalCheckpoint', 'resultDigest'];
  if (!exact(value, keys) || value.schema !== RECEIPT_SCHEMA
    || !Number.isSafeInteger(value.ordinal) || value.ordinal < 0
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || ![value.planConfirmationDigest, value.authorityDigest, value.legacyCompletionDigest, value.resultDigest]
      .every(item => typeof item === 'string' && DIGEST.test(item))) fail(code);
  return {
    schema: RECEIPT_SCHEMA,
    ordinal: value.ordinal,
    runId: value.runId,
    planConfirmationDigest: value.planConfirmationDigest,
    authorityDigest: value.authorityDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    terminalCheckpoint: checkpoint(value.terminalCheckpoint, code),
    resultDigest: value.resultDigest,
  };
}

function signReceipt(payload, keyDocument) {
  const loadedKey = signingKey(keyDocument, 'm4_native_phase_receipt_key_invalid');
  try {
    const payloadDigest = digest(payload);
    return {
      ...payload,
      integrity: {
        algorithm: 'hmac-sha256',
        keyId: loadedKey.keyId,
        payloadDigest,
        signature: signatureFor('amf.m4-native-paused-phase-receipt/v1/integrity',
          payloadDigest, loadedKey),
      },
    };
  } finally {
    loadedKey.key.fill(0);
  }
}

function receiptFor(ordinal, child, resultValue, keyDocument) {
  return signReceipt(receiptPayload({
    schema: RECEIPT_SCHEMA,
    ordinal,
    runId: child.runId,
    planConfirmationDigest: child.confirmationDigest,
    authorityDigest: child.authorityDigest,
    legacyCompletionDigest: child.legacyCompletionDigest,
    terminalCheckpoint: resultValue.lastCheckpoint,
    resultDigest: digest(resultValue),
  }, 'm4_native_phase_receipt_invalid'), keyDocument);
}

function verifyReceipt(value, expectedChild, ordinal, keyDocument) {
  const keys = ['schema', 'ordinal', 'runId', 'planConfirmationDigest', 'authorityDigest',
    'legacyCompletionDigest', 'terminalCheckpoint', 'resultDigest', 'integrity'];
  if (!exact(value, keys) || !exact(value.integrity,
    ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || value.integrity.algorithm !== 'hmac-sha256'
    || typeof value.integrity.keyId !== 'string' || !ID.test(value.integrity.keyId)
    || typeof value.integrity.payloadDigest !== 'string' || !DIGEST.test(value.integrity.payloadDigest)
    || typeof value.integrity.signature !== 'string' || !SIGNATURE.test(value.integrity.signature)) {
    fail('m4_native_phase_receipt_invalid');
  }
  const payload = receiptPayload({
    schema: value.schema,
    ordinal: value.ordinal,
    runId: value.runId,
    planConfirmationDigest: value.planConfirmationDigest,
    authorityDigest: value.authorityDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    terminalCheckpoint: value.terminalCheckpoint,
    resultDigest: value.resultDigest,
  }, 'm4_native_phase_receipt_invalid');
  if (payload.ordinal !== ordinal || payload.runId !== expectedChild.runId
    || payload.planConfirmationDigest !== expectedChild.confirmationDigest
    || payload.authorityDigest !== expectedChild.authorityDigest
    || payload.legacyCompletionDigest !== expectedChild.legacyCompletionDigest) {
    fail('m4_native_phase_receipt_mismatch');
  }
  const loadedKey = signingKey(keyDocument, 'm4_native_phase_receipt_key_invalid');
  try {
    if (value.integrity.keyId !== loadedKey.keyId) fail('m4_native_phase_receipt_key_mismatch');
    const payloadDigest = digest(payload);
    if (value.integrity.payloadDigest !== payloadDigest) fail('m4_native_phase_receipt_digest_mismatch');
    const expected = signatureFor('amf.m4-native-paused-phase-receipt/v1/integrity',
      payloadDigest, loadedKey);
    if (!equalSignature(value.integrity.signature, expected)) {
      fail('m4_native_phase_receipt_signature_mismatch');
    }
    return clone({ ...payload, integrity: value.integrity }, 'm4_native_phase_receipt_invalid');
  } finally {
    loadedKey.key.fill(0);
  }
}

function verifiedReceipts(value, plan, keyDocument) {
  if (!Array.isArray(value) || value.length > plan.childPlans.length) {
    fail('m4_native_phase_receipts_invalid');
  }
  return value.map((item, ordinal) => verifyReceipt(
    clone(item, 'm4_native_phase_receipts_invalid'), plan.childPlans[ordinal], ordinal, keyDocument));
}

function completionCheckpoint(plan, receiptDigest) {
  const checkpointDigest = digest({
    schema: 'amf.m4-native-paused-phase-final-checkpoint/v1',
    runId: plan.runId,
    gateEvidenceDigest: plan.gateEvidenceDigest,
    catalogDigest: plan.catalogDigest,
    legacyCompletionDigest: plan.legacyCompletionDigest,
    registryAuthorityDigest: plan.registryAuthorityDigest,
    sourceTagAuthorityDigest: plan.sourceTagAuthorityDigest,
    receiptKeyId: plan.receiptKeyId,
    receiptDigest,
  });
  return { id: `m4nativephase-${checkpointDigest.slice(7)}`, digest: checkpointDigest };
}

function completionFor(plan, receipts, keyDocument) {
  const loadedKey = signingKey(keyDocument, 'm4_native_phase_completion_key_invalid');
  try {
    if (loadedKey.keyId !== plan.completionKeyId) fail('m4_native_phase_completion_key_mismatch');
    const receiptDigest = digest(receipts);
    const payload = {
      schema: COMPLETION_SCHEMA,
      state: 'complete',
      runId: plan.runId,
      gateEvidenceDigest: plan.gateEvidenceDigest,
      catalogDigest: plan.catalogDigest,
      legacyCompletionDigest: plan.legacyCompletionDigest,
      registryAuthorityDigest: plan.registryAuthorityDigest,
      sourceTagAuthorityDigest: plan.sourceTagAuthorityDigest,
      receiptKeyId: plan.receiptKeyId,
      receiptDigest,
      checkpoint: completionCheckpoint(plan, receiptDigest),
    };
    const evidenceDigest = digest({
      schema: 'amf.m4-native-paused-phase-completion-evidence/v1',
      manifestId: plan.completionManifestId,
      keyId: loadedKey.keyId,
      completion: payload,
    });
    return {
      ...payload,
      evidence: {
        manifestId: plan.completionManifestId,
        keyId: loadedKey.keyId,
        digest: evidenceDigest,
        signature: signatureFor('amf.m4-native-paused-phase-completion/v1/integrity',
          evidenceDigest, loadedKey),
      },
    };
  } finally {
    loadedKey.key.fill(0);
  }
}

function completionPayload(value, code) {
  const keys = ['schema', 'state', 'runId', 'gateEvidenceDigest', 'catalogDigest',
    'legacyCompletionDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest',
    'receiptKeyId', 'receiptDigest', 'checkpoint'];
  if (!exact(value, keys) || value.schema !== COMPLETION_SCHEMA || value.state !== 'complete'
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || ![value.gateEvidenceDigest, value.catalogDigest, value.legacyCompletionDigest,
      value.registryAuthorityDigest, value.sourceTagAuthorityDigest, value.receiptDigest]
      .every(item => typeof item === 'string' && DIGEST.test(item))
    || typeof value.receiptKeyId !== 'string' || !ID.test(value.receiptKeyId)) fail(code);
  const payload = {
    schema: COMPLETION_SCHEMA,
    state: 'complete',
    runId: value.runId,
    gateEvidenceDigest: value.gateEvidenceDigest,
    catalogDigest: value.catalogDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    registryAuthorityDigest: value.registryAuthorityDigest,
    sourceTagAuthorityDigest: value.sourceTagAuthorityDigest,
    receiptKeyId: value.receiptKeyId,
    receiptDigest: value.receiptDigest,
    checkpoint: checkpoint(value.checkpoint, code),
  };
  if (!same(payload.checkpoint, completionCheckpoint(payload, payload.receiptDigest))) fail(code);
  return payload;
}

export function verifyM4NativePausedPhaseCompletion(value, keyDocument) {
  const keys = ['schema', 'state', 'runId', 'gateEvidenceDigest', 'catalogDigest',
    'legacyCompletionDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest',
    'receiptKeyId', 'receiptDigest', 'checkpoint', 'evidence'];
  if (!exact(value, keys) || !exact(value.evidence,
    ['manifestId', 'keyId', 'digest', 'signature'])
    || typeof value.evidence.manifestId !== 'string' || !ID.test(value.evidence.manifestId)
    || typeof value.evidence.keyId !== 'string' || !ID.test(value.evidence.keyId)
    || typeof value.evidence.digest !== 'string' || !DIGEST.test(value.evidence.digest)
    || typeof value.evidence.signature !== 'string' || !SIGNATURE.test(value.evidence.signature)) {
    fail('m4_native_phase_completion_invalid');
  }
  const payload = completionPayload({
    schema: value.schema,
    state: value.state,
    runId: value.runId,
    gateEvidenceDigest: value.gateEvidenceDigest,
    catalogDigest: value.catalogDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    registryAuthorityDigest: value.registryAuthorityDigest,
    sourceTagAuthorityDigest: value.sourceTagAuthorityDigest,
    receiptKeyId: value.receiptKeyId,
    receiptDigest: value.receiptDigest,
    checkpoint: value.checkpoint,
  }, 'm4_native_phase_completion_invalid');
  const loadedKey = signingKey(keyDocument, 'm4_native_phase_completion_key_invalid');
  try {
    if (value.evidence.keyId !== loadedKey.keyId) fail('m4_native_phase_completion_key_mismatch');
    const evidenceDigest = digest({
      schema: 'amf.m4-native-paused-phase-completion-evidence/v1',
      manifestId: value.evidence.manifestId,
      keyId: loadedKey.keyId,
      completion: payload,
    });
    if (value.evidence.digest !== evidenceDigest) fail('m4_native_phase_completion_digest_mismatch');
    const expected = signatureFor('amf.m4-native-paused-phase-completion/v1/integrity',
      evidenceDigest, loadedKey);
    if (!equalSignature(value.evidence.signature, expected)) {
      fail('m4_native_phase_completion_signature_mismatch');
    }
    return clone({ ...payload, evidence: value.evidence }, 'm4_native_phase_completion_invalid');
  } finally {
    loadedKey.key.fill(0);
  }
}

function runSerial(input) {
  const keys = ['gateInput', 'catalog', 'catalogKey', 'legacyCompletion',
    'maxCallsPerInvocationPerShard', 'maxCallsPerInvocationTotal', 'receiptKeyId',
    'completionManifestId', 'completionKeyId', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'];
  const value = {};
  try {
    for (const key of keys) value[key] = input[key];
  } catch {
    fail('m4_native_phase_run_input_invalid');
  }
  return serialRequest(value, 'm4_native_phase_run_input_invalid');
}

export async function runM4NativePausedPhase(input = {}) {
  const keys = ['gateInput', 'catalog', 'catalogKey', 'legacyCompletion',
    'maxCallsPerInvocationPerShard', 'maxCallsPerInvocationTotal', 'receiptKeyId',
    'completionManifestId', 'completionKeyId', 'registryAuthorityDigest', 'sourceTagAuthorityDigest', 'confirmedPlanDigest',
    'verifyCurrentCatalog', 'verifyLegacyCompletion', 'factories'];
  if (!exact(input, keys)) fail('m4_native_phase_run_input_invalid');
  const serial = runSerial(input);
  const plan = await planFor(serial);
  let confirmedPlanDigest;
  try { confirmedPlanDigest = input.confirmedPlanDigest; }
  catch { fail('m4_native_phase_run_input_invalid'); }
  if (typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest)
    || confirmedPlanDigest !== plan.confirmationDigest) fail('m4_native_phase_confirmation_invalid');
  const dependencies = runtimeDependencies(input);
  await currentPrerequisites(dependencies, serial);

  const resources = [];
  let primary = null;
  try {
    const receiptKeyResource = await callResourceFactory(dependencies.factories.receiptKey, {
      runId: plan.runId,
      catalogDigest: plan.catalogDigest,
      receiptKeyId: plan.receiptKeyId,
    }, 'm4_native_phase_receipt_key_factory_failed');
    let receiptKeyDocument;
    try {
      receiptKeyDocument = clone(receiptKeyResource.value,
        'm4_native_phase_receipt_key_factory_result_invalid');
      const loadedReceiptKey = signingKey(receiptKeyDocument,
        'm4_native_phase_receipt_key_factory_result_invalid');
      let loadedCatalogKey = null;
      try {
        loadedCatalogKey = signingKey(serial.catalogKey,
          'm4_native_phase_catalog_key_invalid');
        if (loadedReceiptKey.keyId !== plan.receiptKeyId) {
          fail('m4_native_phase_receipt_key_mismatch');
        }
        if (equivalentHmacSha256Keys(loadedReceiptKey.key, loadedCatalogKey.key)) {
          fail('m4_native_phase_key_separation_invalid');
        }
      } finally {
        loadedReceiptKey.key.fill(0);
        loadedCatalogKey?.key.fill(0);
      }
    } catch (error) {
      await closeOne(receiptKeyResource, error);
      throw error;
    }
    resources.push(receiptKeyResource);

    const rawLeaseResource = await callResourceFactory(dependencies.factories.phaseLease, {
      runId: plan.runId,
      planDigest: plan.confirmationDigest,
      catalogDigest: plan.catalogDigest,
    }, 'm4_native_phase_lease_factory_failed');
    let lease;
    try { lease = phaseLease(rawLeaseResource.value, 'm4_native_phase_lease_factory_result_invalid'); }
    catch (error) { await closeOne(rawLeaseResource, error); throw error; }
    const leaseContext = { runId: plan.runId, planDigest: plan.confirmationDigest,
      catalogDigest: plan.catalogDigest };
    try {
      await leaseCall(lease.acquire, leaseContext, 'm4_native_phase_lease_acquire_failed');
    } catch (error) {
      await closeOne(rawLeaseResource, error);
      throw error;
    }
    resources.push({
      close: async () => {
        let failed = false;
        try { await lease.release(clone(leaseContext, 'm4_native_phase_lease_release_failed')); }
        catch { failed = true; }
        try { await rawLeaseResource.close?.(); } catch { failed = true; }
        if (failed) fail('m4_native_phase_lease_release_failed');
      },
    });
    await leaseCall(lease.heartbeat, leaseContext, 'm4_native_phase_lease_heartbeat_failed');

    const storeResource = await callResourceFactory(dependencies.factories.phaseStore, {
      runId: plan.runId,
      planDigest: plan.confirmationDigest,
      catalogDigest: plan.catalogDigest,
      shardCount: plan.childPlans.length,
    }, 'm4_native_phase_store_factory_failed');
    if (!object(storeResource.value) || typeof storeResource.value.load !== 'function'
      || typeof storeResource.value.commit !== 'function') {
      await closeOne(storeResource, null);
      fail('m4_native_phase_store_factory_result_invalid');
    }
    resources.push(storeResource);
    const store = storeResource.value;
    let receipts;
    try { receipts = verifiedReceipts(await store.load(), plan, receiptKeyDocument); }
    catch (error) {
      if (error?.code?.startsWith?.('m4_native_phase_')) throw error;
      fail('m4_native_phase_store_read_failed');
    }
    let totalCalls = 0;
    for (let ordinal = receipts.length; ordinal < plan.childPlans.length; ordinal += 1) {
      const item = serial.catalog.shards[ordinal];
      const child = plan.childPlans[ordinal];
      let shardCalls = 0;
      let complete = false;
      while (!complete) {
        if (shardCalls >= serial.maxCallsPerInvocationPerShard
          || totalCalls >= serial.maxCallsPerInvocationTotal) {
          fail('m4_native_phase_bound_exhausted');
        }
        await leaseCall(lease.heartbeat, leaseContext, 'm4_native_phase_lease_heartbeat_failed');
        const shardResource = await callResourceFactory(dependencies.factories.shard, {
          ordinal,
          runId: child.runId,
          authorityDigest: child.authorityDigest,
          confirmationDigest: child.confirmationDigest,
        }, 'm4_native_phase_shard_factory_failed');
        let shardPrimary = null;
        let output;
        try {
          const runtime = batchRuntime(shardResource.value,
            'm4_native_phase_shard_factory_result_invalid');
          output = verifyM4NativePausedPhaseChildResult(await runM4NativePausedBatch({
            gateInput: runtime.gateInput,
            maxEvents: item.maxEvents,
            authority: item.authority,
            legacyCompletion: serial.prerequisite,
            registryAuthorityDigest: serial.registryAuthorityDigest,
            sourceTagAuthorityDigest: serial.sourceTagAuthorityDigest,
            confirmedPlanDigest: child.confirmationDigest,
            reader: runtime.reader,
            projectionIdentityResolver: runtime.projectionIdentityResolver,
            derivationKey: runtime.derivationKey,
            derivationKeyId: runtime.derivationKeyId,
            verifyPauseEvidence: runtime.verifyPauseEvidence,
            verifyLegacyCompletion: runtime.verifyLegacyCompletion,
            integrityFor: runtime.integrityFor,
            factories: runtime.factories,
          }), { ...child,
            registryAuthorityDigest: serial.registryAuthorityDigest,
            sourceTagAuthorityDigest: serial.sourceTagAuthorityDigest,
          });
        } catch (error) {
          shardPrimary = error;
          throw error;
        } finally {
          await closeOne(shardResource, shardPrimary);
        }
        shardCalls += 1;
        totalCalls += 1;
        if (!output.complete && output.processed === 0) fail('m4_native_phase_no_progress');
        if (output.complete) {
          const receipt = receiptFor(ordinal, child, output, receiptKeyDocument);
          let committed;
          try { committed = await store.commit(receipt); }
          catch (error) {
            if (error?.code?.startsWith?.('m4_native_phase_')) throw error;
            fail('m4_native_phase_store_commit_failed');
          }
          if (!same(verifyReceipt(committed, child, ordinal, receiptKeyDocument), receipt)) {
            fail('m4_native_phase_store_ack_mismatch');
          }
          let reloaded;
          try { reloaded = verifiedReceipts(await store.load(), plan, receiptKeyDocument); }
          catch (error) {
            if (error?.code?.startsWith?.('m4_native_phase_')) throw error;
            fail('m4_native_phase_store_read_failed');
          }
          if (reloaded.length !== ordinal + 1 || !same(reloaded[ordinal], receipt)) {
            fail('m4_native_phase_store_ack_mismatch');
          }
          receipts = reloaded;
          complete = true;
        }
      }
    }

    if (receipts.length !== plan.childPlans.length) fail('m4_native_phase_receipts_incomplete');
    await leaseCall(lease.heartbeat, leaseContext, 'm4_native_phase_lease_heartbeat_failed');
    await currentPrerequisites(dependencies, serial);
    await leaseCall(lease.heartbeat, leaseContext, 'm4_native_phase_lease_heartbeat_failed');
    const receiptDigest = digest(receipts);
    const completionResource = await callResourceFactory(dependencies.factories.completionKey, {
      runId: plan.runId,
      catalogDigest: plan.catalogDigest,
      receiptDigest,
    }, 'm4_native_phase_completion_key_factory_failed');
    resources.push(completionResource);
    const completion = completionFor(plan, receipts, completionResource.value);
    return {
      schema: RESULT_SCHEMA,
      operation: 'run',
      runId: plan.runId,
      complete: true,
      receipts: clone(receipts, 'm4_native_phase_result_invalid'),
      completion,
    };
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    let cleanupFailed = false;
    for (const resource of [...resources].reverse()) {
      try { await resource.close?.(); } catch { cleanupFailed = true; }
    }
    if (primary === null && cleanupFailed) fail('m4_native_phase_cleanup_failed');
  }
}

export { M4NativePausedPhaseStore };
