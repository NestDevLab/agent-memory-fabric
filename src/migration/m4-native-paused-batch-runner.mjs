import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4NativePausedIntervalSource } from './m4-native-paused-interval-source.mjs';
import { planM4V2Backfill, runM4V2Backfill } from './m4-v2-backfill-runner.mjs';

const AUTHORITY_SCHEMA = 'amf.m4-native-paused-interval-authority/v1';
const LEGACY_COMPLETION_SCHEMA = 'amf.m4-legacy-group-replay-completion/v1';
const PLAN_SCHEMA = 'amf.m4-native-paused-batch-plan/v1';
const RESULT_SCHEMA = 'amf.m4-native-paused-batch-result/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const SOURCE_BINDING = /^hmac-sha256:source-v1:[a-f0-9]{64}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }

function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function evidence(value, code) {
  if (!exact(value, ['manifestId', 'digest', 'signature']) || typeof value.manifestId !== 'string'
    || !ID.test(value.manifestId) || typeof value.digest !== 'string' || !DIGEST.test(value.digest)
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

function authority(value, code = 'm4_native_batch_authority_invalid') {
  if (!exact(value, ['schema', 'pauseEvidence', 'source', 'sourceBinding', 'interval', 'initialCheckpoint'])
    || value.schema !== AUTHORITY_SCHEMA || typeof value.sourceBinding !== 'string'
    || !SOURCE_BINDING.test(value.sourceBinding)) fail(code);
  return { schema: AUTHORITY_SCHEMA, pauseEvidence: evidence(value.pauseEvidence, code),
    source: checkpoint(value.source, code), sourceBinding: value.sourceBinding,
    interval: interval(value.interval, code), initialCheckpoint: checkpoint(value.initialCheckpoint, code) };
}

function legacyCompletion(value, code = 'm4_native_batch_legacy_completion_invalid') {
  if (!exact(value, ['schema', 'state', 'authorityDigest', 'checkpoint', 'evidence'])
    || value.schema !== LEGACY_COMPLETION_SCHEMA || value.state !== 'complete'
    || typeof value.authorityDigest !== 'string' || !DIGEST.test(value.authorityDigest)) fail(code);
  return { schema: LEGACY_COMPLETION_SCHEMA, state: 'complete', authorityDigest: value.authorityDigest,
    checkpoint: checkpoint(value.checkpoint, code), evidence: evidence(value.evidence, code) };
}

export function deriveM4NativePausedRunId(value, prerequisite) {
  const accepted = authority(value);
  const completed = legacyCompletion(prerequisite);
  return `m4-native-${digest(['amf.m4-native-paused-batch/run-id/v1', accepted, completed]).slice(7)}`;
}

function request(value, run = false) {
  const keys = run
    ? ['gateInput', 'maxEvents', 'authority', 'legacyCompletion', 'confirmedPlanDigest', 'reader', 'derivationKey',
      'derivationKeyId', 'verifyPauseEvidence', 'verifyLegacyCompletion', 'integrityFor', 'factories']
    : ['gateInput', 'maxEvents', 'authority', 'legacyCompletion'];
  const code = run ? 'm4_native_batch_run_input_invalid' : 'm4_native_batch_plan_input_invalid';
  try {
    if (!exact(value, keys)) fail(code);
    const confirmedPlanDigest = run ? value.confirmedPlanDigest : null;
    if (run && (typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest))) fail(code);
    return { gateInput: clone(value.gateInput, code), maxEvents: value.maxEvents,
      authority: authority(clone(value.authority, code), code),
      legacyCompletion: legacyCompletion(clone(value.legacyCompletion, code)),
      ...(run ? { confirmedPlanDigest, runtimeInput: value } : {}) };
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}

async function prepared(value) {
  let basePlan;
  try { basePlan = await planM4V2Backfill({ gateInput: value.gateInput, maxEvents: value.maxEvents }); }
  catch { fail('m4_native_batch_gate_invalid'); }
  let signedNativeAuthority;
  try { signedNativeAuthority = checkpoint(value.gateInput.pauseManifest.pause.nativeTranscriptAuthority,
    'm4_native_batch_gate_mismatch'); }
  catch { fail('m4_native_batch_gate_mismatch'); }
  if (basePlan.phase !== 'paused-native' || !same(basePlan.pauseEvidence, value.authority.pauseEvidence)
    || !same(signedNativeAuthority, value.authority.source)
    || !same(basePlan.sourceCheckpoint, value.authority.initialCheckpoint)
    || basePlan.runId !== deriveM4NativePausedRunId(value.authority, value.legacyCompletion)) fail('m4_native_batch_gate_mismatch');
  const authorityDigest = digest(value.authority);
  const legacyCompletionDigest = digest(value.legacyCompletion);
  const confirmationDigest = digest({ schema: 'amf.m4-native-paused-batch-confirmation/v1',
    basePlanDigest: basePlan.planDigest, authorityDigest, legacyCompletionDigest });
  const plan = { schema: PLAN_SCHEMA, operation: 'plan', runId: basePlan.runId, phase: 'paused-native',
    maxEvents: basePlan.maxEvents, authorityDigest, legacyCompletionDigest, confirmationDigest };
  return { basePlan, plan };
}

function runtime(value) {
  try {
    const reader = value.reader;
    const open = object(reader) ? reader.open : null;
    const derivationKey = value.derivationKey;
    const derivationKeyId = value.derivationKeyId;
    const verifyPauseEvidence = value.verifyPauseEvidence;
    const verifyLegacyCompletion = value.verifyLegacyCompletion;
    const integrityFor = value.integrityFor;
    const rawFactories = value.factories;
    const factoryNames = ['lease', 'outbox', 'archive', 'checkpointStore'];
    if (typeof open !== 'function' || !Buffer.isBuffer(derivationKey) || derivationKey.length !== 32
      || typeof derivationKeyId !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(derivationKeyId)
      || typeof verifyPauseEvidence !== 'function' || typeof verifyLegacyCompletion !== 'function'
      || typeof integrityFor !== 'function' || !exact(rawFactories, factoryNames)) {
      fail('m4_native_batch_dependency_invalid');
    }
    const factories = {};
    for (const name of factoryNames) {
      const factory = rawFactories[name];
      if (typeof factory !== 'function') fail('m4_native_batch_dependency_invalid');
      factories[name] = factory;
    }
    return { reader: { open: open.bind(reader) }, derivationKey: Buffer.from(derivationKey),
      derivationKeyId, verifyPauseEvidence, verifyLegacyCompletion, integrityFor, factories };
  } catch (error) {
    if (error?.code === 'm4_native_batch_dependency_invalid') throw error;
    fail('m4_native_batch_dependency_invalid');
  }
}

async function preflightLegacy(verifyLegacyCompletion, accepted) {
  let value;
  try { value = await verifyLegacyCompletion(); }
  catch { fail('m4_native_batch_legacy_unverified'); }
  let safe;
  try { safe = legacyCompletion(clone(value, 'm4_native_batch_legacy_unverified'),
    'm4_native_batch_legacy_unverified'); }
  catch { fail('m4_native_batch_legacy_unverified'); }
  if (!same(safe, accepted)) fail('m4_native_batch_legacy_mismatch');
}

async function preflightPause(verifyPauseEvidence, accepted) {
  let value;
  try { value = await verifyPauseEvidence(); }
  catch { fail('m4_native_batch_pause_unverified'); }
  const snapshot = clone(value, 'm4_native_batch_pause_unverified');
  if (!exact(snapshot, ['pauseEvidence', 'nativeTranscriptAuthority', 'sourceCheckpoint'])) {
    fail('m4_native_batch_pause_unverified');
  }
  let safe;
  try { safe = { pauseEvidence: evidence(snapshot.pauseEvidence, 'm4_native_batch_pause_unverified'),
    nativeTranscriptAuthority: checkpoint(snapshot.nativeTranscriptAuthority, 'm4_native_batch_pause_unverified'),
    sourceCheckpoint: checkpoint(snapshot.sourceCheckpoint, 'm4_native_batch_pause_unverified') }; }
  catch { fail('m4_native_batch_pause_unverified'); }
  if (!same(safe.pauseEvidence, accepted.pauseEvidence)
    || !same(safe.nativeTranscriptAuthority, accepted.source)
    || !same(safe.sourceCheckpoint, accepted.initialCheckpoint)) fail('m4_native_batch_pause_mismatch');
}

function copyResult(value, plan) {
  if (!exact(value, ['schema', 'runId', 'phase', 'processed', 'duplicates', 'lastCheckpoint', 'complete'])
    || value.schema !== 'amf.m4-backfill-result/v1' || value.runId !== plan.runId
    || value.phase !== 'paused-native' || !Number.isSafeInteger(value.processed) || value.processed < 0
    || !Number.isSafeInteger(value.duplicates) || value.duplicates < 0 || value.duplicates > value.processed
    || typeof value.complete !== 'boolean') fail('m4_native_batch_result_invalid');
  return { schema: RESULT_SCHEMA, operation: 'run', runId: value.runId, phase: 'paused-native',
    authorityDigest: plan.authorityDigest, legacyCompletionDigest: plan.legacyCompletionDigest,
    processed: value.processed, duplicates: value.duplicates,
    lastCheckpoint: checkpoint(value.lastCheckpoint, 'm4_native_batch_result_invalid'), complete: value.complete };
}

export async function planM4NativePausedBatch(input = {}) {
  const accepted = request(input);
  return clone((await prepared(accepted)).plan, 'm4_native_batch_plan_invalid');
}

export async function runM4NativePausedBatch(input = {}) {
  const accepted = request(input, true);
  const planned = await prepared(accepted);
  if (accepted.confirmedPlanDigest !== planned.plan.confirmationDigest) {
    fail('m4_native_batch_confirmation_invalid');
  }
  const dependencies = runtime(accepted.runtimeInput);
  let source = null;
  try {
    await preflightLegacy(dependencies.verifyLegacyCompletion, accepted.legacyCompletion);
    await preflightPause(dependencies.verifyPauseEvidence, accepted.authority);
    source = createM4NativePausedIntervalSource({ authority: accepted.authority,
      derivationKey: dependencies.derivationKey, derivationKeyId: dependencies.derivationKeyId,
      verifyPauseEvidence: dependencies.verifyPauseEvidence, reader: dependencies.reader,
      integrityFor: dependencies.integrityFor });
    let result;
    try {
      result = await runM4V2Backfill({ gateInput: accepted.gateInput, maxEvents: accepted.maxEvents,
        confirmedPlanDigest: planned.basePlan.planDigest,
        factories: { ...dependencies.factories, source: async () => source } });
    } catch (error) {
      if (error?.code?.startsWith?.('m4_')) throw error;
      fail('m4_native_batch_execution_failed');
    }
    return copyResult(result, planned.plan);
  } finally {
    try { await source?.close?.(); } finally { dependencies.derivationKey.fill(0); }
  }
}
