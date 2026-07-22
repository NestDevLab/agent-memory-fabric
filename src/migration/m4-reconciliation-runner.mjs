import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4BackfillGate } from './m4-backfill-gate.mjs';
import { verifyM4LegacyGroupReplayCompletion } from './m4-legacy-group-replay-batch-runner.mjs';
import { verifyM4NativePausedPhaseCompletion } from './m4-native-paused-phase-orchestrator.mjs';
import { createM4ReconciliationManifest } from './m4-reconciliation-manifest.mjs';
import {
  M4_MAX_MISMATCH_SAMPLES,
  M4_MAX_VISITED_EVENTS,
  reconcileM4,
} from './m4-reconciliation-reader.mjs';

const PLAN_SCHEMA = 'amf.m4-reconciliation-plan/v1';
const RESULT_SCHEMA = 'amf.m4-reconciliation-run-result/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function same(left, right) { try { return canonicalJson(left) === canonicalJson(right); } catch { return false; } }
function digest(value) { return `sha256:${crypto.createHash('sha256')
  .update(canonicalJson(value), 'utf8').digest('hex')}`; }

function keyDocument(value, code) {
  let key = null;
  try {
    if (!exact(value, ['schema', 'keyId', 'key'])) fail(code);
    const schema = value.schema;
    const keyId = value.keyId;
    const encodedKey = value.key;
    if (schema !== KEY_SCHEMA || typeof keyId !== 'string' || !ID.test(keyId)
      || typeof encodedKey !== 'string' || !BASE64.test(encodedKey)) fail(code);
    key = Buffer.from(encodedKey, 'base64');
    if (key.length < 32 || key.length > 64 || key.toString('base64') !== encodedKey) fail(code);
    return { document: { schema, keyId, key: encodedKey }, keyId, key };
  } catch (error) {
    key?.fill(0);
    if (error?.code === code) throw error;
    fail(code);
  }
}

function equivalentHmacSha256Keys(left, right) {
  const leftBlock = Buffer.alloc(64); const rightBlock = Buffer.alloc(64);
  try { left.copy(leftBlock); right.copy(rightBlock); return crypto.timingSafeEqual(leftBlock, rightBlock); }
  finally { leftBlock.fill(0); rightBlock.fill(0); }
}

function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function staticEvidence(value, code) {
  if (!exact(value, ['pausedInterval', 'replayQueues', 'sourceCheckpoints'])) fail(code);
  const map = (candidate, names) => {
    if (!exact(candidate, names)) fail(code);
    return Object.fromEntries(names.map(name => [name, checkpoint(candidate[name], code)]));
  };
  return {
    pausedInterval: map(value.pausedInterval, ['start', 'end']),
    replayQueues: map(value.replayQueues, ['pendingOutbox', 'acknowledgements', 'deadLetters']),
    sourceCheckpoints: map(value.sourceCheckpoints,
      ['collectorCursor', 'sourceCheckpoint', 'nativeTranscriptAuthority']),
  };
}

function gateEvidenceDigest(gate) {
  return digest({ schema: 'amf.m4-native-paused-phase-gate-evidence/v1',
    pauseEvidence: gate.pauseEvidence, rollbackEvidence: gate.rollbackEvidence,
    sourceCheckpoint: gate.sourceCheckpoint, targetCheckpoint: gate.targetCheckpoint });
}

function serialRequest(value, code) {
  const keys = ['gateInput', 'legacyCompletion', 'legacyCompletionKeyDocument',
    'nativePhaseCompletion', 'nativePhaseCompletionKeyDocument', 'sourceEvidence',
    'targetEvidence', 'maxVisitedEvents', 'maxMismatchSamples', 'manifestId', 'revision',
    'reconciliationKeyId'];
  try {
    if (!exact(value, keys)) fail(code);
    const gateInput = clone(value.gateInput, code);
    const gate = verifyM4BackfillGate(gateInput);
    if (gate.phase !== 'paused-native') fail('m4_reconciliation_runner_gate_invalid');
    const legacyKey = keyDocument(value.legacyCompletionKeyDocument,
      'm4_reconciliation_runner_legacy_key_invalid');
    const nativeKey = keyDocument(value.nativePhaseCompletionKeyDocument,
      'm4_reconciliation_runner_native_key_invalid');
    let legacy; let native;
    try {
      legacy = verifyM4LegacyGroupReplayCompletion(clone(value.legacyCompletion, code), legacyKey.document);
      native = verifyM4NativePausedPhaseCompletion(clone(value.nativePhaseCompletion, code), nativeKey.document);
      if (native.legacyCompletionDigest !== digest(legacy)
        || native.gateEvidenceDigest !== gateEvidenceDigest(gate)) {
        fail('m4_reconciliation_runner_prerequisite_mismatch');
      }
      if (legacyKey.keyId === nativeKey.keyId
        || equivalentHmacSha256Keys(legacyKey.key, nativeKey.key)) {
        fail('m4_reconciliation_runner_key_separation_invalid');
      }
      if (typeof value.reconciliationKeyId !== 'string' || !ID.test(value.reconciliationKeyId)
        || [legacyKey.keyId, nativeKey.keyId].includes(value.reconciliationKeyId)
        || typeof value.manifestId !== 'string' || !ID.test(value.manifestId)
        || !Number.isSafeInteger(value.revision) || value.revision < 1
        || !Number.isSafeInteger(value.maxVisitedEvents) || value.maxVisitedEvents < 1
        || value.maxVisitedEvents > M4_MAX_VISITED_EVENTS
        || !Number.isSafeInteger(value.maxMismatchSamples) || value.maxMismatchSamples < 0
        || value.maxMismatchSamples > M4_MAX_MISMATCH_SAMPLES) {
        fail('m4_reconciliation_runner_plan_input_invalid');
      }
      return { gateInput, gate, legacy, legacyKeyDocument: legacyKey.document,
        native, nativeKeyDocument: nativeKey.document,
        sourceEvidence: staticEvidence(clone(value.sourceEvidence, code), code),
        targetEvidence: staticEvidence(clone(value.targetEvidence, code), code),
        maxVisitedEvents: value.maxVisitedEvents, maxMismatchSamples: value.maxMismatchSamples,
        manifestId: value.manifestId, revision: value.revision,
        reconciliationKeyId: value.reconciliationKeyId };
    } finally { legacyKey.key.fill(0); nativeKey.key.fill(0); }
  } catch (error) {
    if (error?.code?.startsWith?.('m4_reconciliation_runner_')) throw error;
    fail(code);
  }
}

function planFor(serial) {
  const identity = {
    gateEvidenceDigest: gateEvidenceDigest(serial.gate),
    legacyCompletionDigest: digest(serial.legacy),
    nativePhaseCompletionDigest: digest(serial.native),
    sourceEvidenceDigest: digest(serial.sourceEvidence),
    targetEvidenceDigest: digest(serial.targetEvidence),
    maxVisitedEvents: serial.maxVisitedEvents,
    maxMismatchSamples: serial.maxMismatchSamples,
    manifestId: serial.manifestId,
    revision: serial.revision,
    reconciliationKeyId: serial.reconciliationKeyId,
  };
  const runId = `m4-reconcile-${digest(['amf.m4-reconciliation-run/v1', identity]).slice(7)}`;
  return { schema: PLAN_SCHEMA, operation: 'plan', runId, ...identity,
    confirmationDigest: digest({ schema: 'amf.m4-reconciliation-confirmation/v1', runId, ...identity }) };
}

export async function planM4Reconciliation(input = {}) {
  return clone(planFor(serialRequest(input, 'm4_reconciliation_runner_plan_input_invalid')),
    'm4_reconciliation_runner_plan_invalid');
}

async function currentPrerequisites(dependencies, serial) {
  let legacy; let native;
  try {
    legacy = verifyM4LegacyGroupReplayCompletion(await dependencies.verifyCurrentLegacyCompletion(),
      serial.legacyKeyDocument);
    native = verifyM4NativePausedPhaseCompletion(await dependencies.verifyCurrentNativePhaseCompletion(),
      serial.nativeKeyDocument);
  } catch { fail('m4_reconciliation_runner_prerequisite_unverified'); }
  if (!same(legacy, serial.legacy) || !same(native, serial.native)) {
    fail('m4_reconciliation_runner_prerequisite_changed');
  }
}

function runtimeDependencies(input) {
  try {
    const verifyCurrentLegacyCompletion = input.verifyCurrentLegacyCompletion;
    const verifyCurrentNativePhaseCompletion = input.verifyCurrentNativePhaseCompletion;
    const factories = input.factories;
    if (typeof verifyCurrentLegacyCompletion !== 'function'
      || typeof verifyCurrentNativePhaseCompletion !== 'function'
      || !exact(factories, ['source', 'target', 'reconciliationKey'])
      || Object.values(factories).some(value => typeof value !== 'function')) {
      fail('m4_reconciliation_runner_dependency_invalid');
    }
    return { verifyCurrentLegacyCompletion, verifyCurrentNativePhaseCompletion, factories };
  } catch (error) {
    if (error?.code === 'm4_reconciliation_runner_dependency_invalid') throw error;
    fail('m4_reconciliation_runner_dependency_invalid');
  }
}

async function open(factory, context, code) {
  let raw;
  try { raw = await factory(context); } catch { fail(code); }
  try {
    if (!exact(raw, ['value', 'close']) || (raw.close !== null && typeof raw.close !== 'function')) fail(code);
    return { value: raw.value, close: raw.close === null ? null : raw.close.bind(raw) };
  } catch {
    try { if (typeof raw?.close === 'function') await raw.close(); } catch { /* keep factory result error */ }
    fail(code);
  }
}

function side(value, expectedEvidence, code) {
  try {
    if (!exact(value, ['events', 'evidence']) || typeof value.events?.[Symbol.asyncIterator] !== 'function') fail(code);
    const evidence = staticEvidence(clone(value.evidence, code), code);
    if (!same(evidence, expectedEvidence)) fail('m4_reconciliation_runner_evidence_mismatch');
    return { events: value.events, evidence };
  } catch (error) {
    if (error?.code === 'm4_reconciliation_runner_evidence_mismatch') throw error;
    fail(code);
  }
}

async function closeResources(resources, primary) {
  let failed = false;
  for (const resource of [...resources].reverse()) {
    try { await resource.close?.(); } catch { failed = true; }
  }
  if (!primary && failed) fail('m4_reconciliation_runner_cleanup_failed');
}

function ensureKeySeparation(reconciliation, serial) {
  const legacy = keyDocument(serial.legacyKeyDocument, 'm4_reconciliation_runner_legacy_key_invalid');
  let native = null;
  try {
    native = keyDocument(serial.nativeKeyDocument, 'm4_reconciliation_runner_native_key_invalid');
    if (reconciliation.keyId !== serial.reconciliationKeyId
      || equivalentHmacSha256Keys(reconciliation.key, legacy.key)
      || equivalentHmacSha256Keys(reconciliation.key, native.key)) {
      fail('m4_reconciliation_runner_key_separation_invalid');
    }
  } finally { legacy.key.fill(0); native?.key.fill(0); }
}

function runSerial(input) {
  const serialKeys = ['gateInput', 'legacyCompletion', 'legacyCompletionKeyDocument',
    'nativePhaseCompletion', 'nativePhaseCompletionKeyDocument', 'sourceEvidence',
    'targetEvidence', 'maxVisitedEvents', 'maxMismatchSamples', 'manifestId', 'revision',
    'reconciliationKeyId'];
  try {
    return serialRequest(Object.fromEntries(serialKeys.map(key => [key, input[key]])),
      'm4_reconciliation_runner_run_input_invalid');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_reconciliation_runner_')) throw error;
    fail('m4_reconciliation_runner_run_input_invalid');
  }
}

export async function runM4Reconciliation(input = {}) {
  const keys = ['gateInput', 'legacyCompletion', 'legacyCompletionKeyDocument',
    'nativePhaseCompletion', 'nativePhaseCompletionKeyDocument', 'sourceEvidence',
    'targetEvidence', 'maxVisitedEvents', 'maxMismatchSamples', 'manifestId', 'revision',
    'reconciliationKeyId', 'confirmedPlanDigest', 'verifyCurrentLegacyCompletion',
    'verifyCurrentNativePhaseCompletion', 'factories'];
  if (!exact(input, keys)) fail('m4_reconciliation_runner_run_input_invalid');
  const serial = runSerial(input); const plan = planFor(serial);
  let confirmedPlanDigest;
  try { confirmedPlanDigest = input.confirmedPlanDigest; }
  catch { fail('m4_reconciliation_runner_run_input_invalid'); }
  if (typeof confirmedPlanDigest !== 'string'
    || confirmedPlanDigest !== plan.confirmationDigest) {
    fail('m4_reconciliation_runner_confirmation_invalid');
  }
  const dependencies = runtimeDependencies(input);
  await currentPrerequisites(dependencies, serial);
  const resources = []; let primary = null;
  try {
    const sourceResource = await open(dependencies.factories.source,
      { runId: plan.runId, planDigest: plan.confirmationDigest },
      'm4_reconciliation_runner_source_factory_failed');
    resources.push(sourceResource);
    const source = side(sourceResource.value, serial.sourceEvidence,
      'm4_reconciliation_runner_source_invalid');
    const targetResource = await open(dependencies.factories.target,
      { runId: plan.runId, planDigest: plan.confirmationDigest },
      'm4_reconciliation_runner_target_factory_failed');
    resources.push(targetResource);
    const target = side(targetResource.value, serial.targetEvidence,
      'm4_reconciliation_runner_target_invalid');
    let report;
    try {
      report = await reconcileM4({ source: source.events, target: target.events,
        sourceEvidence: source.evidence, targetEvidence: target.evidence,
        maxVisitedEvents: serial.maxVisitedEvents,
        maxMismatchSamples: serial.maxMismatchSamples });
    } catch (error) {
      if (error?.code?.startsWith?.('m4_reconciliation_')) throw error;
      fail('m4_reconciliation_runner_compare_failed');
    }
    await currentPrerequisites(dependencies, serial);
    const keyResource = await open(dependencies.factories.reconciliationKey,
      { runId: plan.runId, reportBinding: report.dimensionsBinding },
      'm4_reconciliation_runner_key_factory_failed');
    resources.push(keyResource);
    const signing = keyDocument(keyResource.value, 'm4_reconciliation_runner_key_invalid');
    let manifest;
    try {
      ensureKeySeparation(signing, serial);
      manifest = createM4ReconciliationManifest({ manifestId: serial.manifestId,
        revision: serial.revision, report,
        pauseManifest: serial.gateInput.pauseManifest,
        pauseKeyDocument: serial.gateInput.pauseKeyDocument,
        rollbackManifest: serial.gateInput.rollbackManifest,
        rollbackKeyDocument: serial.gateInput.rollbackKeyDocument,
        reconciliationKeyDocument: signing.document });
    } finally { signing.key.fill(0); }
    return { schema: RESULT_SCHEMA, planDigest: plan.confirmationDigest, report, manifest };
  } catch (error) { primary = error; throw error; }
  finally { await closeResources(resources, primary); }
}
