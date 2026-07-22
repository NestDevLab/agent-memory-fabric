import crypto from 'node:crypto';

import { timestampWithin, verifyM4SelectorScopeSnapshot } from '../migration/m4-authority-snapshots.mjs';
import { createM4CutoverAuthorization, verifyM4CutoverAuthorization } from '../migration/m4-cutover-authorization.mjs';
import { createM4CutoverCanaryManifest, verifyM4CutoverCanaryManifest } from '../migration/m4-cutover-canary.mjs';
import { verifyM4ReconciliationManifest } from '../migration/m4-reconciliation-manifest.mjs';
import { planM4Reconciliation, runM4Reconciliation } from '../migration/m4-reconciliation-runner.mjs';
import { m4ReconciliationArchiveRevisionEvidence, verifyM4ReconciliationArchiveRevision,
  verifyM4ReconciliationSnapshot } from '../migration/m4-reconciliation-snapshot.mjs';
import { createM4RecoveryPairManifest, verifyM4RecoveryPairManifest } from '../migration/m4-recovery-pair.mjs';
import { openM4ReconciliationSnapshot } from './m4-reconciliation-snapshots.mjs';
import { openPrivateM4SnapshotBundle } from './private-snapshot-bundle.mjs';
import {
  artifactPath,
  canonicalDigest,
  privateFileDigest,
  readPrivateJson,
  readPrivateJsonWithDigest,
  validateArtifactRoot,
  writePrivateArtifact,
} from './private-artifacts.mjs';

const CONFIG_SCHEMAS = Object.freeze({
  recovery: 'amf.m4-live-recovery-operator/v1',
  reconciliation: 'amf.m4-live-reconciliation-operator/v1',
  canary: 'amf.m4-live-canary-operator/v1',
  authorization: 'amf.m4-live-authorization-operator/v1',
});
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function validIdentity(config, schema, keys, code) {
  if (!exact(config, keys) || config.schema !== schema || typeof config.manifestId !== 'string'
    || !ID.test(config.manifestId) || !Number.isSafeInteger(config.revision) || config.revision < 1) fail(code);
  validateArtifactRoot(config.artifactRoot, code);
  return config;
}
function reference(path, code) {
  return readPrivateJsonWithDigest(path, code);
}
function independentKeyDocuments(documents, code) {
  const loaded = [];
  try {
    for (const document of documents) {
      if (!plain(document) || typeof document.keyId !== 'string' || typeof document.key !== 'string') fail(code);
      const key = Buffer.from(document.key, 'base64'); if (key.length < 32 || key.length > 64 || key.toString('base64') !== document.key) fail(code);
      const effective = Buffer.alloc(64); key.copy(effective); key.fill(0);
      if (loaded.some(item => item.keyId === document.keyId
        || crypto.timingSafeEqual(item.effective, effective))) { effective.fill(0); fail(code); }
      loaded.push({ keyId: document.keyId, effective });
    }
  } finally { for (const item of loaded) item.effective.fill(0); }
}
function outputAvailable(root, stage, manifestId, revision, code) {
  const target = artifactPath(root, stage, manifestId, revision);
  try {
    privateFileDigest(target, code);
    fail('m4_live_operator_artifact_exists');
  } catch (error) {
    if (error?.code === 'm4_live_operator_artifact_exists') throw error;
    if (error?.code !== code) throw error;
  }
}
function planFor(stage, config, inputDigests, candidate) {
  const binding = { schema: 'amf.m4-live-plan-binding/v1', stage, manifestId: config.manifestId,
    revision: config.revision, artifactRoot: config.artifactRoot, inputDigests,
    candidateDigest: candidate.integrity.payloadDigest };
  return { schema: 'amf.m4-live-plan/v1', operation: 'plan', stage, manifestId: config.manifestId,
    revision: config.revision, state: candidate.state ?? candidate.reconciliation?.state ?? 'complete',
    confirmationDigest: canonicalDigest(binding) };
}
function reconciliationPlanFor(config, inputDigests, innerPlan) {
  const binding = { schema: 'amf.m4-live-reconciliation-plan-binding/v1', stage: 'reconciliation',
    manifestId: config.manifestId, revision: config.revision, artifactRoot: config.artifactRoot,
    inputDigests, runnerPlanDigest: innerPlan.confirmationDigest };
  return { schema: 'amf.m4-live-plan/v1', operation: 'plan', stage: 'reconciliation',
    manifestId: config.manifestId, revision: config.revision, state: 'planned',
    confirmationDigest: canonicalDigest(binding) };
}
function assertReconciliationRevisionsCurrent(sourceRevision, targetRevision, clock) {
  const now = currentIso(clock);
  if (!timestampWithin(now, sourceRevision.observedAt, sourceRevision.validThrough)
    || !timestampWithin(now, targetRevision.observedAt, targetRevision.validThrough)) {
    fail('m4_live_operator_reconciliation_revision_stale');
  }
}
function resultFor(stage, candidate, plan) {
  return { schema: 'amf.m4-live-result/v1', operation: 'run', stage,
    manifestId: candidate.manifestId, revision: candidate.revision,
    state: candidate.state ?? candidate.reconciliation?.state ?? 'complete',
    planDigest: plan.confirmationDigest, payloadDigest: candidate.integrity.payloadDigest };
}
function prepareRecovery(configPath) {
  const code = 'm4_live_operator_recovery_config_invalid';
  const configReference = readPrivateJsonWithDigest(configPath, code);
  const config = validIdentity(configReference.value, CONFIG_SCHEMAS.recovery,
    ['schema', 'artifactRoot', 'manifestId', 'revision', 'reconciliationManifestPath',
      'reconciliationKeyPath', 'legacyRecoveryRecordPath', 'v3RecoveryRecordPath', 'recoveryKeyPath'], code);
  const reconciliation = reference(config.reconciliationManifestPath, code);
  const reconciliationKey = reference(config.reconciliationKeyPath, code);
  const legacy = reference(config.legacyRecoveryRecordPath, code);
  const v3 = reference(config.v3RecoveryRecordPath, code);
  const recoveryKey = reference(config.recoveryKeyPath, code);
  let candidate;
  try {
    candidate = createM4RecoveryPairManifest({ manifestId: config.manifestId, revision: config.revision,
      reconciliationManifest: reconciliation.value, reconciliationKeyDocument: reconciliationKey.value,
      legacyRecord: legacy.value, v3Record: v3.value, recoveryKeyDocument: recoveryKey.value });
    verifyM4RecoveryPairManifest(candidate, recoveryKey.value);
  } catch { fail('m4_live_operator_recovery_evidence_invalid'); }
  const inputDigests = { config: configReference.digest, reconciliation: reconciliation.digest,
    reconciliationKey: reconciliationKey.digest, legacy: legacy.digest, v3: v3.digest, recoveryKey: recoveryKey.digest };
  return { config, candidate, plan: planFor('recovery', config, inputDigests, candidate) };
}
async function prepareReconciliation(configPath, clock) {
  const code = 'm4_live_operator_reconciliation_config_invalid';
  const configReference = readPrivateJsonWithDigest(configPath, code);
  const config = validIdentity(configReference.value, CONFIG_SCHEMAS.reconciliation,
    ['schema', 'artifactRoot', 'manifestId', 'revision', 'gateInputPath', 'legacyCompletionPath',
      'legacyCompletionKeyPath', 'nativePhaseCompletionPath', 'nativePhaseCompletionKeyPath',
      'sourceStaticEvidencePath', 'targetStaticEvidencePath', 'sourceEventsPath', 'targetEventsPath',
      'sourceSnapshotManifestPath', 'sourceSnapshotTrustAnchorPath', 'targetSnapshotManifestPath',
      'targetSnapshotTrustAnchorPath', 'sourceRevisionManifestPath', 'sourceRevisionTrustAnchorPath',
      'targetRevisionManifestPath', 'targetRevisionTrustAnchorPath', 'reconciliationKeyPath',
      'maxVisitedEvents', 'maxMismatchSamples'], code);
  const refs = Object.fromEntries([
    ['gateInput', config.gateInputPath], ['legacyCompletion', config.legacyCompletionPath],
    ['legacyCompletionKey', config.legacyCompletionKeyPath], ['nativePhaseCompletion', config.nativePhaseCompletionPath],
    ['nativePhaseCompletionKey', config.nativePhaseCompletionKeyPath], ['sourceEvidence', config.sourceStaticEvidencePath],
    ['targetEvidence', config.targetStaticEvidencePath], ['reconciliationKey', config.reconciliationKeyPath],
    ['sourceSnapshotManifest', config.sourceSnapshotManifestPath], ['sourceSnapshotKey', config.sourceSnapshotTrustAnchorPath],
    ['targetSnapshotManifest', config.targetSnapshotManifestPath], ['targetSnapshotKey', config.targetSnapshotTrustAnchorPath],
    ['sourceRevisionManifest', config.sourceRevisionManifestPath], ['sourceRevisionKey', config.sourceRevisionTrustAnchorPath],
    ['targetRevisionManifest', config.targetRevisionManifestPath], ['targetRevisionKey', config.targetRevisionTrustAnchorPath],
  ].map(([name, target]) => [name, reference(target, code)]));
  let sourceBundle; let targetBundle;
  try {
    sourceBundle = openPrivateM4SnapshotBundle({ eventsPath: config.sourceEventsPath,
      revisionPath: config.sourceRevisionManifestPath, snapshotPath: config.sourceSnapshotManifestPath });
    targetBundle = openPrivateM4SnapshotBundle({ eventsPath: config.targetEventsPath,
      revisionPath: config.targetRevisionManifestPath, snapshotPath: config.targetSnapshotManifestPath });
    if (sourceBundle.revisionFileDigest !== refs.sourceRevisionManifest.digest
      || sourceBundle.snapshotFileDigest !== refs.sourceSnapshotManifest.digest
      || targetBundle.revisionFileDigest !== refs.targetRevisionManifest.digest
      || targetBundle.snapshotFileDigest !== refs.targetSnapshotManifest.digest) {
      fail('m4_live_operator_reconciliation_snapshot_attestation_invalid');
    }
  } catch {
    try { sourceBundle?.close(); } catch {} try { targetBundle?.close(); } catch {}
    fail('m4_live_operator_reconciliation_snapshot_attestation_invalid');
  }
  const sourceEventsDigest = sourceBundle.eventFileDigest;
  const targetEventsDigest = targetBundle.eventFileDigest;
  refs.sourceRevisionManifest = { value: sourceBundle.revision, digest: sourceBundle.revisionFileDigest };
  refs.sourceSnapshotManifest = { value: sourceBundle.snapshot, digest: sourceBundle.snapshotFileDigest };
  refs.targetRevisionManifest = { value: targetBundle.revision, digest: targetBundle.revisionFileDigest };
  refs.targetSnapshotManifest = { value: targetBundle.snapshot, digest: targetBundle.snapshotFileDigest };
  try {
  let sourceSnapshot; let targetSnapshot; let sourceRevision; let targetRevision;
  try {
    sourceSnapshot = verifyM4ReconciliationSnapshot(refs.sourceSnapshotManifest.value, refs.sourceSnapshotKey.value);
    targetSnapshot = verifyM4ReconciliationSnapshot(refs.targetSnapshotManifest.value, refs.targetSnapshotKey.value);
    sourceRevision = verifyM4ReconciliationArchiveRevision(refs.sourceRevisionManifest.value, refs.sourceRevisionKey.value);
    targetRevision = verifyM4ReconciliationArchiveRevision(refs.targetRevisionManifest.value, refs.targetRevisionKey.value);
  } catch { fail('m4_live_operator_reconciliation_snapshot_attestation_invalid'); }
  assertReconciliationRevisionsCurrent(sourceRevision, targetRevision, clock);
  if (sourceSnapshot.archive !== 'legacy-v2' || targetSnapshot.archive !== 'v3'
    || sourceRevision.archive !== 'legacy-v2' || targetRevision.archive !== 'v3'
    || canonicalDigest(sourceSnapshot.revision) !== canonicalDigest(sourceRevision.revision)
    || canonicalDigest(targetSnapshot.revision) !== canonicalDigest(targetRevision.revision)
    || canonicalDigest(sourceSnapshot.revisionEvidence) !== canonicalDigest(m4ReconciliationArchiveRevisionEvidence(sourceRevision))
    || canonicalDigest(targetSnapshot.revisionEvidence) !== canonicalDigest(m4ReconciliationArchiveRevisionEvidence(targetRevision))
    || sourceSnapshot.prerequisiteEvidenceDigest !== canonicalDigest(refs.legacyCompletion.value)
    || targetSnapshot.prerequisiteEvidenceDigest !== canonicalDigest(refs.nativePhaseCompletion.value)
    || canonicalDigest(sourceSnapshot.terminalCheckpoint) !== canonicalDigest(refs.legacyCompletion.value.checkpoint)
    || canonicalDigest(targetSnapshot.terminalCheckpoint) !== canonicalDigest(refs.nativePhaseCompletion.value.checkpoint)
    || !timestampWithin(sourceSnapshot.capturedAt, sourceRevision.observedAt, sourceRevision.validThrough)
    || !timestampWithin(targetSnapshot.capturedAt, targetRevision.observedAt, targetRevision.validThrough)
    || sourceSnapshot.eventFileDigest !== sourceEventsDigest || targetSnapshot.eventFileDigest !== targetEventsDigest
    || sourceSnapshot.staticEvidenceDigest !== canonicalDigest(refs.sourceEvidence.value)
    || targetSnapshot.staticEvidenceDigest !== canonicalDigest(refs.targetEvidence.value)
    || sourceSnapshot.eventCount + targetSnapshot.eventCount > config.maxVisitedEvents) {
    fail('m4_live_operator_reconciliation_snapshot_attestation_invalid');
  }
  independentKeyDocuments([refs.legacyCompletionKey.value, refs.nativePhaseCompletionKey.value,
    refs.reconciliationKey.value, refs.sourceSnapshotKey.value, refs.targetSnapshotKey.value,
    refs.sourceRevisionKey.value, refs.targetRevisionKey.value],
  'm4_live_operator_reconciliation_key_separation_invalid');
  const serial = { gateInput: refs.gateInput.value, legacyCompletion: refs.legacyCompletion.value,
    legacyCompletionKeyDocument: refs.legacyCompletionKey.value, nativePhaseCompletion: refs.nativePhaseCompletion.value,
    nativePhaseCompletionKeyDocument: refs.nativePhaseCompletionKey.value, sourceEvidence: refs.sourceEvidence.value,
    targetEvidence: refs.targetEvidence.value, maxVisitedEvents: config.maxVisitedEvents,
    maxMismatchSamples: config.maxMismatchSamples, manifestId: config.manifestId, revision: config.revision,
    reconciliationKeyId: refs.reconciliationKey.value?.keyId };
  let innerPlan;
  try { innerPlan = await planM4Reconciliation(serial); }
  catch { fail('m4_live_operator_reconciliation_evidence_invalid'); }
  const inputDigests = { config: configReference.digest,
    ...Object.fromEntries(Object.entries(refs).map(([name, item]) => [name, item.digest])),
    sourceEvents: sourceEventsDigest, targetEvents: targetEventsDigest,
    sourceBundle: sourceBundle.markerDigest, targetBundle: targetBundle.markerDigest };
  sourceBundle.assertCurrent(); targetBundle.assertCurrent();
  return { config, refs, serial, innerPlan, sourceSnapshot, targetSnapshot, sourceRevision, targetRevision,
    sourceBundle, targetBundle, close: () => { sourceBundle.close(); targetBundle.close(); },
    plan: reconciliationPlanFor(config, inputDigests, innerPlan) };
  } catch (error) { sourceBundle.close(); targetBundle.close(); throw error; }
}

async function executeReconciliation(prepared, clock) {
  let sourceResource; let targetResource;
  const source = () => {
    prepared.sourceBundle.assertCurrent();
    sourceResource = openM4ReconciliationSnapshot(prepared.config.sourceEventsPath, prepared.sourceSnapshot,
      { identity: prepared.sourceBundle.eventIdentity });
    return { value: { events: sourceResource.events, evidence: prepared.serial.sourceEvidence }, close: sourceResource.close };
  };
  const target = () => {
    prepared.targetBundle.assertCurrent();
    targetResource = openM4ReconciliationSnapshot(prepared.config.targetEventsPath, prepared.targetSnapshot,
      { identity: prepared.targetBundle.eventIdentity });
    return { value: { events: targetResource.events, evidence: prepared.serial.targetEvidence }, close: targetResource.close };
  };
  let result;
  try {
    result = await runM4Reconciliation({ ...prepared.serial,
      confirmedPlanDigest: prepared.innerPlan.confirmationDigest,
      verifyCurrentLegacyCompletion: async () => readPrivateJson(prepared.config.legacyCompletionPath,
        'm4_live_operator_reconciliation_evidence_invalid'),
      verifyCurrentNativePhaseCompletion: async () => readPrivateJson(prepared.config.nativePhaseCompletionPath,
        'm4_live_operator_reconciliation_evidence_invalid'),
      factories: { source, target, reconciliationKey: async () => {
        prepared.sourceBundle.assertCurrent(); prepared.targetBundle.assertCurrent();
        assertReconciliationRevisionsCurrent(prepared.sourceRevision, prepared.targetRevision, clock);
        return { value: clone(prepared.refs.reconciliationKey.value,
          'm4_live_operator_reconciliation_evidence_invalid'), close: null };
      } } });
    sourceResource?.verifyComplete(); targetResource?.verifyComplete();
    verifyM4ReconciliationManifest(result.manifest, prepared.refs.reconciliationKey.value);
  } catch (error) {
    if (error?.code?.startsWith?.('m4_reconciliation_') || error?.code?.startsWith?.('m4_live_')) throw error;
    fail('m4_live_operator_reconciliation_run_failed');
  }
  return result.manifest;
}
function prepareCanary(configPath) {
  const code = 'm4_live_operator_canary_config_invalid';
  const configReference = readPrivateJsonWithDigest(configPath, code);
  const config = validIdentity(configReference.value, CONFIG_SCHEMAS.canary,
    ['schema', 'artifactRoot', 'manifestId', 'revision', 'policyPath', 'aggregateObservationPath',
      'rollbackDrillPath', 'canaryKeyPath'], code);
  const policy = reference(config.policyPath, code);
  const observed = reference(config.aggregateObservationPath, code);
  const rollback = reference(config.rollbackDrillPath, code);
  const canaryKey = reference(config.canaryKeyPath, code);
  if (!plain(observed.value) || Object.hasOwn(observed.value, 'rollbackDrill')) fail('m4_live_operator_canary_observation_invalid');
  let candidate;
  try {
    candidate = createM4CutoverCanaryManifest({ manifestId: config.manifestId, revision: config.revision,
      policy: policy.value, observations: { ...clone(observed.value, code), rollbackDrill: rollback.value },
      keyDocument: canaryKey.value });
    verifyM4CutoverCanaryManifest(candidate, canaryKey.value);
  } catch { fail('m4_live_operator_canary_evidence_invalid'); }
  const inputDigests = { config: configReference.digest, policy: policy.digest,
    observations: observed.digest, rollbackDrill: rollback.digest, canaryKey: canaryKey.digest };
  return { config, candidate, plan: planFor('canary', config, inputDigests, candidate) };
}
function strictCurrentTime(value) {
  if (typeof value !== 'string' || !value.endsWith('Z') || !timestampWithin(value, value, value)) {
    fail('m4_live_operator_clock_invalid');
  }
  return value;
}
function currentIso(clock) {
  let value;
  try { value = clock().toISOString(); } catch { fail('m4_live_operator_clock_invalid'); }
  return strictCurrentTime(value);
}
function prepareAuthorization(configPath, clock) {
  const code = 'm4_live_operator_authorization_config_invalid';
  const configReference = readPrivateJsonWithDigest(configPath, code);
  const config = validIdentity(configReference.value, CONFIG_SCHEMAS.authorization,
    ['schema', 'artifactRoot', 'manifestId', 'revision', 'authorizedAt', 'reconciliationManifestPath',
      'reconciliationKeyPath', 'recoveryPairPath', 'recoveryKeyPath', 'aliasManifestPath', 'aliasKeyPath',
      'canaryManifestPath', 'canaryKeyPath', 'preservationProofPath', 'preservationKeyPath',
      'selectorScopeManifestPath', 'selectorScopeTrustAnchorPath', 'routeConfigurationPath',
      'rollbackRevisionPath', 'authorizationKeyPath'], code);
  const refs = Object.fromEntries([
    ['reconciliationManifest', config.reconciliationManifestPath], ['reconciliationKey', config.reconciliationKeyPath],
    ['recoveryManifest', config.recoveryPairPath], ['recoveryKey', config.recoveryKeyPath],
    ['aliasManifest', config.aliasManifestPath], ['aliasKey', config.aliasKeyPath],
    ['canaryManifest', config.canaryManifestPath], ['canaryKey', config.canaryKeyPath],
    ['preservationManifest', config.preservationProofPath], ['preservationKey', config.preservationKeyPath],
    ['selectorScopeManifest', config.selectorScopeManifestPath], ['selectorScopeKey', config.selectorScopeTrustAnchorPath],
    ['routeConfiguration', config.routeConfigurationPath], ['rollbackRevision', config.rollbackRevisionPath],
    ['authorizationKey', config.authorizationKeyPath],
  ].map(([name, path]) => [name, reference(path, code)]));
  let scope;
  try { scope = verifyM4SelectorScopeSnapshot(refs.selectorScopeManifest.value, refs.selectorScopeKey.value); }
  catch { fail('m4_live_operator_authorization_scope_invalid'); }
  const now = currentIso(clock);
  if (!timestampWithin(config.authorizedAt, scope.observedAt, scope.validThrough)
    || !timestampWithin(now, scope.observedAt, scope.validThrough)) fail('m4_live_operator_authorization_scope_stale');
  let candidate;
  try {
    candidate = createM4CutoverAuthorization({ manifestId: config.manifestId, revision: config.revision,
      authorizedAt: config.authorizedAt, reconciliationManifest: refs.reconciliationManifest.value,
      reconciliationKeyDocument: refs.reconciliationKey.value, recoveryManifest: refs.recoveryManifest.value,
      recoveryKeyDocument: refs.recoveryKey.value, aliasManifest: refs.aliasManifest.value,
      aliasKeyDocument: refs.aliasKey.value, canaryManifest: refs.canaryManifest.value,
      canaryKeyDocument: refs.canaryKey.value, preservationManifest: refs.preservationManifest.value,
      preservationKeyDocument: refs.preservationKey.value, selectorScopeManifest: refs.selectorScopeManifest.value,
      routeConfiguration: refs.routeConfiguration.value, rollbackRevision: refs.rollbackRevision.value,
      authorizationKeyDocument: refs.authorizationKey.value },
    { selectorScopeKeyDocument: refs.selectorScopeKey.value });
    verifyM4CutoverAuthorization(candidate, refs.authorizationKey.value);
  } catch (error) {
    if (error?.code === 'm4_live_operator_authorization_scope_stale') throw error;
    fail('m4_live_operator_authorization_evidence_invalid');
  }
  const inputDigests = { config: configReference.digest,
    ...Object.fromEntries(Object.entries(refs).map(([name, item]) => [name, item.digest])) };
  return { config, candidate, scope, plan: planFor('authorization', config, inputDigests, candidate) };
}
async function prepare(stage, configPath, clock) {
  if (stage === 'recovery') return prepareRecovery(configPath);
  if (stage === 'reconciliation') return prepareReconciliation(configPath, clock);
  if (stage === 'canary') return prepareCanary(configPath);
  if (stage === 'authorization') return prepareAuthorization(configPath, clock);
  fail('m4_live_operator_stage_invalid');
}

export async function planM4LiveOperator({ stage, configPath } = {}, { clock = () => new Date() } = {}) {
  let prepared;
  try { prepared = await prepare(stage, configPath, clock); return clone(prepared.plan, 'm4_live_operator_plan_invalid'); }
  catch (error) { if (error?.code?.startsWith?.('m4_live_operator_')) throw error; fail('m4_live_operator_plan_invalid'); }
  finally { prepared?.close?.(); }
}

export async function runM4LiveOperator({ stage, configPath, confirmedPlanDigest } = {}, { clock = () => new Date() } = {}) {
  if (typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest)) fail('m4_live_operator_confirmation_invalid');
  const prepared = await prepare(stage, configPath, clock);
  try {
  if (prepared.plan.confirmationDigest !== confirmedPlanDigest) fail('m4_live_operator_confirmation_invalid');
  outputAvailable(prepared.config.artifactRoot, stage, prepared.config.manifestId, prepared.config.revision,
    'm4_live_operator_artifact_missing');
  if (stage === 'authorization') {
    const now = currentIso(clock);
    if (!timestampWithin(now, prepared.scope.observedAt, prepared.scope.validThrough)) {
      fail('m4_live_operator_authorization_scope_stale');
    }
  }
  if (stage === 'reconciliation') {
    const candidate = await executeReconciliation(prepared, clock);
    prepared.sourceBundle.assertCurrent(); prepared.targetBundle.assertCurrent();
    assertReconciliationRevisionsCurrent(prepared.sourceRevision, prepared.targetRevision, clock);
    writePrivateArtifact(prepared.config.artifactRoot, stage, prepared.config.manifestId,
      prepared.config.revision, candidate);
    return resultFor(stage, candidate, prepared.plan);
  }
  writePrivateArtifact(prepared.config.artifactRoot, stage, prepared.config.manifestId,
    prepared.config.revision, prepared.candidate);
  return resultFor(stage, prepared.candidate, prepared.plan);
  } finally { prepared?.close?.(); }
}
