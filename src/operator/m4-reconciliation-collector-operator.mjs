import fs from 'node:fs';
import path from 'node:path';

import { verifyM4LegacyGroupReplayCompletion } from '../migration/m4-legacy-group-replay-batch-runner.mjs';
import { verifyM4NativePausedPhaseCompletion } from '../migration/m4-native-paused-phase-orchestrator.mjs';
import { assertM4ReconciliationCollectorKeySeparation, collectM4ReconciliationArchiveRevision,
  collectM4ReconciliationSnapshot } from '../migration/m4-reconciliation-collector.mjs';
import { canonicalDigest, readPrivateJsonWithDigest, validateArtifactRoot } from './private-artifacts.mjs';
import { createPrivateM4SnapshotSpool } from './private-snapshot-bundle.mjs';

const SCHEMA = 'amf.m4-reconciliation-collector-operator/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function current(clock) {
  let value; try { value = clock().toISOString(); } catch { fail('m4_reconciliation_collector_operator_clock_invalid'); }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) fail('m4_reconciliation_collector_operator_clock_invalid');
  return value;
}
function reference(target, code) { return readPrivateJsonWithDigest(target, code); }
function targetAvailable(config) {
  const target = path.join(config.artifactRoot, 'm4', 'snapshots', config.bundleId);
  if (fs.existsSync(target)) fail('m4_reconciliation_collector_operator_target_exists');
}
function verifyCompletion(archive, value, keyDocument, dependencies) {
  try {
    return archive === 'legacy-v2'
      ? dependencies.verifyLegacyCompletion(value, keyDocument)
      : dependencies.verifyNativeCompletion(value, keyDocument);
  } catch { fail('m4_reconciliation_collector_operator_completion_invalid'); }
}
function defaults(dependencies = {}) {
  const value = { createSource: dependencies.createSource,
    verifyLegacyCompletion: dependencies.verifyLegacyCompletion ?? verifyM4LegacyGroupReplayCompletion,
    verifyNativeCompletion: dependencies.verifyNativeCompletion ?? verifyM4NativePausedPhaseCompletion,
    clock: dependencies.clock ?? (() => new Date()) };
  if (typeof value.createSource !== 'function' || typeof value.verifyLegacyCompletion !== 'function'
    || typeof value.verifyNativeCompletion !== 'function' || typeof value.clock !== 'function') {
    fail('m4_reconciliation_collector_operator_dependency_invalid');
  }
  return value;
}
function prepare(configPath, dependencies) {
  const code = 'm4_reconciliation_collector_operator_config_invalid';
  const configReference = reference(configPath, code); const config = configReference.value;
  const names = ['schema', 'artifactRoot', 'bundleId', 'archive', 'snapshotId', 'revisionManifestId', 'revision',
    'completionPath', 'completionKeyPath', 'revisionKeyPath', 'snapshotKeyPath', 'staticEvidencePath',
    'sourceConfigPath', 'revisionValiditySeconds', 'maxEvents'];
  if (!exact(config, names) || config.schema !== SCHEMA || !['legacy-v2', 'v3'].includes(config.archive)
    || ![config.bundleId, config.snapshotId, config.revisionManifestId].every(value => typeof value === 'string' && ID.test(value))
    || !Number.isSafeInteger(config.revision) || config.revision < 1
    || !Number.isSafeInteger(config.revisionValiditySeconds) || config.revisionValiditySeconds < 60
    || config.revisionValiditySeconds > 86_400 || !Number.isSafeInteger(config.maxEvents)
    || config.maxEvents < 0 || config.maxEvents > 5_000_000) fail(code);
  validateArtifactRoot(config.artifactRoot, code); targetAvailable(config);
  const refs = Object.fromEntries(['completion', 'completionKey', 'revisionKey', 'snapshotKey', 'staticEvidence', 'sourceConfig']
    .map(name => [name, reference(config[`${name}Path`], code)]));
  try { assertM4ReconciliationCollectorKeySeparation([refs.completionKey.value,
    refs.revisionKey.value, refs.snapshotKey.value]); }
  catch { fail('m4_reconciliation_collector_operator_key_separation_invalid'); }
  const completion = verifyCompletion(config.archive, refs.completion.value, refs.completionKey.value, dependencies);
  const inputDigests = { config: configReference.digest,
    ...Object.fromEntries(Object.entries(refs).map(([name, value]) => [name, value.digest])) };
  const binding = { schema: 'amf.m4-reconciliation-collector-plan-binding/v1', archive: config.archive,
    bundleId: config.bundleId, revision: config.revision, artifactRoot: config.artifactRoot, inputDigests };
  return { config: clone(config, code), refs, completion, inputDigests,
    plan: { schema: 'amf.m4-reconciliation-collector-plan/v1', operation: 'plan', archive: config.archive,
      bundleId: config.bundleId, revision: config.revision, state: 'planned',
      confirmationDigest: canonicalDigest(binding) } };
}

export async function planM4ReconciliationCollection({ configPath } = {}, rawDependencies = {}) {
  const dependencies = defaults(rawDependencies);
  if (typeof configPath !== 'string' || !path.isAbsolute(configPath)) fail('m4_reconciliation_collector_operator_request_invalid');
  return clone(prepare(configPath, dependencies).plan, 'm4_reconciliation_collector_operator_request_invalid');
}

export async function runM4ReconciliationCollection({ configPath, confirmedPlanDigest } = {}, rawDependencies = {}) {
  const dependencies = defaults(rawDependencies);
  if (typeof configPath !== 'string' || !path.isAbsolute(configPath)
    || typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest)) {
    fail('m4_reconciliation_collector_operator_request_invalid');
  }
  const prepared = prepare(configPath, dependencies);
  if (prepared.plan.confirmationDigest !== confirmedPlanDigest) fail('m4_reconciliation_collector_operator_confirmation_invalid');
  let source; let primary = null;
  try {
    source = await dependencies.createSource({ archive: prepared.config.archive,
      config: clone(prepared.config, 'm4_reconciliation_collector_operator_source_invalid'),
      sourceConfig: clone(prepared.refs.sourceConfig.value,
        'm4_reconciliation_collector_operator_source_invalid') });
    if (!exact(source, ['revisionSource', 'events', 'close']) || typeof source.revisionSource !== 'function'
      || typeof source.events?.[Symbol.asyncIterator] !== 'function' || typeof source.close !== 'function') {
      fail('m4_reconciliation_collector_operator_source_invalid');
    }
    const observedAt = current(dependencies.clock);
    const validThrough = new Date(Date.parse(observedAt)
      + prepared.config.revisionValiditySeconds * 1_000).toISOString();
    const revision = await collectM4ReconciliationArchiveRevision({ archive: prepared.config.archive,
      manifestId: prepared.config.revisionManifestId, revisionSource: source.revisionSource,
      revisionKeyDocument: prepared.refs.revisionKey.value, observedAt, validThrough });
    const spool = createPrivateM4SnapshotSpool({ artifactRoot: prepared.config.artifactRoot,
      bundleId: prepared.config.bundleId, maxEvents: prepared.config.maxEvents });
    const result = await collectM4ReconciliationSnapshot({ archive: prepared.config.archive,
      snapshotId: prepared.config.snapshotId, completion: prepared.refs.completion.value,
      completionKeyDocument: prepared.refs.completionKey.value,
      verifyCompletion: async (value, keyDocument) => verifyCompletion(prepared.config.archive,
        value, keyDocument, dependencies), revisionManifest: revision,
      revisionKeyDocument: prepared.refs.revisionKey.value,
      snapshotKeyDocument: prepared.refs.snapshotKey.value, events: source.events, spool,
      staticEvidence: prepared.refs.staticEvidence.value, capturedAt: current(dependencies.clock) });
    return { schema: 'amf.m4-reconciliation-collector-result/v1', operation: 'run', archive: prepared.config.archive,
      bundleId: prepared.config.bundleId, revision: prepared.config.revision, state: 'complete',
      planDigest: prepared.plan.confirmationDigest, payloadDigest: result.snapshot.integrity.payloadDigest };
  } catch (error) { primary = error; throw error; }
  finally {
    try { await source?.close?.(); }
    catch { if (primary === null) fail('m4_reconciliation_collector_operator_source_close_failed'); }
  }
}
