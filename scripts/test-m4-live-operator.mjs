import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { createM4ReconciliationArchiveRevision, createM4ReconciliationEventAccumulator,
  createM4ReconciliationSnapshot, m4ReconciliationArchiveRevisionEvidence } from '../src/migration/m4-reconciliation-snapshot.mjs';
import { artifactPath, canonicalDigest, privateFileDigest, writePrivateArtifact } from '../src/operator/private-artifacts.mjs';
import { planM4LiveOperator, runM4LiveOperator } from '../src/operator/m4-live-operator.mjs';
import { openM4ReconciliationSnapshot } from '../src/operator/m4-reconciliation-snapshots.mjs';
import { m4CutoverFixture } from './helpers/m4-cutover-fixtures.mjs';

function workspace(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-live-'));
  fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifactRoot = path.join(root, 'artifacts'); fs.mkdirSync(artifactRoot, { mode: 0o700 });
  let sequence = 0;
  const write = (value, name = `input-${sequence += 1}.json`) => {
    const target = path.join(root, name); fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    return target;
  };
  return { root, artifactRoot, write };
}

const sha = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId,
  key: Buffer.alloc(32, byte).toString('base64') });
const checkpoint = (id, marker = id) => ({ id, digest: sha(marker) });
const sign = (document, domain, valueDigest) => crypto.createHmac('sha256', Buffer.from(document.key, 'base64'))
  .update(canonicalJson([domain, valueDigest, document.keyId]), 'utf8').digest('base64url');
const RECONCILIATION_CLOCK = { clock: () => new Date('2026-07-22T12:00:00Z') };
function descriptorsFor(target) {
  const real = fs.realpathSync(target);
  return fs.readdirSync('/proc/self/fd').filter(name => {
    try { return fs.readlinkSync(`/proc/self/fd/${name}`) === real; } catch { return false; }
  });
}

function reconciliationPrerequisites(fixture) {
  const gateInput = { runId: 'live-reconciliation-gate', phase: 'paused-native', pauseManifest: fixture.paused,
    pauseKeyDocument: fixture.keys.pause, rollbackManifest: fixture.rollback, rollbackKeyDocument: fixture.keys.rollback };
  const legacyKey = key('live-legacy-completion-key', 41); const nativeKey = key('live-native-completion-key', 42);
  const legacyPayload = { schema: 'amf.m4-legacy-group-replay-completion/v1', state: 'complete',
    authorityDigest: sha('live-legacy-authority'), checkpoint: checkpoint('live-legacy-checkpoint') };
  const legacyDigest = sha({ schema: 'amf.m4-legacy-group-replay-completion-evidence/v1',
    manifestId: 'live-legacy-completion', keyId: legacyKey.keyId, completion: legacyPayload });
  const legacy = { ...legacyPayload, evidence: { manifestId: 'live-legacy-completion', digest: legacyDigest,
    signature: sign(legacyKey, 'amf.m4-legacy-group-replay-completion/v1/integrity', legacyDigest) } };
  const pause = gateInput.pauseManifest; const rollback = gateInput.rollbackManifest;
  const gateEvidenceDigest = sha({ schema: 'amf.m4-native-paused-phase-gate-evidence/v1',
    pauseEvidence: { manifestId: pause.manifestId, digest: pause.integrity.payloadDigest, signature: pause.integrity.signature },
    rollbackEvidence: { manifestId: rollback.manifestId, digest: rollback.integrity.payloadDigest,
      signature: rollback.integrity.signature }, sourceCheckpoint: rollback.rollback.sourceCheckpoint,
    targetCheckpoint: rollback.rollback.targetCheckpoint });
  const nativePayload = { schema: 'amf.m4-native-paused-phase-completion/v1', state: 'complete',
    runId: 'live-native-phase', gateEvidenceDigest, catalogDigest: sha('live-catalog'), legacyCompletionDigest: sha(legacy),
    registryAuthorityDigest: sha('live-registry-authority'), sourceTagAuthorityDigest: sha('live-source-tag-authority'),
    receiptKeyId: 'live-receipt-key', receiptDigest: sha('live-receipts') };
  const finalDigest = sha({ schema: 'amf.m4-native-paused-phase-final-checkpoint/v1', runId: nativePayload.runId,
    gateEvidenceDigest, catalogDigest: nativePayload.catalogDigest, legacyCompletionDigest: nativePayload.legacyCompletionDigest,
    registryAuthorityDigest: nativePayload.registryAuthorityDigest,
    sourceTagAuthorityDigest: nativePayload.sourceTagAuthorityDigest,
    receiptKeyId: nativePayload.receiptKeyId, receiptDigest: nativePayload.receiptDigest });
  nativePayload.checkpoint = { id: `m4nativephase-${finalDigest.slice(7)}`, digest: finalDigest };
  const nativeDigest = sha({ schema: 'amf.m4-native-paused-phase-completion-evidence/v1',
    manifestId: 'live-native-completion', keyId: nativeKey.keyId, completion: nativePayload });
  const native = { ...nativePayload, evidence: { manifestId: 'live-native-completion', keyId: nativeKey.keyId,
    digest: nativeDigest, signature: sign(nativeKey, 'amf.m4-native-paused-phase-completion/v1/integrity', nativeDigest) } };
  return { gateInput, legacy, legacyKey, native, nativeKey };
}

function reconciliationConfig(item, fixture, targetEvent = null) {
  const prerequisites = reconciliationPrerequisites(fixture); const reconciliationKey = key('live-reconciliation-key', 43);
  const evidence = { pausedInterval: { start: checkpoint('live-pause-start'), end: checkpoint('live-pause-end') },
    replayQueues: { pendingOutbox: checkpoint('live-pending'), acknowledgements: checkpoint('live-acks'),
      deadLetters: checkpoint('live-dead') }, sourceCheckpoints: { collectorCursor: checkpoint('live-cursor'),
      sourceCheckpoint: checkpoint('live-source'), nativeTranscriptAuthority: checkpoint('live-native-authority') } };
  const event = { eventId: 'cevt_liveevent01', payloadDigest: sha('live-payload'), logicalDigest: sha('live-logical'),
    sourceOccurredAt: '2026-01-01T00:00:00Z', occurredAt: '2026-01-01T00:00:01Z', state: 'active' };
  const sourceBundle = path.join(item.root, 'live-source-bundle'); const targetBundle = path.join(item.root, 'live-target-bundle');
  fs.mkdirSync(sourceBundle, { mode: 0o700 }); fs.mkdirSync(targetBundle, { mode: 0o700 });
  const sourceEventsPath = path.join(sourceBundle, 'events.jsonl'); const targetEventsPath = path.join(targetBundle, 'events.jsonl');
  fs.writeFileSync(sourceEventsPath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  const targetValue = targetEvent ?? event;
  fs.writeFileSync(targetEventsPath, `${JSON.stringify(targetValue)}\n`, { mode: 0o600 });
  const sourceSnapshotKey = key('live-source-snapshot-key', 44); const targetSnapshotKey = key('live-target-snapshot-key', 45);
  const sourceRevisionKey = key('live-source-revision-key', 46); const targetRevisionKey = key('live-target-revision-key', 47);
  const revision = (archive, value, signingKey) => createM4ReconciliationArchiveRevision({
    manifestId: `live-${archive === 'legacy-v2' ? 'legacy' : 'vthree'}-revision`, archive, revision: value,
    observedAt: '2026-07-22T00:00:00Z', validThrough: '2026-07-23T00:00:00Z' }, signingKey);
  const sourceRevision = revision('legacy-v2', checkpoint('legacy-archive-revision'), sourceRevisionKey);
  const targetRevision = revision('v3', checkpoint('vthree-archive-revision'), targetRevisionKey);
  const snapshot = (archive, value, filePath, signingKey, revisionManifest, prerequisite, terminalCheckpoint) => {
    const accumulator = createM4ReconciliationEventAccumulator(); accumulator.add(value); const set = accumulator.finish();
    return createM4ReconciliationSnapshot({ snapshotId: `live-${archive === 'legacy-v2' ? 'legacy' : 'vthree'}-snapshot`, archive,
      revision: revisionManifest.revision, terminalCheckpoint, capturedAt: '2026-07-22T00:01:00Z',
      revisionEvidence: m4ReconciliationArchiveRevisionEvidence(revisionManifest),
      prerequisiteEvidenceDigest: canonicalDigest(prerequisite), ...set, eventFileDigest: privateFileDigest(filePath),
      staticEvidenceDigest: canonicalDigest(evidence) }, signingKey);
  };
  const sourceSnapshot = snapshot('legacy-v2', event, sourceEventsPath, sourceSnapshotKey, sourceRevision,
    prerequisites.legacy, prerequisites.legacy.checkpoint);
  const targetSnapshot = snapshot('v3', targetValue, targetEventsPath, targetSnapshotKey, targetRevision,
    prerequisites.native, prerequisites.native.checkpoint);
  const writeBundle = (directory, bundleId, revisionManifest, snapshotManifest) => {
    const revisionPath = path.join(directory, 'revision.json'); const snapshotPath = path.join(directory, 'snapshot.json');
    fs.writeFileSync(revisionPath, `${JSON.stringify(revisionManifest, null, 2)}\n`, { mode: 0o600 });
    fs.writeFileSync(snapshotPath, `${JSON.stringify(snapshotManifest, null, 2)}\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(directory, 'complete.json'), `${JSON.stringify({ schema: 'amf.m4-snapshot-bundle/v1',
      bundleId, eventFileDigest: snapshotManifest.eventFileDigest, eventCount: snapshotManifest.eventCount,
      eventSetDigest: snapshotManifest.eventSetDigest, revisionDigest: canonicalDigest(revisionManifest),
      snapshotDigest: canonicalDigest(snapshotManifest) }, null, 2)}\n`, { mode: 0o600 });
    return { revisionPath, snapshotPath };
  };
  const sourceFiles = writeBundle(sourceBundle, 'live-source-bundle', sourceRevision, sourceSnapshot);
  const targetFiles = writeBundle(targetBundle, 'live-target-bundle', targetRevision, targetSnapshot);
  return item.write({ schema: 'amf.m4-live-reconciliation-operator/v1', artifactRoot: item.artifactRoot,
    manifestId: 'live-reconciliation-one', revision: 1, gateInputPath: item.write(prerequisites.gateInput),
    legacyCompletionPath: item.write(prerequisites.legacy), legacyCompletionKeyPath: item.write(prerequisites.legacyKey),
    nativePhaseCompletionPath: item.write(prerequisites.native), nativePhaseCompletionKeyPath: item.write(prerequisites.nativeKey),
    sourceStaticEvidencePath: item.write(evidence), targetStaticEvidencePath: item.write(evidence), sourceEventsPath,
    targetEventsPath, sourceSnapshotManifestPath: sourceFiles.snapshotPath, sourceSnapshotTrustAnchorPath: item.write(sourceSnapshotKey),
    targetSnapshotManifestPath: targetFiles.snapshotPath, targetSnapshotTrustAnchorPath: item.write(targetSnapshotKey),
    sourceRevisionManifestPath: sourceFiles.revisionPath, sourceRevisionTrustAnchorPath: item.write(sourceRevisionKey),
    targetRevisionManifestPath: targetFiles.revisionPath, targetRevisionTrustAnchorPath: item.write(targetRevisionKey),
    reconciliationKeyPath: item.write(reconciliationKey), maxVisitedEvents: 100,
    maxMismatchSamples: 10 }, 'reconciliation-config.json');
}

function recoveryConfig(item, fixture) {
  return item.write({ schema: 'amf.m4-live-recovery-operator/v1', artifactRoot: item.artifactRoot,
    manifestId: 'live-recovery-one', revision: 1,
    reconciliationManifestPath: item.write(fixture.reconciliation),
    reconciliationKeyPath: item.write(fixture.keys.reconciliation),
    legacyRecoveryRecordPath: item.write(fixture.recovery.archives[0]),
    v3RecoveryRecordPath: item.write(fixture.recovery.archives[1]),
    recoveryKeyPath: item.write(fixture.keys.recovery) }, 'recovery-config.json');
}

function canaryConfig(item, fixture, observations = fixture.canary.observations) {
  const { rollbackDrill, ...aggregate } = observations;
  return item.write({ schema: 'amf.m4-live-canary-operator/v1', artifactRoot: item.artifactRoot,
    manifestId: 'live-canary-one', revision: 1, policyPath: item.write(fixture.canary.policy),
    aggregateObservationPath: item.write(aggregate), rollbackDrillPath: item.write(rollbackDrill),
    canaryKeyPath: item.write(fixture.keys.canary) }, 'canary-config.json');
}

function authorizationConfig(item, fixture) {
  const input = fixture.authorizationInput;
  return item.write({ schema: 'amf.m4-live-authorization-operator/v1', artifactRoot: item.artifactRoot,
    manifestId: 'live-authorization-one', revision: 1, authorizedAt: input.authorizedAt,
    reconciliationManifestPath: item.write(input.reconciliationManifest),
    reconciliationKeyPath: item.write(input.reconciliationKeyDocument), recoveryPairPath: item.write(input.recoveryManifest),
    recoveryKeyPath: item.write(input.recoveryKeyDocument), aliasManifestPath: item.write(input.aliasManifest),
    aliasKeyPath: item.write(input.aliasKeyDocument), canaryManifestPath: item.write(input.canaryManifest),
    canaryKeyPath: item.write(input.canaryKeyDocument), preservationProofPath: item.write(input.preservationManifest),
    preservationKeyPath: item.write(input.preservationKeyDocument), selectorScopeManifestPath: item.write(input.selectorScopeManifest),
    selectorScopeTrustAnchorPath: item.write(fixture.keys.selectorScope), routeConfigurationPath: item.write(input.routeConfiguration),
    rollbackRevisionPath: item.write(input.rollbackRevision), authorizationKeyPath: item.write(input.authorizationKeyDocument) },
  'authorization-config.json');
}

async function execute(stage, configPath, dependencies) {
  const selected = dependencies ?? (stage === 'reconciliation' ? RECONCILIATION_CLOCK : undefined);
  const plan = await planM4LiveOperator({ stage, configPath }, selected);
  const result = await runM4LiveOperator({ stage, configPath, confirmedPlanDigest: plan.confirmationDigest }, selected);
  return { plan, result };
}

function refreshBundleMarker(config, role) {
  const eventsPath = config[`${role}EventsPath`];
  const revisionPath = config[`${role}RevisionManifestPath`];
  const snapshotPath = config[`${role}SnapshotManifestPath`];
  const markerPath = path.join(path.dirname(eventsPath), 'complete.json');
  const marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
  const revisionManifest = JSON.parse(fs.readFileSync(revisionPath, 'utf8'));
  const snapshotManifest = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
  fs.writeFileSync(markerPath, `${JSON.stringify({ ...marker, eventFileDigest: snapshotManifest.eventFileDigest,
    eventCount: snapshotManifest.eventCount, eventSetDigest: snapshotManifest.eventSetDigest,
    revisionDigest: canonicalDigest(revisionManifest), snapshotDigest: canonicalDigest(snapshotManifest) }, null, 2)}\n`);
}

test('recovery plan is side-effect free and run writes one immutable owner-only artifact', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = recoveryConfig(item, fixture);
  const plan = await planM4LiveOperator({ stage: 'recovery', configPath });
  const target = artifactPath(item.artifactRoot, 'recovery', 'live-recovery-one', 1);
  assert.equal(fs.existsSync(target), false); assert.equal(JSON.stringify(plan).includes(item.root), false);
  const result = await runM4LiveOperator({ stage: 'recovery', configPath, confirmedPlanDigest: plan.confirmationDigest });
  assert.equal(result.state, 'complete'); assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  await assert.rejects(() => runM4LiveOperator({ stage: 'recovery', configPath,
    confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_live_operator_artifact_exists' });
});

test('reconciliation streams content-free snapshots into complete or pending signed evidence', async t => {
  const fixture = await m4CutoverFixture(); const complete = workspace(t);
  const first = await execute('reconciliation', reconciliationConfig(complete, fixture));
  assert.equal(first.result.state, 'complete');
  const pending = workspace(t); const changed = { eventId: 'cevt_liveevent01', payloadDigest: sha('changed-payload'),
    logicalDigest: sha('live-logical'), sourceOccurredAt: '2026-01-01T00:00:00Z',
    occurredAt: '2026-01-01T00:00:01Z', state: 'active' };
  const second = await execute('reconciliation', reconciliationConfig(pending, fixture, changed));
  assert.equal(second.result.state, 'pending');
});

test('reconciliation revision freshness is rechecked before signing and immutable write', async t => {
  const fixture = await m4CutoverFixture();
  for (const [instants, expectedCode] of [
    [['2026-07-22T23:59:59.000Z', '2026-07-23T00:00:00.001Z'],
      'm4_reconciliation_runner_key_factory_failed'],
    [['2026-07-22T23:59:59.000Z', '2026-07-22T23:59:59.500Z', '2026-07-23T00:00:00.001Z'],
      'm4_live_operator_reconciliation_revision_stale'],
  ]) {
    const item = workspace(t); const configPath = reconciliationConfig(item, fixture);
    const plan = await planM4LiveOperator({ stage: 'reconciliation', configPath }, RECONCILIATION_CLOCK);
    let index = 0;
    const advancingClock = { clock: () => new Date(instants[Math.min(index++, instants.length - 1)]) };
    await assert.rejects(() => runM4LiveOperator({ stage: 'reconciliation', configPath,
      confirmedPlanDigest: plan.confirmationDigest }, advancingClock),
    { code: expectedCode });
    assert.equal(fs.existsSync(artifactPath(item.artifactRoot, 'reconciliation',
      'live-reconciliation-one', 1)), false);
  }
});

test('matching truncated snapshots cannot satisfy signed completeness attestations', async t => {
  const fixture = await m4CutoverFixture(); const item = workspace(t); const configPath = reconciliationConfig(item, fixture);
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const signingKey = JSON.parse(fs.readFileSync(config.sourceSnapshotTrustAnchorPath, 'utf8'));
  const first = JSON.parse(fs.readFileSync(config.sourceEventsPath, 'utf8').trim());
  const accumulator = createM4ReconciliationEventAccumulator(); accumulator.add(first);
  accumulator.add({ ...first, eventId: 'cevt_liveevent02' });
  const forgedCompleteness = createM4ReconciliationSnapshot({ snapshotId: 'live-legacy-snapshot', archive: 'legacy-v2',
    revision: JSON.parse(fs.readFileSync(config.sourceRevisionManifestPath, 'utf8')).revision,
    terminalCheckpoint: JSON.parse(fs.readFileSync(config.legacyCompletionPath, 'utf8')).checkpoint,
    capturedAt: '2026-07-22T00:01:00Z',
    revisionEvidence: m4ReconciliationArchiveRevisionEvidence(JSON.parse(fs.readFileSync(config.sourceRevisionManifestPath, 'utf8'))),
    prerequisiteEvidenceDigest: canonicalDigest(JSON.parse(fs.readFileSync(config.legacyCompletionPath, 'utf8'))),
    ...accumulator.finish(), eventFileDigest: privateFileDigest(config.sourceEventsPath),
    staticEvidenceDigest: canonicalDigest(JSON.parse(fs.readFileSync(config.sourceStaticEvidencePath, 'utf8'))) }, signingKey);
  fs.writeFileSync(config.sourceSnapshotManifestPath, `${JSON.stringify(forgedCompleteness)}\n`);
  refreshBundleMarker(config, 'source');
  const plan = await planM4LiveOperator({ stage: 'reconciliation', configPath }, RECONCILIATION_CLOCK);
  await assert.rejects(() => runM4LiveOperator({ stage: 'reconciliation', configPath,
    confirmedPlanDigest: plan.confirmationDigest }, RECONCILIATION_CLOCK));
  assert.equal(fs.existsSync(artifactPath(item.artifactRoot, 'reconciliation', 'live-reconciliation-one', 1)), false);
});

test('signed snapshot replay against a different completion is rejected during planning', async t => {
  const fixture = await m4CutoverFixture(); const item = workspace(t); const configPath = reconciliationConfig(item, fixture);
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const signingKey = JSON.parse(fs.readFileSync(config.sourceSnapshotTrustAnchorPath, 'utf8'));
  const current = JSON.parse(fs.readFileSync(config.sourceSnapshotManifestPath, 'utf8'));
  const { integrity, ...body } = current; void integrity;
  const replayed = createM4ReconciliationSnapshot({ ...body,
    prerequisiteEvidenceDigest: sha('older-completion'), terminalCheckpoint: checkpoint('older-terminal') }, signingKey);
  fs.writeFileSync(config.sourceSnapshotManifestPath, `${JSON.stringify(replayed)}\n`);
  await assert.rejects(() => planM4LiveOperator({ stage: 'reconciliation', configPath }, RECONCILIATION_CLOCK),
    { code: 'm4_live_operator_reconciliation_snapshot_attestation_invalid' });
});

test('same-inode snapshot mutation after anchoring fails before completeness can verify', async t => {
  const item = workspace(t); const first = { eventId: 'cevt_anchor0001', payloadDigest: sha('a'), logicalDigest: sha('b'),
    sourceOccurredAt: '2026-01-01T00:00:00Z', occurredAt: '2026-01-01T00:00:01Z', state: 'active' };
  const changed = { ...first, payloadDigest: sha('c') }; const file = path.join(item.root, 'anchored.jsonl');
  fs.writeFileSync(file, `${JSON.stringify(first)}\n`, { mode: 0o600 });
  const accumulator = createM4ReconciliationEventAccumulator(); accumulator.add(first);
  const manifest = { ...accumulator.finish(), eventFileDigest: privateFileDigest(file) };
  const resource = openM4ReconciliationSnapshot(file, manifest);
  assert.equal(descriptorsFor(file).length, 1);
  fs.writeFileSync(file, `${JSON.stringify(changed)}\n`);
  await assert.rejects(async () => { for await (const ignored of resource.events) void ignored; });
  await resource.close(); assert.equal(descriptorsFor(file).length, 0);
});

test('an attested empty archive snapshot completes without a sentinel row', async t => {
  const item = workspace(t); const file = path.join(item.root, 'empty.jsonl'); fs.writeFileSync(file, '', { mode: 0o600 });
  const accumulator = createM4ReconciliationEventAccumulator();
  const resource = openM4ReconciliationSnapshot(file, { ...accumulator.finish(),
    eventFileDigest: privateFileDigest(file, 'empty_snapshot_invalid', { minBytes: 0 }) });
  const rows = []; for await (const value of resource.events) rows.push(value);
  resource.verifyComplete(); await resource.close(); assert.deepEqual(rows, []);
  assert.equal(descriptorsFor(file).length, 0);
});

test('canary records truthful passed and failed outcomes without exposing aggregate details', async t => {
  const fixture = await m4CutoverFixture();
  const passed = workspace(t); const first = await execute('canary', canaryConfig(passed, fixture));
  assert.equal(first.result.state, 'passed'); assert.deepEqual(Object.keys(first.result).sort(),
    ['manifestId', 'operation', 'payloadDigest', 'planDigest', 'revision', 'schema', 'stage', 'state']);
  const failed = workspace(t); const observations = structuredClone(fixture.canary.observations);
  observations.errors.reader = 1;
  const second = await execute('canary', canaryConfig(failed, fixture, observations));
  assert.equal(second.result.state, 'failed');
});

test('authorization re-verifies the complete chain and current selector-scope freshness before writing', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = authorizationConfig(item, fixture);
  const fixed = { clock: () => new Date('2026-01-02T01:03:30Z') };
  const result = await execute('authorization', configPath, fixed);
  assert.equal(result.result.state, 'authorized');
  const stale = workspace(t); const staleConfig = authorizationConfig(stale, fixture);
  await assert.rejects(() => planM4LiveOperator({ stage: 'authorization', configPath: staleConfig },
    { clock: () => new Date('2026-01-03T00:00:01Z') }),
  { code: 'm4_live_operator_authorization_scope_stale' });
});

test('confirmation binds every private input and drift fails before artifact creation', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = canaryConfig(item, fixture);
  const plan = await planM4LiveOperator({ stage: 'canary', configPath });
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const policy = JSON.parse(fs.readFileSync(config.policyPath, 'utf8')); policy.maxSamples += 1;
  fs.writeFileSync(config.policyPath, `${JSON.stringify(policy)}\n`);
  await assert.rejects(() => runM4LiveOperator({ stage: 'canary', configPath,
    confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_live_operator_confirmation_invalid' });
  assert.equal(fs.existsSync(artifactPath(item.artifactRoot, 'canary', 'live-canary-one', 1)), false);
});

test('same-size late signing-key replacement invalidates the confirmed plan', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = reconciliationConfig(item, fixture);
  const plan = await planM4LiveOperator({ stage: 'reconciliation', configPath }, RECONCILIATION_CLOCK);
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const replacement = key('live-reconciliation-key', 99);
  const before = fs.statSync(config.reconciliationKeyPath).size;
  fs.writeFileSync(config.reconciliationKeyPath, `${JSON.stringify(replacement, null, 2)}\n`);
  assert.equal(fs.statSync(config.reconciliationKeyPath).size, before);
  await assert.rejects(() => runM4LiveOperator({ stage: 'reconciliation', configPath,
    confirmedPlanDigest: plan.confirmationDigest }, RECONCILIATION_CLOCK), { code: 'm4_live_operator_confirmation_invalid' });
});

test('zero-padded HMAC-equivalent authorities are rejected across snapshot roles', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = reconciliationConfig(item, fixture);
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const sourceKey = JSON.parse(fs.readFileSync(config.sourceSnapshotTrustAnchorPath, 'utf8'));
  const effective = Buffer.alloc(64); Buffer.from(sourceKey.key, 'base64').copy(effective);
  const equivalent = { ...sourceKey, keyId: 'live-target-snapshot-key', key: effective.toString('base64') }; effective.fill(0);
  const target = JSON.parse(fs.readFileSync(config.targetSnapshotManifestPath, 'utf8'));
  const { integrity, ...body } = target; void integrity;
  fs.writeFileSync(config.targetSnapshotTrustAnchorPath, `${JSON.stringify(equivalent)}\n`);
  fs.writeFileSync(config.targetSnapshotManifestPath, `${JSON.stringify(createM4ReconciliationSnapshot(body, equivalent))}\n`);
  refreshBundleMarker(config, 'target');
  await assert.rejects(() => planM4LiveOperator({ stage: 'reconciliation', configPath }, RECONCILIATION_CLOCK),
    { code: 'm4_live_operator_reconciliation_key_separation_invalid' });
});

test('private files reject broad modes and symlink components', async t => {
  const item = workspace(t); const fixture = await m4CutoverFixture(); const configPath = recoveryConfig(item, fixture);
  fs.chmodSync(configPath, 0o640);
  await assert.rejects(() => planM4LiveOperator({ stage: 'recovery', configPath }),
    { code: 'm4_live_operator_recovery_config_invalid' });
  fs.chmodSync(configPath, 0o600);
  const alias = path.join(item.root, 'config-link.json'); fs.symlinkSync(configPath, alias);
  await assert.rejects(() => planM4LiveOperator({ stage: 'recovery', configPath: alias }),
    { code: 'm4_live_operator_recovery_config_invalid' });
});

test('exported artifact writer validates stage before creating directories', t => {
  const item = workspace(t);
  assert.throws(() => writePrivateArtifact(item.artifactRoot, '../escape', 'live-artifact-one', 1, { ok: true }),
    { code: 'private_artifact_target_invalid' });
  assert.equal(fs.existsSync(path.join(item.artifactRoot, 'escape')), false);
});
