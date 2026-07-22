import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { planM4ReconciliationCollection,
  runM4ReconciliationCollection } from '../src/operator/m4-reconciliation-collector-operator.mjs';
import { verifyPrivateM4SnapshotBundle } from '../src/operator/private-snapshot-bundle.mjs';

const digest = char => `sha256:${char.repeat(64)}`;
const key = (id, char) => ({ schema: 'amf.migration-signing-key/v1', keyId: id,
  key: Buffer.alloc(32, char).toString('base64') });
const checkpoint = id => ({ id, digest: digest(id === 'content-revision' ? 'a' : 'b') });
const event = { eventId: 'cevt_operator0001', payloadDigest: digest('c'), logicalDigest: digest('d'),
  sourceOccurredAt: '2026-07-22T00:00:00Z', occurredAt: '2026-07-22T00:00:01Z', state: 'active' };
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-collect-operator-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); let sequence = 0;
  const write = value => { const target = path.join(root, `input-${sequence += 1}.json`);
    fs.writeFileSync(target, `${JSON.stringify(value)}\n`, { mode: 0o600 }); return target; };
  const completion = { schema: 'test-completion/v1', state: 'complete', checkpoint: checkpoint('terminal-checkpoint') };
  const config = { schema: 'amf.m4-reconciliation-collector-operator/v1', artifactRoot: root,
    bundleId: 'operator-bundle', archive: 'v3', snapshotId: 'operator-snapshot',
    revisionManifestId: 'operator-revision', revision: 1, completionPath: write(completion),
    completionKeyPath: write(key('completion-key', 1)), revisionKeyPath: write(key('revision-key', 2)),
    snapshotKeyPath: write(key('snapshot-key', 3)), staticEvidencePath: write({ pausedInterval: {
      start: checkpoint('pause-start'), end: checkpoint('pause-end') }, replayQueues: {
      pendingOutbox: checkpoint('pending-outbox'), acknowledgements: checkpoint('acknowledgements'),
      deadLetters: checkpoint('dead-letters') }, sourceCheckpoints: { collectorCursor: checkpoint('collector-cursor'),
      sourceCheckpoint: checkpoint('source-checkpoint'), nativeTranscriptAuthority: checkpoint('native-authority') } }),
    sourceConfigPath: write({ schema: 'test-source/v1', kind: 'sqlite' }), revisionValiditySeconds: 3600, maxEvents: 100 };
  const configPath = write(config); let closed = 0; let consumed = 0;
  const dependencies = { clock: () => new Date('2026-07-22T12:00:00Z'),
    verifyNativeCompletion: value => structuredClone(value),
    async createSource() { return { revisionSource: async () => ({ state: 'complete',
      checkpoint: checkpoint('content-revision') }), events: { async *[Symbol.asyncIterator]() {
        consumed += 1; yield structuredClone(event); } }, async close() { closed += 1; } }; } };
  return { root, config, configPath, dependencies, get closed() { return closed; }, get consumed() { return consumed; } };
}

test('plan writes nothing and confirmed run publishes one complete owner-only bundle', async t => {
  const item = fixture(t); const plan = await planM4ReconciliationCollection({ configPath: item.configPath }, item.dependencies);
  assert.equal(item.consumed, 0); assert.equal(fs.existsSync(path.join(item.root, 'm4')), false);
  const result = await runM4ReconciliationCollection({ configPath: item.configPath,
    confirmedPlanDigest: plan.confirmationDigest }, item.dependencies);
  assert.equal(result.state, 'complete'); assert.equal(item.consumed, 1); assert.equal(item.closed, 1);
  const directory = path.join(item.root, 'm4/snapshots/operator-bundle');
  const verified = verifyPrivateM4SnapshotBundle({ eventsPath: path.join(directory, 'events.jsonl'),
    revisionPath: path.join(directory, 'revision.json'), snapshotPath: path.join(directory, 'snapshot.json') });
  assert.equal(verified.marker.eventCount, 1); assert.equal(JSON.stringify(result).includes(item.root), false);
  await assert.rejects(() => runM4ReconciliationCollection({ configPath: item.configPath,
    confirmedPlanDigest: plan.confirmationDigest }, item.dependencies),
  { code: 'm4_reconciliation_collector_operator_target_exists' });
});

test('confirmation drift creates no valid bundle', async t => {
  const item = fixture(t); const plan = await planM4ReconciliationCollection({ configPath: item.configPath }, item.dependencies);
  const changed = JSON.parse(fs.readFileSync(item.config.completionPath, 'utf8')); changed.extra = true;
  fs.writeFileSync(item.config.completionPath, `${JSON.stringify(changed)}\n`);
  await assert.rejects(() => runM4ReconciliationCollection({ configPath: item.configPath,
    confirmedPlanDigest: plan.confirmationDigest }, item.dependencies),
  { code: 'm4_reconciliation_collector_operator_confirmation_invalid' });
  assert.equal(fs.existsSync(path.join(item.root, 'm4/snapshots/operator-bundle/complete.json')), false);
});

test('source failure creates no valid bundle and always closes the source', async t => {
  const item = fixture(t); let closed = 0;
  const dependencies = { ...item.dependencies, async createSource() { return {
    async revisionSource() { throw new Error('private source failure'); },
    events: { async *[Symbol.asyncIterator]() {} }, async close() { closed += 1; } }; } };
  const plan = await planM4ReconciliationCollection({ configPath: item.configPath }, dependencies);
  await assert.rejects(() => runM4ReconciliationCollection({ configPath: item.configPath,
    confirmedPlanDigest: plan.confirmationDigest }, dependencies));
  assert.equal(closed, 1);
  assert.equal(fs.existsSync(path.join(item.root, 'm4/snapshots/operator-bundle/complete.json')), false);
});

test('equivalent authority keys fail before any source is opened', async t => {
  const item = fixture(t); const config = JSON.parse(fs.readFileSync(item.configPath, 'utf8'));
  const revisionKey = JSON.parse(fs.readFileSync(config.revisionKeyPath, 'utf8'));
  fs.writeFileSync(config.snapshotKeyPath, `${JSON.stringify({ ...revisionKey, keyId: 'snapshot-key' })}\n`);
  await assert.rejects(() => planM4ReconciliationCollection({ configPath: item.configPath }, item.dependencies),
    { code: 'm4_reconciliation_collector_operator_key_separation_invalid' });
  assert.equal(item.consumed, 0);
});
