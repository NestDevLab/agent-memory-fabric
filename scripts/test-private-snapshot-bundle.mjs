import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createPrivateM4SnapshotSpool, openPrivateM4SnapshotBundle,
  verifyPrivateM4SnapshotBundle } from '../src/operator/private-snapshot-bundle.mjs';

function temporary() { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-bundle-')); fs.chmodSync(root, 0o700); return root; }
const event = number => ({ eventId: `cevt_test${String(number).padStart(4, '0')}`, payloadDigest: `sha256:${'1'.repeat(64)}`,
  logicalDigest: `sha256:${'2'.repeat(64)}`, sourceOccurredAt: '2026-07-22T00:00:00Z',
  occurredAt: '2026-07-22T00:00:01Z', state: 'active' });

test('bundle is owner-only and becomes valid only when the completion marker is linked last', async t => {
  const root = temporary(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const spool = createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'source-snapshot' });
  await spool.append(event(1)); const finished = await spool.finish();
  assert.equal(fs.existsSync(path.join(root, 'm4/snapshots/source-snapshot')), false);
  assert.equal(fs.statSync(finished.eventsPath).mode & 0o077, 0);
  const finishedCopy = structuredClone(finished);
  const published = await spool.publish({ revision: { kind: 'revision' }, snapshot: { kind: 'snapshot',
    eventFileDigest: finishedCopy.eventFileDigest, eventCount: finishedCopy.eventCount,
    eventSetDigest: finishedCopy.eventSetDigest } });
  assert.equal(fs.existsSync(published.completionPath), true);
  assert.equal(fs.statSync(path.dirname(published.eventsPath)).mode & 0o077, 0);
  assert.equal(fs.statSync(published.eventsPath).mode & 0o077, 0);
  assert.equal(fs.readFileSync(published.eventsPath, 'utf8').includes('cevt_test0001'), true);
  assert.equal(verifyPrivateM4SnapshotBundle(published).marker.eventCount, 1);
  fs.writeFileSync(published.completionPath, '{}\n', { mode: 0o600 });
  assert.throws(() => verifyPrivateM4SnapshotBundle(published), { code: 'm4_snapshot_bundle_invalid' });
});

test('ordering, limits, duplicate publication and abort fail closed', async t => {
  const root = temporary(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const unordered = createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'unordered-snapshot' });
  await unordered.append(event(2));
  await assert.rejects(() => unordered.append(event(1)), { code: 'm4_reconciliation_snapshot_event_order_invalid' });
  await unordered.abort();
  const limited = createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'limited-snapshot', maxEvents: 1 });
  await limited.append(event(1));
  await assert.rejects(() => limited.append(event(2)), { code: 'm4_snapshot_bundle_append_invalid' });
  await limited.abort();
  const existing = path.join(root, 'm4/snapshots/existing-snapshot'); fs.mkdirSync(existing, { mode: 0o700 });
  assert.throws(() => createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'existing-snapshot' }),
    { code: 'm4_snapshot_bundle_target_exists' });
  const inconsistent = createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'inconsistent-snapshot' });
  await inconsistent.append(event(1)); const finished = await inconsistent.finish();
  await assert.rejects(() => inconsistent.publish({ revision: { kind: 'revision' }, snapshot: {
    eventFileDigest: finished.eventFileDigest, eventCount: finished.eventCount + 1,
    eventSetDigest: finished.eventSetDigest } }), { code: 'm4_snapshot_bundle_publish_invalid' });
  assert.equal(fs.existsSync(path.join(root, 'm4/snapshots/inconsistent-snapshot')), false);
  await inconsistent.publish({ revision: { kind: 'revision' }, snapshot: {
    eventFileDigest: finished.eventFileDigest, eventCount: finished.eventCount,
    eventSetDigest: finished.eventSetDigest } });
});

test('an opened bundle remains pinned when its pathname is replaced', async t => {
  const root = temporary(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const spool = createPrivateM4SnapshotSpool({ artifactRoot: root, bundleId: 'pinned-bundle' });
  await spool.append(event(1)); const finished = await spool.finish();
  const published = await spool.publish({ revision: { kind: 'revision' }, snapshot: { kind: 'snapshot',
    eventFileDigest: finished.eventFileDigest, eventCount: finished.eventCount,
    eventSetDigest: finished.eventSetDigest } });
  const opened = openPrivateM4SnapshotBundle(published); const directory = path.dirname(published.eventsPath);
  const moved = `${directory}-moved`; fs.renameSync(directory, moved); fs.mkdirSync(directory, { mode: 0o700 });
  opened.assertCurrent(); assert.equal(opened.revision.kind, 'revision'); opened.close();
  assert.equal(fs.existsSync(path.join(moved, 'events.jsonl')), true);
});
