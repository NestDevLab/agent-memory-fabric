import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4ReconciliationEventAccumulator,
  M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS } from '../migration/m4-reconciliation-snapshot.mjs';
import { assertPrivateFileIdentity, canonicalDigest, openPrivateDigest, validateArtifactRoot } from './private-artifacts.mjs';

const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function fsyncDirectory(target) {
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}
function privateDirectory(target, code) {
  let stat; try { stat = fs.lstatSync(target); } catch { fail(code); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
    || (stat.mode & 0o077) !== 0) fail(code);
}
function ensureDirectory(parent, name, code) {
  const target = path.join(parent, name);
  try { fs.mkdirSync(target, { mode: 0o700 }); }
  catch (error) { if (error?.code !== 'EEXIST') fail(code); }
  privateDirectory(target, code); return target;
}
function writeExclusive(target, value, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, value);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
  } catch (error) {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    if (error?.code === 'EEXIST') fail('m4_snapshot_bundle_target_exists');
    if (error?.code?.startsWith?.('m4_snapshot_bundle_')) throw error;
    fail(code);
  }
}
function safeUnlink(target) { try { fs.unlinkSync(target); } catch {} }
function safeRemoveDirectory(target) { try { fs.rmdirSync(target); } catch {} }

export function createPrivateM4SnapshotSpool({ artifactRoot, bundleId,
  maxEvents = M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS } = {}) {
  const code = 'm4_snapshot_bundle_config_invalid';
  const root = validateArtifactRoot(artifactRoot, code);
  if (typeof bundleId !== 'string' || !ID.test(bundleId) || !Number.isSafeInteger(maxEvents)
    || maxEvents < 0 || maxEvents > M4_RECONCILIATION_SNAPSHOT_MAX_EVENTS) fail(code);
  const m4Root = ensureDirectory(root, 'm4', code);
  const snapshotsRoot = ensureDirectory(m4Root, 'snapshots', code);
  const stagingRoot = ensureDirectory(m4Root, 'snapshot-staging', code);
  const targetRoot = path.join(snapshotsRoot, bundleId);
  if (fs.existsSync(targetRoot)) fail('m4_snapshot_bundle_target_exists');
  const staging = path.join(stagingRoot, `.${bundleId}.${process.pid}.${crypto.randomBytes(12).toString('hex')}`);
  try { fs.mkdirSync(staging, { mode: 0o700 }); } catch { fail('m4_snapshot_bundle_staging_failed'); }
  const stagingEvents = path.join(staging, 'events.jsonl');
  let descriptor;
  try {
    descriptor = fs.openSync(stagingEvents, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  } catch { safeRemoveDirectory(staging); fail('m4_snapshot_bundle_staging_failed'); }
  const fileHash = crypto.createHash('sha256');
  const accumulator = createM4ReconciliationEventAccumulator();
  let count = 0; let state = 'open'; let finished;

  async function abort() {
    if (state === 'published' || state === 'aborted') return;
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} descriptor = undefined; }
    safeUnlink(stagingEvents);
    for (const name of ['revision.json', 'snapshot.json', 'complete.json']) safeUnlink(path.join(staging, name));
    safeRemoveDirectory(staging); state = 'aborted';
  }

  return {
    async append(event) {
      if (state !== 'open' || !plain(event) || count >= maxEvents) fail('m4_snapshot_bundle_append_invalid');
      const encoded = `${canonicalJson(event)}\n`;
      try { accumulator.add(event); fs.writeSync(descriptor, encoded, null, 'utf8'); fileHash.update(encoded, 'utf8'); }
      catch (error) { if (error?.code?.startsWith?.('m4_')) throw error; fail('m4_snapshot_bundle_write_failed'); }
      count += 1;
    },
    async finish() {
      if (state !== 'open') fail('m4_snapshot_bundle_finish_invalid');
      try { fs.fsyncSync(descriptor); fs.closeSync(descriptor); descriptor = undefined; }
      catch { await abort(); fail('m4_snapshot_bundle_write_failed'); }
      const set = accumulator.finish();
      finished = { eventsPath: stagingEvents, eventFileDigest: `sha256:${fileHash.digest('hex')}`,
        eventCount: count, eventSetDigest: set.eventSetDigest };
      state = 'finished'; return structuredClone(finished);
    },
    async publish(value) {
      if (state !== 'finished' || !exact(value, ['revision', 'snapshot'])) fail('m4_snapshot_bundle_publish_invalid');
      if (!plain(value.snapshot) || value.snapshot.eventFileDigest !== finished.eventFileDigest
        || value.snapshot.eventCount !== finished.eventCount
        || value.snapshot.eventSetDigest !== finished.eventSetDigest) fail('m4_snapshot_bundle_publish_invalid');
      const revisionPath = path.join(staging, 'revision.json');
      const snapshotPath = path.join(staging, 'snapshot.json');
      const markerPath = path.join(staging, 'complete.json');
      const marker = { schema: 'amf.m4-snapshot-bundle/v1', bundleId,
        eventFileDigest: finished.eventFileDigest, eventCount: finished.eventCount,
        eventSetDigest: finished.eventSetDigest,
        revisionDigest: `sha256:${crypto.createHash('sha256').update(canonicalJson(value.revision), 'utf8').digest('hex')}`,
        snapshotDigest: `sha256:${crypto.createHash('sha256').update(canonicalJson(value.snapshot), 'utf8').digest('hex')}` };
      const created = [];
      try {
        writeExclusive(revisionPath, `${JSON.stringify(value.revision, null, 2)}\n`, 'm4_snapshot_bundle_publish_failed');
        writeExclusive(snapshotPath, `${JSON.stringify(value.snapshot, null, 2)}\n`, 'm4_snapshot_bundle_publish_failed');
        writeExclusive(markerPath, `${JSON.stringify(marker, null, 2)}\n`, 'm4_snapshot_bundle_publish_failed');
        fsyncDirectory(staging);
        fs.mkdirSync(targetRoot, { mode: 0o700 });
        for (const name of ['events.jsonl', 'revision.json', 'snapshot.json']) {
          fs.linkSync(path.join(staging, name), path.join(targetRoot, name)); created.push(name);
        }
        fsyncDirectory(targetRoot);
        fs.linkSync(markerPath, path.join(targetRoot, 'complete.json')); created.push('complete.json');
        fsyncDirectory(targetRoot); fsyncDirectory(snapshotsRoot);
      } catch (error) {
        for (const name of created.reverse()) safeUnlink(path.join(targetRoot, name));
        safeRemoveDirectory(targetRoot);
        if (error?.code === 'EEXIST') fail('m4_snapshot_bundle_target_exists');
        if (error?.code?.startsWith?.('m4_snapshot_bundle_')) throw error;
        fail('m4_snapshot_bundle_publish_failed');
      }
      for (const name of ['events.jsonl', 'revision.json', 'snapshot.json', 'complete.json']) safeUnlink(path.join(staging, name));
      safeRemoveDirectory(staging); state = 'published';
      return { eventsPath: path.join(targetRoot, 'events.jsonl'), revisionPath: path.join(targetRoot, 'revision.json'),
        snapshotPath: path.join(targetRoot, 'snapshot.json'), completionPath: path.join(targetRoot, 'complete.json') };
    },
    abort,
  };
}

export function openPrivateM4SnapshotBundle({ eventsPath, revisionPath, snapshotPath } = {}) {
  const code = 'm4_snapshot_bundle_invalid';
  if (![eventsPath, revisionPath, snapshotPath].every(target => typeof target === 'string' && path.isAbsolute(target))) fail(code);
  const directory = path.dirname(eventsPath);
  if (path.dirname(revisionPath) !== directory || path.dirname(snapshotPath) !== directory
    || path.basename(eventsPath) !== 'events.jsonl' || path.basename(revisionPath) !== 'revision.json'
    || path.basename(snapshotPath) !== 'snapshot.json') fail(code);
  validateArtifactRoot(directory, code);
  const markerPath = path.join(directory, 'complete.json');
  const identities = [];
  try {
    const events = openPrivateDigest(eventsPath, code, { minBytes: 0, maxBytes: 4 * 1024 * 1024 * 1024 }); identities.push(events);
    const revisionFile = openPrivateDigest(revisionPath, code); identities.push(revisionFile);
    const snapshotFile = openPrivateDigest(snapshotPath, code); identities.push(snapshotFile);
    const markerFile = openPrivateDigest(markerPath, code); identities.push(markerFile);
    const inodeKeys = identities.map(identity => `${identity.stat.dev}\0${identity.stat.ino}`);
    if (new Set(inodeKeys).size !== inodeKeys.length) fail(code);
    let marker; let revision; let snapshot;
    try {
      revision = JSON.parse(fs.readFileSync(revisionFile.descriptor, 'utf8'));
      snapshot = JSON.parse(fs.readFileSync(snapshotFile.descriptor, 'utf8'));
      marker = JSON.parse(fs.readFileSync(markerFile.descriptor, 'utf8'));
    } catch { fail(code); }
    for (const identity of identities) assertPrivateFileIdentity(identity, code);
  if (!exact(marker, ['schema', 'bundleId', 'eventFileDigest', 'eventCount', 'eventSetDigest',
    'revisionDigest', 'snapshotDigest']) || marker.schema !== 'amf.m4-snapshot-bundle/v1'
    || typeof marker.bundleId !== 'string' || !ID.test(marker.bundleId)
    || path.basename(directory) !== marker.bundleId
    || ![marker.eventFileDigest, marker.eventSetDigest, marker.revisionDigest, marker.snapshotDigest]
      .every(value => typeof value === 'string' && DIGEST.test(value))
    || !Number.isSafeInteger(marker.eventCount) || marker.eventCount < 0
    || marker.eventFileDigest !== events.digest || marker.revisionDigest !== canonicalDigest(revision)
    || marker.snapshotDigest !== canonicalDigest(snapshot) || snapshot.eventFileDigest !== marker.eventFileDigest
    || snapshot.eventSetDigest !== marker.eventSetDigest || snapshot.eventCount !== marker.eventCount) fail(code);
    const assertCurrent = () => { for (const identity of identities) assertPrivateFileIdentity(identity, code); };
    let closed = false;
    const close = () => {
      if (closed) return; closed = true;
      for (const identity of identities) { try { fs.closeSync(identity.descriptor); } catch {} }
    };
    return { marker: structuredClone(marker), markerPath, markerDigest: canonicalDigest(marker),
      markerFileDigest: markerFile.digest, revision: structuredClone(revision), revisionFileDigest: revisionFile.digest,
      snapshot: structuredClone(snapshot), snapshotFileDigest: snapshotFile.digest,
      eventFileDigest: events.digest, eventIdentity: events, assertCurrent, close };
  } catch (error) {
    for (const identity of identities) { try { fs.closeSync(identity.descriptor); } catch {} }
    if (error?.code === code) throw error;
    fail(code);
  }
}

export function verifyPrivateM4SnapshotBundle(input = {}) {
  const opened = openPrivateM4SnapshotBundle(input);
  try { return { marker: structuredClone(opened.marker), markerPath: opened.markerPath,
    markerDigest: opened.markerDigest }; }
  finally { opened.close(); }
}
