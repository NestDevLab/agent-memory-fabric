import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  aggregatePauseCheckpointInputs,
  createPauseManifest,
  loadVerifiedMigrationPauseFromEnv,
  verifyAggregatePauseCheckpointInput,
  verifyPauseManifest,
  verifyPauseManifestAgainstCheckpointInputs,
  verifyPauseManifestFiles,
  writeOwnerOnlyAtomic
} from '../src/migration-pause.mjs';

const COLLECTORS = ['1', '2', '3', '4'].map(byte => `pause-collector-${byte.repeat(64)}`);
const checkpoint = (id, byte) => ({ id, digest: `sha256:${byte.repeat(64)}` });
const keyDocument = () => ({
  schema: 'amf.migration-signing-key/v1',
  keyId: 'migration-key-test',
  key: Buffer.alloc(32, 9).toString('base64')
});
const roster = (collectors = COLLECTORS) => ({
  schema: 'amf.migration-pause-collector-roster/v1',
  manifestId: 'pause-manifest-test',
  revision: 3,
  keyId: 'migration-key-test',
  collectors
});
function child(index, byte = String(index + 5)) {
  return {
    schema: 'amf.migration-pause-checkpoints/v1',
    manifestId: 'pause-manifest-test',
    revision: 3,
    keyId: 'migration-key-test',
    pause: {
      state: 'paused',
      collectorCursor: checkpoint('collector-cursor-test', byte),
      pendingOutbox: checkpoint('pending-outbox-test', byte),
      acknowledgements: checkpoint('acknowledgements-test', byte),
      deadLetters: checkpoint('dead-letters-test', byte),
      sourceCheckpoint: checkpoint('source-checkpoint-test', byte),
      nativeTranscriptAuthority: checkpoint('native-authority-test', byte),
      evidence: checkpoint(COLLECTORS[index], byte)
    }
  };
}
const children = () => COLLECTORS.map((_, index) => child(index));
const aggregateInput = () => aggregatePauseCheckpointInputs(children(), roster());
const conformance = JSON.parse(fs.readFileSync(new URL('./fixtures/migration-manifest-v1.conformance.json', import.meta.url), 'utf8'));

function privateJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value), { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-pause-set-'));
  const childPaths = children().map((value, index) => {
    const target = path.join(directory, `child-${index}.json`); privateJson(target, value); return target;
  });
  const rosterPath = path.join(directory, 'roster.json'); privateJson(rosterPath, roster());
  const aggregatePath = path.join(directory, 'aggregate.json'); privateJson(aggregatePath, aggregateInput());
  const keyPath = path.join(directory, 'key.json'); privateJson(keyPath, keyDocument());
  return { directory, childPaths, rosterPath, aggregatePath, keyPath,
    path: name => path.join(directory, name) };
}

test('four-collector aggregation is order-independent, exact, and signable', () => {
  const inputs = children(); const expectedRoster = roster();
  const aggregate = aggregatePauseCheckpointInputs(inputs, expectedRoster);
  assert.deepEqual(aggregate, aggregatePauseCheckpointInputs(inputs.toReversed(), expectedRoster));
  assert.match(aggregate.pause.evidence.id, /^pause-set-[a-f0-9]{64}$/);
  for (const [name, value] of Object.entries(aggregate.pause)) {
    if (name === 'state') continue;
    assert.match(value.id, /^[a-z][a-z0-9-]{2,79}$/);
    assert.match(value.digest, /^sha256:[a-f0-9]{64}$/);
  }
  const manifest = createPauseManifest(aggregate, keyDocument());
  assert.equal(verifyPauseManifestAgainstCheckpointInputs(manifest, keyDocument(), inputs.toReversed(), expectedRoster).verified, true);
  assert.equal(verifyAggregatePauseCheckpointInput(aggregate, inputs, expectedRoster), aggregate);
});

test('every child checkpoint and evidence digest is bound into the aggregate', () => {
  const inputs = children(); const baseline = aggregatePauseCheckpointInputs(inputs, roster());
  const changed = structuredClone(inputs); changed[1].pause.pendingOutbox.digest = `sha256:${'a'.repeat(64)}`;
  changed[1].pause.evidence.digest = `sha256:${'b'.repeat(64)}`;
  const next = aggregatePauseCheckpointInputs(changed, roster());
  assert.notEqual(next.pause.collectorCursor.digest, baseline.pause.collectorCursor.digest);
  assert.notEqual(next.pause.pendingOutbox.digest, baseline.pause.pendingOutbox.digest);
  assert.notEqual(next.pause.evidence.digest, baseline.pause.evidence.digest);
});

test('roster rejects missing, unexpected, duplicate, excessive, unsorted, and mixed children', () => {
  const inputs = children();
  assert.throws(() => aggregatePauseCheckpointInputs(inputs.slice(0, 3), roster()), { code: 'migration_pause_aggregate_count_invalid' });
  const unexpected = structuredClone(inputs); unexpected[3].pause.evidence.id = `pause-collector-${'5'.repeat(64)}`;
  assert.throws(() => aggregatePauseCheckpointInputs(unexpected, roster()), { code: 'migration_pause_aggregate_roster_mismatch' });
  const duplicate = structuredClone(inputs); duplicate[1] = child(0, 'a');
  assert.throws(() => aggregatePauseCheckpointInputs(duplicate, roster()), { code: 'migration_pause_aggregate_duplicate' });
  assert.throws(() => aggregatePauseCheckpointInputs(inputs, roster(Array.from({ length: 257 }, (_, index) => `pause-collector-${index.toString(16).padStart(64, '0')}`))), { code: 'migration_pause_roster_invalid' });
  assert.throws(() => aggregatePauseCheckpointInputs(inputs, roster(COLLECTORS.toReversed())), { code: 'migration_pause_roster_invalid' });
  const mixed = structuredClone(inputs); mixed[2].revision = 4;
  assert.throws(() => aggregatePauseCheckpointInputs(mixed, roster()), { code: 'migration_pause_aggregate_metadata_mismatch' });
});

test('same collector with different state cannot satisfy two roster members', () => {
  const inputs = children(); const secondSnapshot = child(0, 'a');
  secondSnapshot.pause.evidence.digest = `sha256:${'b'.repeat(64)}`;
  assert.notEqual(secondSnapshot.pause.evidence.digest, inputs[0].pause.evidence.digest);
  assert.equal(secondSnapshot.pause.evidence.id, inputs[0].pause.evidence.id);
  assert.throws(() => aggregatePauseCheckpointInputs([inputs[0], secondSnapshot, inputs[2], inputs[3]], roster()),
    { code: 'migration_pause_aggregate_duplicate' });
});

test('signing rejects a raw child and set verification rejects missing or changed evidence', () => {
  const inputs = children(); const aggregate = aggregatePauseCheckpointInputs(inputs, roster());
  assert.throws(() => createPauseManifest(inputs[0], keyDocument()), { code: 'migration_pause_aggregate_required' });
  assert.throws(() => createPauseManifest(structuredClone(aggregate), keyDocument()), { code: 'migration_pause_aggregate_unverified' });
  const manifest = createPauseManifest(aggregate, keyDocument());
  assert.throws(() => verifyPauseManifestAgainstCheckpointInputs(manifest, keyDocument(), inputs.slice(0, 3), roster()),
    { code: 'migration_pause_aggregate_count_invalid' });
  const changed = structuredClone(inputs); changed[0].pause.evidence.digest = `sha256:${'f'.repeat(64)}`;
  assert.throws(() => verifyPauseManifestAgainstCheckpointInputs(manifest, keyDocument(), changed, roster()),
    { code: 'migration_pause_checkpoint_set_mismatch' });
});

test('manifest HMAC verification remains compatible with the published contract', () => {
  const manifest = createPauseManifest(aggregateInput(), keyDocument());
  const verified = verifyPauseManifest(manifest, keyDocument());
  assert.deepEqual(verified, { state: 'paused', health: 'degraded', verified: true,
    manifestId: 'pause-manifest-test', revision: 3, keyId: 'migration-key-test' });
  const publishedPause = conformance.valid.find(item => item.phase === 'pause');
  const publishedKey = { schema: 'amf.migration-signing-key/v1', keyId: conformance.integrityTestKey.keyId,
    key: conformance.integrityTestKey.base64 };
  assert.equal(verifyPauseManifest(publishedPause, publishedKey).manifestId, 'pause-manifest-001');
  const tampered = structuredClone(manifest); tampered.pause.evidence.digest = `sha256:${'8'.repeat(64)}`;
  assert.throws(() => verifyPauseManifest(tampered, keyDocument()), { code: 'migration_pause_digest_mismatch' });
});

test('owner-only file verification rejects unsafe mode, symlink, traversal, and overwrite', () => {
  const setup = fixture();
  try {
    const manifestPath = setup.path('manifest.json');
    writeOwnerOnlyAtomic(manifestPath, createPauseManifest(aggregateInput(), keyDocument()));
    assert.equal(verifyPauseManifestFiles(manifestPath, setup.keyPath).verified, true);
    assert.equal(fs.statSync(manifestPath).mode & 0o777, 0o600);
    assert.throws(() => writeOwnerOnlyAtomic(manifestPath, {}), { code: 'migration_pause_output_exists' });
    fs.chmodSync(setup.keyPath, 0o640);
    assert.throws(() => verifyPauseManifestFiles(manifestPath, setup.keyPath), { code: 'migration_pause_file_mode_invalid' });
    fs.chmodSync(setup.keyPath, 0o600);
    const link = setup.path('key-link.json'); fs.symlinkSync(setup.keyPath, link);
    assert.throws(() => verifyPauseManifestFiles(manifestPath, link), { code: 'migration_pause_file_unsafe' });
    const publishedPause = conformance.valid.find(item => item.phase === 'pause');
    const legacyPath = setup.path('non-aggregate.json'); const publishedKeyPath = setup.path('published-key.json');
    privateJson(legacyPath, publishedPause);
    privateJson(publishedKeyPath, { schema: 'amf.migration-signing-key/v1', keyId: conformance.integrityTestKey.keyId,
      key: conformance.integrityTestKey.base64 });
    assert.throws(() => verifyPauseManifestFiles(legacyPath, publishedKeyPath), { code: 'migration_pause_aggregate_required' });
    assert.throws(() => verifyPauseManifestFiles(`${setup.directory}/../${path.basename(setup.directory)}/manifest.json`, setup.keyPath),
      { code: 'migration_pause_path_invalid' });
  } finally { fs.rmSync(setup.directory, { recursive: true, force: true }); }
});

test('startup fence accepts only an authenticated signed manifest pair', () => {
  const setup = fixture();
  try {
    const manifestPath = setup.path('manifest.json'); privateJson(manifestPath, createPauseManifest(aggregateInput(), keyDocument()));
    assert.equal(loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath,
      AMF_MIGRATION_PAUSE_KEY_PATH: setup.keyPath }).verified, true);
    assert.throws(() => loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath }),
      { code: 'migration_pause_config_incomplete' });
    const changed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); changed.revision = 4; privateJson(manifestPath, changed);
    assert.throws(() => loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath,
      AMF_MIGRATION_PAUSE_KEY_PATH: setup.keyPath }), { code: 'migration_pause_digest_mismatch' });
  } finally { fs.rmSync(setup.directory, { recursive: true, force: true }); }
});

test('strict CLI aggregates, signs, and recomputes the retained checkpoint set', () => {
  const setup = fixture(); const script = fileURLToPath(new URL('./amf-migration-pause.mjs', import.meta.url));
  try {
    const aggregatePath = setup.path('cli-aggregate.json'); const manifestPath = setup.path('cli-manifest.json');
    const repeatedInputs = setup.childPaths.flatMap(value => ['--input', value]);
    const aggregated = spawnSync(process.execPath, [script, 'aggregate', '--roster', setup.rosterPath,
      ...repeatedInputs, '--output', aggregatePath], { encoding: 'utf8' });
    assert.equal(aggregated.status, 0, aggregated.stderr);
    assert.deepEqual(JSON.parse(aggregated.stdout), { ok: true, operation: 'aggregate', manifestId: 'pause-manifest-test', revision: 3, collectorCount: 4 });
    const checkpoints = setup.childPaths.flatMap(value => ['--checkpoint', value]);
    const generated = spawnSync(process.execPath, [script, 'generate', '--input', aggregatePath, '--roster', setup.rosterPath,
      ...checkpoints, '--key-file', setup.keyPath, '--output', manifestPath], { encoding: 'utf8' });
    assert.equal(generated.status, 0, generated.stderr);
    const verified = spawnSync(process.execPath, [script, 'verify-set', '--manifest', manifestPath, '--roster', setup.rosterPath,
      ...repeatedInputs, '--key-file', setup.keyPath], { encoding: 'utf8' });
    assert.equal(verified.status, 0, verified.stderr);
    assert.deepEqual(JSON.parse(verified.stdout), { ok: true, operation: 'verify-set', manifestId: 'pause-manifest-test',
      phase: 'pause', revision: 3, state: 'paused', health: 'degraded', collectorCount: 4 });
    assert.doesNotMatch(`${aggregated.stdout}${aggregated.stderr}${generated.stdout}${generated.stderr}${verified.stdout}${verified.stderr}`,
      /sha256:|child-[0-9]\.json|CQkJCQkJ/);
  } finally { fs.rmSync(setup.directory, { recursive: true, force: true }); }
});

test('strict CLI rejects partial signing, unknown or duplicate flags, and oversized argv before file reads', () => {
  const setup = fixture(); const script = fileURLToPath(new URL('./amf-migration-pause.mjs', import.meta.url));
  try {
    const partial = spawnSync(process.execPath, [script, 'generate', '--input', setup.childPaths[0], '--roster', setup.rosterPath,
      ...setup.childPaths.flatMap(value => ['--checkpoint', value]), '--key-file', setup.keyPath, '--output', setup.path('partial.json')], { encoding: 'utf8' });
    assert.notEqual(partial.status, 0); assert.match(partial.stderr, /migration_pause_aggregate_required/);
    const unknown = spawnSync(process.execPath, [script, 'verify', '--manifest', setup.aggregatePath, '--key-file', setup.keyPath,
      '--extra', setup.keyPath], { encoding: 'utf8' });
    assert.notEqual(unknown.status, 0); assert.match(unknown.stderr, /migration_pause_argument_invalid/);
    const duplicate = spawnSync(process.execPath, [script, 'verify', '--manifest', setup.aggregatePath, '--manifest', setup.aggregatePath,
      '--key-file', setup.keyPath], { encoding: 'utf8' });
    assert.notEqual(duplicate.status, 0); assert.match(duplicate.stderr, /migration_pause_argument_invalid/);
    const oversized = Array.from({ length: 257 }, (_, index) => ['--input', `/missing/checkpoint-${index}.json`]).flat();
    const capped = spawnSync(process.execPath, [script, 'aggregate', '--roster', setup.rosterPath, ...oversized,
      '--output', setup.path('capped.json')], { encoding: 'utf8' });
    assert.notEqual(capped.status, 0); assert.match(capped.stderr, /migration_pause_argument_invalid/);
    assert.doesNotMatch(capped.stderr, /file_unavailable|checkpoint-256/);
  } finally { fs.rmSync(setup.directory, { recursive: true, force: true }); }
});
