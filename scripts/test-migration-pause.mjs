import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createPauseManifest,
  loadVerifiedMigrationPauseFromEnv,
  verifyPauseManifest,
  verifyPauseManifestFiles,
  writeOwnerOnlyAtomic
} from '../src/migration-pause.mjs';

const checkpoint = (id, byte) => ({ id, digest: `sha256:${byte.repeat(64)}` });
const input = () => ({
  schema: 'amf.migration-pause-checkpoints/v1',
  manifestId: 'pause-manifest-test',
  revision: 3,
  keyId: 'migration-key-test',
  pause: {
    state: 'paused',
    collectorCursor: checkpoint('collector-cursor-test', '1'),
    pendingOutbox: checkpoint('pending-outbox-test', '2'),
    acknowledgements: checkpoint('acknowledgements-test', '3'),
    deadLetters: checkpoint('dead-letters-test', '4'),
    sourceCheckpoint: checkpoint('source-checkpoint-test', '5'),
    nativeTranscriptAuthority: checkpoint('native-authority-test', '6'),
    evidence: checkpoint('pause-evidence-test', '7')
  }
});
const keyDocument = () => ({
  schema: 'amf.migration-signing-key/v1',
  keyId: 'migration-key-test',
  key: Buffer.alloc(32, 9).toString('base64')
});
const conformance = JSON.parse(fs.readFileSync(new URL('./fixtures/migration-manifest-v1.conformance.json', import.meta.url), 'utf8'));

function privateJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value), { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

test('pause manifest generation and verification use the documented canonical HMAC', () => {
  const manifest = createPauseManifest(input(), keyDocument());
  const verified = verifyPauseManifest(manifest, keyDocument());
  assert.deepEqual(verified, {
    state: 'paused', health: 'degraded', verified: true,
    manifestId: 'pause-manifest-test', revision: 3, keyId: 'migration-key-test'
  });
  assert.match(manifest.integrity.payloadDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(manifest.integrity.signature, /^[A-Za-z0-9_-]{43}$/);
  const publishedPause = conformance.valid.find(item => item.phase === 'pause');
  const publishedKey = { schema: 'amf.migration-signing-key/v1', keyId: conformance.integrityTestKey.keyId, key: conformance.integrityTestKey.base64 };
  assert.equal(verifyPauseManifest(publishedPause, publishedKey).manifestId, 'pause-manifest-001');
});

test('verification rejects tampering, unknown fields, non-pause bodies, and malformed or short keys', () => {
  const manifest = createPauseManifest(input(), keyDocument());
  const tampered = structuredClone(manifest);
  tampered.pause.evidence.digest = `sha256:${'8'.repeat(64)}`;
  assert.throws(() => verifyPauseManifest(tampered, keyDocument()), { code: 'migration_pause_digest_mismatch' });
  const unknown = structuredClone(input());
  unknown.privatePayload = 'forbidden';
  assert.throws(() => createPauseManifest(unknown, keyDocument()), { code: 'migration_pause_input_invalid' });
  const nonPause = structuredClone(manifest);
  nonPause.phase = 'rollback';
  assert.throws(() => verifyPauseManifest(nonPause, keyDocument()), { code: 'migration_pause_manifest_invalid' });
  assert.throws(() => createPauseManifest(input(), { ...keyDocument(), key: Buffer.alloc(8).toString('base64') }), { code: 'migration_pause_key_invalid' });
  assert.throws(() => createPauseManifest(input(), { ...keyDocument(), key: 'not-base64' }), { code: 'migration_pause_key_invalid' });
});

test('file verification requires owner-only regular files and rejects symlinks and traversal', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-pause-files-'));
  try {
    const keyPath = path.join(directory, 'key.json');
    const manifestPath = path.join(directory, 'manifest.json');
    privateJson(keyPath, keyDocument());
    privateJson(manifestPath, createPauseManifest(input(), keyDocument()));
    assert.equal(verifyPauseManifestFiles(manifestPath, keyPath).verified, true);
    fs.chmodSync(keyPath, 0o640);
    assert.throws(() => verifyPauseManifestFiles(manifestPath, keyPath), { code: 'migration_pause_file_mode_invalid' });
    fs.chmodSync(keyPath, 0o600);
    const linkPath = path.join(directory, 'key-link.json');
    fs.symlinkSync(keyPath, linkPath);
    assert.throws(() => verifyPauseManifestFiles(manifestPath, linkPath), { code: 'migration_pause_file_unsafe' });
    const linkedDirectory = path.join(directory, 'linked-directory');
    fs.symlinkSync(directory, linkedDirectory);
    assert.throws(() => verifyPauseManifestFiles(path.join(linkedDirectory, 'manifest.json'), keyPath), { code: 'migration_pause_file_unsafe' });
    assert.throws(() => verifyPauseManifestFiles(`${directory}/../${path.basename(directory)}/manifest.json`, keyPath), { code: 'migration_pause_path_invalid' });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('owner-only output is atomic, refuses overwrite, and startup env fails closed', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-pause-output-'));
  try {
    const keyPath = path.join(directory, 'key.json');
    const manifestPath = path.join(directory, 'manifest.json');
    privateJson(keyPath, keyDocument());
    const manifest = createPauseManifest(input(), keyDocument());
    writeOwnerOnlyAtomic(manifestPath, manifest);
    assert.equal(fs.statSync(manifestPath).mode & 0o777, 0o600);
    assert.equal(fs.readdirSync(directory).some(name => name.endsWith('.tmp')), false);
    assert.throws(() => writeOwnerOnlyAtomic(manifestPath, { overwritten: true }), { code: 'migration_pause_output_exists' });
    assert.equal(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).manifestId, manifest.manifestId);
    assert.equal(loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath, AMF_MIGRATION_PAUSE_KEY_PATH: keyPath }).verified, true);
    assert.throws(() => loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath }), { code: 'migration_pause_config_incomplete' });
    privateJson(manifestPath, { ...manifest, revision: 4 });
    assert.throws(() => loadVerifiedMigrationPauseFromEnv({ AMF_MIGRATION_PAUSE_MANIFEST_PATH: manifestPath, AMF_MIGRATION_PAUSE_KEY_PATH: keyPath }), { code: 'migration_pause_digest_mismatch' });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI generation and read-only verification emit bounded output without key material', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-pause-cli-'));
  try {
    const inputPath = path.join(directory, 'input.json');
    const keyPath = path.join(directory, 'key.json');
    const manifestPath = path.join(directory, 'manifest.json');
    privateJson(inputPath, input());
    privateJson(keyPath, keyDocument());
    const script = fileURLToPath(new URL('./amf-migration-pause.mjs', import.meta.url));
    const generated = spawnSync(process.execPath, [script, 'generate', '--input', inputPath, '--key-file', keyPath, '--output', manifestPath], { encoding: 'utf8' });
    assert.equal(generated.status, 0, generated.stderr);
    assert.deepEqual(JSON.parse(generated.stdout), { ok: true, operation: 'generate', manifestId: 'pause-manifest-test', phase: 'pause', revision: 3 });
    const before = fs.readFileSync(manifestPath);
    const verified = spawnSync(process.execPath, [script, 'verify', '--manifest', manifestPath, '--key-file', keyPath], { encoding: 'utf8' });
    assert.equal(verified.status, 0, verified.stderr);
    assert.deepEqual(JSON.parse(verified.stdout), { ok: true, operation: 'verify', manifestId: 'pause-manifest-test', phase: 'pause', revision: 3, state: 'paused', health: 'degraded' });
    assert.deepEqual(fs.readFileSync(manifestPath), before);
    assert.doesNotMatch(`${generated.stdout}${generated.stderr}${verified.stdout}${verified.stderr}`, /sha256:|CQkJCQkJ/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
