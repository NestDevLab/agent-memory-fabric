import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

import { installRelease } from '../deploy/amf-install-release.mjs';

function write(path, contents = 'fixture\n') {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, contents);
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'amf-safe-deploy-'));
  const releaseRoot = join(root, 'agent-memory-fabric');
  const backupRoot = join(root, 'backups');
  const source = join(root, 'source');
  const archivePath = join(root, 'release.tar');
  mkdirSync(releaseRoot, { mode: 0o711 });
  chmodSync(releaseRoot, 0o711);

  write(join(releaseRoot, '.env'), 'private-env\n');
  write(join(releaseRoot, '.env.runtime'), 'runtime-env\n');
  write(join(releaseRoot, 'runtime/secrets/key'), 'secret\n');
  write(join(releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'ciphertext\n');
  write(join(releaseRoot, 'src/removed.mjs'), 'old\n');
  write(join(releaseRoot, '.amf-release-manifest.json'), JSON.stringify({
    schema: 'amf.release_manifest/v1',
    revision: 'old',
    files: ['src/removed.mjs']
  }));

  write(join(source, 'Dockerfile'));
  write(join(source, 'compose.agent-memory-fabric.yml'));
  write(join(source, 'package.json'), '{"name":"fixture"}\n');
  write(join(source, 'deploy/tmpfiles.d/agent-memory-fabric.conf'));
  write(join(source, 'scripts/amf-verify-deployment-mode.mjs'));
  write(join(source, 'src/current.mjs'), 'new\n');
  const tar = spawnSync('tar', ['-cf', archivePath, '-C', source, '.']);
  assert.equal(tar.status, 0);

  return { root, releaseRoot, backupRoot, source, archivePath };
}

function inode(path) {
  const stat = lstatSync(path);
  return `${stat.dev}:${stat.ino}`;
}

test('installs code in place while preserving runtime configuration and raw data', () => {
  const item = fixture();
  try {
    const before = {
      env: inode(join(item.releaseRoot, '.env')),
      runtimeEnv: inode(join(item.releaseRoot, '.env.runtime')),
      runtime: inode(join(item.releaseRoot, 'runtime')),
      data: inode(join(item.releaseRoot, 'var/agent-memory-fabric'))
    };
    const result = installRelease({
      ...item,
      revision: 'new-revision',
      expectedUid: process.getuid(),
      expectedGid: process.getgid(),
      clock: () => new Date('2026-07-20T13:00:00.000Z')
    });

    assert.equal(result.dataIdentityPreserved, true);
    assert.equal(result.rootMode, '0711');
    assert.equal(existsSync(join(item.releaseRoot, 'src/current.mjs')), true);
    assert.equal(existsSync(join(item.releaseRoot, 'src/removed.mjs')), false);
    assert.equal(readFileSync(join(item.releaseRoot, '.env'), 'utf8'), 'private-env\n');
    assert.equal(readFileSync(join(item.releaseRoot, '.env.runtime'), 'utf8'), 'runtime-env\n');
    assert.equal(readFileSync(join(item.releaseRoot, 'runtime/secrets/key'), 'utf8'), 'secret\n');
    assert.equal(readFileSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'utf8'), 'ciphertext\n');
    assert.deepEqual({
      env: inode(join(item.releaseRoot, '.env')),
      runtimeEnv: inode(join(item.releaseRoot, '.env.runtime')),
      runtime: inode(join(item.releaseRoot, 'runtime')),
      data: inode(join(item.releaseRoot, 'var/agent-memory-fabric'))
    }, before);
    assert.equal(existsSync(join(result.backupPath, '.env')), true);
    assert.equal(existsSync(join(result.backupPath, '.env.runtime')), true);
    assert.equal(existsSync(join(result.backupPath, 'runtime/secrets/key')), true);
    assert.equal(existsSync(join(result.backupPath, 'var')), false);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects an archive that contains a persistent path', () => {
  const item = fixture();
  try {
    write(join(item.source, 'var/agent-memory-fabric/raw/poison'), 'bad\n');
    const tar = spawnSync('tar', ['-cf', item.archivePath, '-C', item.source, '.']);
    assert.equal(tar.status, 0);
    assert.throws(() => installRelease({
      ...item,
      revision: 'bad-revision',
      dryRun: true,
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'release_archive_contains_persistent_path' });
    assert.equal(readFileSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'utf8'), 'ciphertext\n');
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('dry-run validates the release without creating a backup or changing live code', () => {
  const item = fixture();
  try {
    const result = installRelease({
      ...item,
      revision: 'dry-run-revision',
      dryRun: true,
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    });
    assert.equal(result.mode, 'dry-run');
    assert.equal(existsSync(item.backupRoot), false);
    assert.equal(existsSync(join(item.releaseRoot, 'src/current.mjs')), false);
    assert.equal(readFileSync(join(item.releaseRoot, 'src/removed.mjs'), 'utf8'), 'old\n');
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('refuses a concurrent deployment lock', () => {
  const item = fixture();
  try {
    mkdirSync(join(item.root, '.agent-memory-fabric.deploy.lock'), { mode: 0o700 });
    assert.throws(() => installRelease({
      ...item,
      revision: 'locked-revision',
      dryRun: true,
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'deploy_lock_held' });
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects existing code paths whose parent is a symlink', () => {
  const item = fixture();
  try {
    rmSync(join(item.releaseRoot, 'src'), { recursive: true });
    symlinkSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw'), join(item.releaseRoot, 'src'));
    assert.throws(() => installRelease({
      ...item,
      revision: 'symlink-revision',
      dryRun: true,
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'release_parent_path_unsafe' });
    assert.equal(readFileSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'utf8'), 'ciphertext\n');
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});
