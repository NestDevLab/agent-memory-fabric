import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  lstatSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

import { formatInstallError, installRelease } from '../deploy/amf-install-release.mjs';

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
  mkdirSync(backupRoot, { mode: 0o700 });
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

function sha256(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }

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
    const manifest = JSON.parse(readFileSync(join(item.releaseRoot, '.amf-release-manifest.json'), 'utf8'));
    assert.equal(manifest.schema, 'amf.release_manifest/v2');
    assert.deepEqual(manifest.files.map(item => item.path), [...manifest.files.map(item => item.path)].sort());
    assert.deepEqual(manifest.files.find(item => item.path === 'src/current.mjs'), { path: 'src/current.mjs', sha256: sha256(join(item.releaseRoot, 'src/current.mjs')) });
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('v2 manifest digests are deterministic and reveal published-file tampering', () => {
  const item = fixture();
  try {
    installRelease({ ...item, revision: 'digest-release', expectedUid: process.getuid(), expectedGid: process.getgid(), clock: () => new Date('2026-07-20T13:00:00.000Z') });
    const manifestPath = join(item.releaseRoot, '.amf-release-manifest.json');
    const first = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const current = first.files.find(item => item.path === 'src/current.mjs');
    assert.equal(current.sha256, sha256(join(item.releaseRoot, current.path)));
    writeFileSync(join(item.releaseRoot, current.path), 'tampered\n');
    assert.notEqual(current.sha256, sha256(join(item.releaseRoot, current.path)));
  } finally { rmSync(item.root, { recursive: true, force: true }); }
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
    assert.deepEqual(readdirSync(item.backupRoot), []);
    assert.equal(existsSync(join(item.releaseRoot, 'src/current.mjs')), false);
    assert.equal(readFileSync(join(item.releaseRoot, 'src/removed.mjs'), 'utf8'), 'old\n');
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('low disk rejects before backup or mutation and preserves persistent identities and bytes', () => {
  const item = fixture();
  try {
    const paths = {
      source: join(item.releaseRoot, 'src/removed.mjs'),
      env: join(item.releaseRoot, '.env'),
      runtimeEnv: join(item.releaseRoot, '.env.runtime'),
      runtime: join(item.releaseRoot, 'runtime'),
      data: join(item.releaseRoot, 'var/agent-memory-fabric'),
      raw: join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json')
    };
    const before = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, {
      inode: inode(path),
      bytes: lstatSync(path).isFile() ? readFileSync(path, 'utf8') : null
    }]));
    assert.throws(() => installRelease({
      ...item,
      revision: 'low-space',
      expectedUid: process.getuid(),
      expectedGid: process.getgid(),
      filesystemStats: () => ({ bavail: 1n, bsize: 1n })
    }), { code: 'release_staging_space_insufficient' });
    assert.deepEqual(Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, {
      inode: inode(path),
      bytes: lstatSync(path).isFile() ? readFileSync(path, 'utf8') : null
    }])), before);
    assert.deepEqual(readdirSync(item.backupRoot), []);
    assert.equal(existsSync(join(item.releaseRoot, 'src/current.mjs')), false);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects an existing destination leaf symlink without changing persistent content', () => {
  const item = fixture();
  try {
    const raw = join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json');
    const destination = join(item.releaseRoot, 'src/current.mjs');
    symlinkSync('../var/agent-memory-fabric/raw/event.enc.json', destination);
    const before = { inode: inode(raw), bytes: readFileSync(raw, 'utf8') };
    assert.throws(() => installRelease({
      ...item,
      revision: 'leaf-alias',
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'release_destination_path_unsafe' });
    assert.deepEqual({ inode: inode(raw), bytes: readFileSync(raw, 'utf8') }, before);
    assert.deepEqual(readdirSync(item.backupRoot), []);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects a legacy manifest temporary alias without changing persistent content', () => {
  const item = fixture();
  try {
    const raw = join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json');
    symlinkSync('var/agent-memory-fabric/raw/event.enc.json', join(item.releaseRoot, '.amf-release-manifest.json.tmp'));
    const before = { inode: inode(raw), bytes: readFileSync(raw, 'utf8') };
    assert.throws(() => installRelease({
      ...item,
      revision: 'manifest-alias',
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'release_manifest_temporary_path_unsafe' });
    assert.deepEqual({ inode: inode(raw), bytes: readFileSync(raw, 'utf8') }, before);
    assert.deepEqual(readdirSync(item.backupRoot), []);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects symlinked and hard-linked archive payloads', () => {
  for (const kind of ['symlink', 'hardlink']) {
    const item = fixture();
    try {
      const source = join(item.source, 'src/current.mjs');
      rmSync(source);
      if (kind === 'symlink') symlinkSync('../package.json', source);
      else linkSync(join(item.source, 'package.json'), source);
      const tar = spawnSync('tar', ['-cf', item.archivePath, '-C', item.source, '.']);
      assert.equal(tar.status, 0);
      assert.throws(() => installRelease({
        ...item,
        revision: `${kind}-archive`,
        dryRun: true,
        expectedUid: process.getuid(),
        expectedGid: process.getgid()
      }), { code: 'release_archive_entry_unsafe' });
    } finally {
      rmSync(item.root, { recursive: true, force: true });
    }
  }
});

test('ordered archive symlink pivot cannot write outside extraction', () => {
  const item = fixture();
  try {
    const attack = join(item.root, 'attack');
    const payload = join(item.root, 'payload');
    const outside = join(item.root, 'outside');
    write(join(outside, 'poison'), 'sentinel\n');
    mkdirSync(attack, { recursive: true });
    symlinkSync(outside, join(attack, 'pivot'));
    write(join(payload, 'poison'), 'overwritten\n');
    const first = spawnSync('tar', ['-cf', item.archivePath, '-C', attack, 'pivot']);
    assert.equal(first.status, 0);
    const second = spawnSync('tar', [
      '-rf', item.archivePath,
      '--transform=s|^poison$|pivot/poison|',
      '-C', payload,
      'poison'
    ]);
    assert.equal(second.status, 0);
    assert.throws(() => installRelease({
      ...item,
      revision: 'archive-pivot',
      dryRun: true,
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    }), { code: 'release_archive_extract_failed' });
    assert.equal(readFileSync(join(outside, 'poison'), 'utf8'), 'sentinel\n');
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rejects unsafe or oversized configuration before creating a backup', () => {
  for (const kind of ['symlink', 'hardlink', 'oversized']) {
    const item = fixture();
    try {
      const config = join(item.releaseRoot, 'runtime/secrets/key');
      if (kind === 'symlink') {
        rmSync(config);
        symlinkSync('../../.env', config);
      } else if (kind === 'hardlink') {
        linkSync(config, join(item.releaseRoot, 'runtime/secrets/key-copy'));
      }
      assert.throws(() => installRelease({
        ...item,
        revision: `config-${kind}`,
        dryRun: true,
        expectedUid: process.getuid(),
        expectedGid: process.getgid(),
        ...(kind === 'oversized' ? { configBackupMaxBytes: 1 } : {})
      }), { code: kind === 'oversized' ? 'config_backup_size_exceeded' : 'config_backup_entry_unsafe' });
      assert.deepEqual(readdirSync(item.backupRoot), []);
    } finally {
      rmSync(item.root, { recursive: true, force: true });
    }
  }
});

test('late failure restores replaced and removed source plus the previous manifest', () => {
  const item = fixture();
  try {
    const manifest = join(item.releaseRoot, '.amf-release-manifest.json');
    const before = {
      source: { inode: inode(join(item.releaseRoot, 'src/removed.mjs')), bytes: readFileSync(join(item.releaseRoot, 'src/removed.mjs'), 'utf8') },
      manifest: { inode: inode(manifest), bytes: readFileSync(manifest, 'utf8') },
      raw: { inode: inode(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json')), bytes: readFileSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'utf8') }
    };
    assert.throws(() => installRelease({
      ...item,
      revision: 'faulted-release',
      expectedUid: process.getuid(),
      expectedGid: process.getgid(),
      injectFault: point => { if (point === 'after_manifest_publish') throw Object.assign(new Error('injected'), { code: 'injected_failure' }); }
    }), { code: 'injected_failure' });
    assert.deepEqual({
      source: { inode: inode(join(item.releaseRoot, 'src/removed.mjs')), bytes: readFileSync(join(item.releaseRoot, 'src/removed.mjs'), 'utf8') },
      manifest: { inode: inode(manifest), bytes: readFileSync(manifest, 'utf8') },
      raw: { inode: inode(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json')), bytes: readFileSync(join(item.releaseRoot, 'var/agent-memory-fabric/raw/event.enc.json'), 'utf8') }
    }, before);
    assert.equal(existsSync(join(item.releaseRoot, 'src/current.mjs')), false);
    assert.equal(lstatSync(item.releaseRoot).mode & 0o7777, 0o711);
  } finally {
    rmSync(item.root, { recursive: true, force: true });
  }
});

test('rollback failure preserves the lock and same-filesystem recovery evidence', () => {
  const item = fixture();
  try {
    let observed;
    try {
      installRelease({
        ...item,
        revision: 'rollback-failure',
        expectedUid: process.getuid(),
        expectedGid: process.getgid(),
        injectFault: point => {
          if (point === 'after_manifest_publish' || point === 'before_rollback_record') {
            throw Object.assign(new Error('injected'), { code: 'injected_failure' });
          }
        }
      });
    } catch (error) {
      observed = error;
    }
    assert.equal(observed?.code, 'release_rollback_failed');
    assert.equal(observed?.recoveryRequired, true);
    assert.equal(existsSync(observed?.recoveryPath), true);
    assert.equal(existsSync(join(observed.recoveryPath, 'rollback')), true);
    assert.equal(existsSync(join(item.root, '.agent-memory-fabric.deploy.lock')), true);
    const cliReport = formatInstallError(observed);
    assert.equal(cliReport.split('\n').filter(Boolean).length, 1);
    assert.deepEqual(JSON.parse(cliReport.replace(/^amf-install-release: /, '')), {
      error: 'release_rollback_failed',
      recoveryRequired: true,
      recoveryPath: observed.recoveryPath
    });
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
