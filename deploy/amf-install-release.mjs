#!/usr/bin/env node

import {
  chmodSync,
  chownSync,
  closeSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  rmdirSync,
  statfsSync,
  unlinkSync,
  writeFileSync,
  writeSync
} from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const MANIFEST_NAME = '.amf-release-manifest.json';
const MANIFEST_SCHEMA = 'amf.release_manifest/v1';
const PROTECTED_ROOTS = new Set(['.env', '.env.runtime', MANIFEST_NAME, 'runtime', 'var']);
const REQUIRED_RELEASE_FILES = [
  'Dockerfile',
  'compose.agent-memory-fabric.yml',
  'package.json',
  'deploy/tmpfiles.d/agent-memory-fabric.conf',
  'scripts/amf-verify-deployment-mode.mjs'
];

function failure(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function run(command, args, code, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    ...options
  });
  if (result.error || result.status !== 0) throw failure(code);
  return result.stdout || '';
}

function within(parent, candidate) {
  const child = relative(parent, candidate);
  return child === '' || (!child.startsWith(`..${sep}`) && child !== '..' && !isAbsolute(child));
}

function normalizedEntry(entry) {
  const trimmed = entry.replace(/^\.\//, '').replace(/\/$/, '');
  if (!trimmed || trimmed === '.') return null;
  if (isAbsolute(trimmed) || trimmed.includes('\0')) throw failure('release_archive_path_unsafe');
  const segments = trimmed.split('/');
  if (segments.some(segment => segment === '' || segment === '.' || segment === '..')) {
    throw failure('release_archive_path_unsafe');
  }
  if (PROTECTED_ROOTS.has(segments[0])) throw failure('release_archive_contains_persistent_path');
  return segments.join('/');
}

function validateRelativeCodePath(entry) {
  const normalized = normalizedEntry(entry);
  if (!normalized) throw failure('release_manifest_path_invalid');
  return normalized;
}

function assertNoSymlinkParents(releaseRoot, entry) {
  const segments = entry.split('/');
  let current = releaseRoot;
  for (const segment of segments.slice(0, -1)) {
    current = join(current, segment);
    if (!existsSync(current)) break;
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw failure('release_parent_path_unsafe');
  }
}

function identity(path, type) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw failure('persistent_path_symlink_forbidden');
  if (type === 'file' && !stat.isFile()) throw failure('persistent_file_invalid');
  if (type === 'directory' && !stat.isDirectory()) throw failure('persistent_directory_invalid');
  return `${stat.dev}:${stat.ino}`;
}

function walkFiles(root, current = '', output = []) {
  const directory = join(root, current);
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relativePath = current ? `${current}/${entry.name}` : entry.name;
    if (entry.isDirectory()) walkFiles(root, relativePath, output);
    else output.push(relativePath);
  }
  return output;
}

function readPreviousManifest(releaseRoot) {
  const manifestPath = join(releaseRoot, MANIFEST_NAME);
  if (!existsSync(manifestPath)) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    throw failure('release_manifest_invalid');
  }
  if (parsed?.schema !== MANIFEST_SCHEMA || !Array.isArray(parsed.files)) {
    throw failure('release_manifest_invalid');
  }
  return parsed.files.map(validateRelativeCodePath);
}

function writeFromStdin(target) {
  const descriptor = openSync(target, 'wx', 0o600);
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    while (true) {
      const count = readSync(0, buffer, 0, buffer.length, null);
      if (count === 0) break;
      writeSync(descriptor, buffer, 0, count);
    }
  } finally {
    closeSync(descriptor);
  }
}

function compactTimestamp(date) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function removeStaleFiles(releaseRoot, previousFiles, currentFiles) {
  const current = new Set(currentFiles);
  const stale = previousFiles.filter(entry => !current.has(entry));
  const parents = new Set();
  for (const entry of stale) {
    assertNoSymlinkParents(releaseRoot, entry);
    const target = resolve(releaseRoot, entry);
    if (!within(releaseRoot, target)) throw failure('release_manifest_path_invalid');
    if (!existsSync(target)) continue;
    const stat = lstatSync(target);
    if (stat.isDirectory()) throw failure('stale_release_path_invalid');
    unlinkSync(target);
    let parent = dirname(target);
    while (parent !== releaseRoot && within(releaseRoot, parent)) {
      parents.add(parent);
      parent = dirname(parent);
    }
  }
  for (const directory of [...parents].sort((a, b) => b.length - a.length)) {
    try {
      rmdirSync(directory);
    } catch (error) {
      if (!['ENOENT', 'ENOTEMPTY'].includes(error?.code)) throw error;
    }
  }
  return stale.length;
}

function enforceDeploymentRoot(releaseRoot, expectedUid, expectedGid) {
  chmodSync(releaseRoot, 0o711);
  const stat = lstatSync(releaseRoot);
  if (stat.uid !== expectedUid || stat.gid !== expectedGid) {
    chownSync(releaseRoot, expectedUid, expectedGid);
  }
}

function installReleaseUnlocked({
  archivePath,
  backupRoot,
  releaseRoot,
  revision,
  dryRun = false,
  expectedUid = 0,
  expectedGid = 0,
  clock = () => new Date()
}) {
  if (!archivePath || !backupRoot || !releaseRoot || !revision) throw failure('argument_required');
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(revision)) throw failure('revision_invalid');

  const resolvedRelease = resolve(releaseRoot);
  const resolvedBackup = resolve(backupRoot);
  if (!isAbsolute(releaseRoot) || !isAbsolute(backupRoot)) throw failure('path_must_be_absolute');
  if (within(resolvedRelease, resolvedBackup)) throw failure('backup_root_inside_release_forbidden');

  const releaseStat = lstatSync(resolvedRelease);
  if (!releaseStat.isDirectory() || releaseStat.isSymbolicLink()) throw failure('release_root_invalid');
  if (releaseStat.uid !== expectedUid || releaseStat.gid !== expectedGid) throw failure('release_root_owner_invalid');

  const persistent = {
    env: [join(resolvedRelease, '.env'), 'file'],
    runtimeEnv: [join(resolvedRelease, '.env.runtime'), 'file'],
    runtime: [join(resolvedRelease, 'runtime'), 'directory'],
    data: [join(resolvedRelease, 'var/agent-memory-fabric'), 'directory']
  };
  const before = Object.fromEntries(
    Object.entries(persistent).map(([name, [path, type]]) => [name, identity(path, type)])
  );
  const previousFiles = readPreviousManifest(resolvedRelease);

  const stage = mkdtempSync(join(dirname(resolvedRelease), '.amf-release-stage-'));
  let backupPath = null;
  let sourceMutationStarted = false;
  try {
    const stagedArchive = join(stage, 'release.tar');
    if (archivePath === '-') writeFromStdin(stagedArchive);
    else {
      try {
        copyFileSync(resolve(archivePath), stagedArchive);
      } catch {
        throw failure('release_archive_read_failed');
      }
    }

    const archiveSize = BigInt(lstatSync(stagedArchive).size);
    const filesystem = statfsSync(dirname(resolvedRelease), { bigint: true });
    const requiredFree = archiveSize * 3n + 64n * 1024n * 1024n;
    if (filesystem.bavail * filesystem.bsize < requiredFree) throw failure('release_staging_space_insufficient');

    const archiveEntries = run('tar', ['-tf', stagedArchive], 'release_archive_list_failed')
      .split('\n')
      .filter(Boolean);
    for (const entry of archiveEntries) normalizedEntry(entry);

    const extracted = join(stage, 'extracted');
    mkdirSync(extracted, { mode: 0o700 });
    run('tar', ['-xf', stagedArchive, '-C', extracted], 'release_archive_extract_failed');
    for (const required of REQUIRED_RELEASE_FILES) {
      const requiredPath = join(extracted, required);
      if (!existsSync(requiredPath) || !lstatSync(requiredPath).isFile()) {
        throw failure('release_archive_incomplete');
      }
    }
    const currentFiles = walkFiles(extracted).sort().map(validateRelativeCodePath);
    for (const entry of [...previousFiles, ...currentFiles]) assertNoSymlinkParents(resolvedRelease, entry);
    const currentFileSet = new Set(currentFiles);

    const plan = {
      ok: true,
      mode: dryRun ? 'dry-run' : 'apply',
      releaseRoot: resolvedRelease,
      revision,
      files: currentFiles.length,
      staleFiles: previousFiles.filter(entry => !currentFileSet.has(entry)).length,
      persistentPaths: Object.keys(persistent)
    };
    if (dryRun) return plan;

    mkdirSync(resolvedBackup, { recursive: true, mode: 0o700 });
    const backupStat = lstatSync(resolvedBackup);
    if (!backupStat.isDirectory() || backupStat.isSymbolicLink()) throw failure('backup_root_invalid');
    if (backupStat.uid !== expectedUid || backupStat.gid !== expectedGid || (backupStat.mode & 0o777) !== 0o700) {
      throw failure('backup_root_permissions_invalid');
    }
    backupPath = join(resolvedBackup, `config-pre-${revision}-${compactTimestamp(clock())}`);
    if (existsSync(backupPath)) throw failure('config_backup_exists');
    mkdirSync(backupPath, { mode: 0o700 });
    run('/bin/cp', [
      '-a', '--',
      persistent.env[0],
      persistent.runtimeEnv[0],
      persistent.runtime[0],
      backupPath
    ], 'config_backup_failed');

    sourceMutationStarted = true;
    run('/bin/cp', ['-a', '--', `${extracted}/.`, `${resolvedRelease}/`], 'release_copy_failed');
    enforceDeploymentRoot(resolvedRelease, expectedUid, expectedGid);
    const staleFilesRemoved = removeStaleFiles(resolvedRelease, previousFiles, currentFiles);

    const manifest = {
      schema: MANIFEST_SCHEMA,
      revision,
      installedAt: clock().toISOString(),
      files: currentFiles
    };
    const temporaryManifest = join(resolvedRelease, `${MANIFEST_NAME}.tmp`);
    writeFileSync(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
    renameSync(temporaryManifest, join(resolvedRelease, MANIFEST_NAME));

    const after = Object.fromEntries(
      Object.entries(persistent).map(([name, [path, type]]) => [name, identity(path, type)])
    );
    if (Object.keys(before).some(name => before[name] !== after[name])) {
      throw failure('persistent_path_identity_changed');
    }
    const verifiedRoot = lstatSync(resolvedRelease);
    if ((verifiedRoot.mode & 0o777) !== 0o711 || verifiedRoot.uid !== expectedUid || verifiedRoot.gid !== expectedGid) {
      throw failure('deployment_root_mode_invalid');
    }

    return {
      ...plan,
      backupPath,
      staleFilesRemoved,
      dataIdentityPreserved: true,
      rootMode: '0711'
    };
  } finally {
    if (sourceMutationStarted) enforceDeploymentRoot(resolvedRelease, expectedUid, expectedGid);
    rmSync(stage, { recursive: true, force: true });
  }
}

export function installRelease(options) {
  if (!options?.releaseRoot || !isAbsolute(options.releaseRoot)) throw failure('path_must_be_absolute');
  const resolvedRelease = resolve(options.releaseRoot);
  const lockPath = join(dirname(resolvedRelease), `.${basename(resolvedRelease)}.deploy.lock`);
  try {
    mkdirSync(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') throw failure('deploy_lock_held');
    throw error;
  }
  try {
    return installReleaseUnlocked(options);
  } finally {
    rmdirSync(lockPath);
  }
}

function parseArgs(argv) {
  const options = { archivePath: null, backupRoot: null, releaseRoot: null, revision: null, dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--dry-run') options.dryRun = true;
    else if (argument === '--archive') options.archivePath = argv[++index];
    else if (argument === '--backup-root') options.backupRoot = argv[++index];
    else if (argument === '--release-root') options.releaseRoot = argv[++index];
    else if (argument === '--revision') options.revision = argv[++index];
    else throw failure('argument_unknown');
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.getuid?.() !== 0) throw failure('root_required');
    const result = installRelease(parseArgs(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`amf-install-release: ${error?.code || 'internal_error'}\n`);
    process.exitCode = 1;
  }
}
