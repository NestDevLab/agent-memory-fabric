#!/usr/bin/env node

import {
  chmodSync,
  chownSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statfsSync,
  unlinkSync,
  writeSync
} from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const MANIFEST_NAME = '.amf-release-manifest.json';
const MANIFEST_SCHEMA = 'amf.release_manifest/v2';
const LEGACY_MANIFEST_SCHEMA = 'amf.release_manifest/v1';
const PROTECTED_ROOTS = new Set(['.env', '.env.runtime', MANIFEST_NAME, 'runtime', 'var']);
const REQUIRED_RELEASE_FILES = [
  'Dockerfile',
  'compose.agent-memory-fabric.yml',
  'package.json',
  'deploy/tmpfiles.d/agent-memory-fabric.conf',
  'scripts/amf-verify-deployment-mode.mjs'
];
export const DEFAULT_CONFIG_BACKUP_MAX_BYTES = 16 * 1024 * 1024;
export const DEFAULT_CONFIG_BACKUP_MAX_FILES = 4096;

function failure(code, cause = null) {
  const error = new Error(code, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function run(command, args, code, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    ...options
  });
  if (result.error || result.status !== 0) throw failure(code, result.error);
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

function manifestRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== 2 || typeof value.path !== 'string'
    || typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256)) {
    throw failure('release_manifest_invalid');
  }
  const path = validateRelativeCodePath(value.path);
  if (value.path !== path) throw failure('release_manifest_invalid');
  return { path, sha256: value.sha256 };
}

function fileSha256(path) {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const hash = createHash('sha256'); const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    while (true) { const count = readSync(descriptor, buffer, 0, buffer.length, null); if (count === 0) break; hash.update(buffer.subarray(0, count)); }
    return hash.digest('hex');
  } finally { closeSync(descriptor); }
}

function ordinaryFile(path, code) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) throw failure(code);
  return stat;
}

function ordinaryDirectory(path, code) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw failure(code);
  return stat;
}

function identity(path, type) {
  if (type === 'optional-directory') {
    try {
      lstatSync(path);
    } catch (error) {
      if (error?.code === 'ENOENT') return 'absent';
      throw error;
    }
  }
  const stat = type === 'file'
    ? ordinaryFile(path, 'persistent_file_invalid')
    : ordinaryDirectory(path, 'persistent_directory_invalid');
  return `${stat.dev}:${stat.ino}`;
}

function assertSafeParents(root, entry, code = 'release_parent_path_unsafe') {
  const segments = entry.split('/');
  let current = root;
  for (const segment of segments.slice(0, -1)) {
    current = join(current, segment);
    if (!existsSync(current)) break;
    ordinaryDirectory(current, code);
  }
}

function inspectReleaseTree(root, current = '', output = { files: [], directories: [] }) {
  const directory = join(root, current);
  for (const entry of readdirSync(directory)) {
    const relativePath = current ? `${current}/${entry}` : entry;
    const path = join(root, relativePath);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw failure('release_archive_entry_unsafe');
    if (stat.isDirectory()) {
      output.directories.push(relativePath);
      inspectReleaseTree(root, relativePath, output);
    } else if (stat.isFile() && stat.nlink === 1) {
      output.files.push(relativePath);
    } else {
      throw failure('release_archive_entry_unsafe');
    }
  }
  return output;
}

function readPreviousManifest(releaseRoot) {
  const manifestPath = join(releaseRoot, MANIFEST_NAME);
  if (!existsSync(manifestPath)) return [];
  ordinaryFile(manifestPath, 'release_manifest_invalid');
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    throw failure('release_manifest_invalid');
  }
  if (!Array.isArray(parsed?.files) || ![MANIFEST_SCHEMA, LEGACY_MANIFEST_SCHEMA].includes(parsed.schema)) {
    throw failure('release_manifest_invalid');
  }
  const files = parsed.schema === LEGACY_MANIFEST_SCHEMA
    ? parsed.files.map(validateRelativeCodePath)
    : parsed.files.map(manifestRecord).map(record => record.path);
  if (new Set(files).size !== files.length || files.some((entry, index) => index > 0 && files[index - 1] >= entry)) {
    throw failure('release_manifest_invalid');
  }
  return files;
}

function writeFromStdin(target) {
  const descriptor = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    while (true) {
      const count = readSync(0, buffer, 0, buffer.length, null);
      if (count === 0) break;
      writeAll(descriptor, buffer.subarray(0, count));
    }
  } finally {
    closeSync(descriptor);
  }
}

function writeAll(descriptor, value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  let offset = 0;
  while (offset < buffer.length) {
    const written = writeSync(descriptor, buffer, offset, buffer.length - offset);
    if (written < 1) throw failure('file_write_incomplete');
    offset += written;
  }
}

function compactTimestamp(date) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function inspectConfiguration(persistent, maxBytes, maxFiles) {
  const entries = [];
  let bytes = 0;
  let files = 0;
  const addFile = (source, relativePath) => {
    const stat = ordinaryFile(source, 'config_backup_entry_unsafe');
    bytes += stat.size;
    files += 1;
    if (bytes > maxBytes) throw failure('config_backup_size_exceeded');
    if (files > maxFiles) throw failure('config_backup_file_count_exceeded');
    entries.push({ type: 'file', source, relativePath, stat });
  };
  const walk = (source, relativePath) => {
    const stat = ordinaryDirectory(source, 'config_backup_entry_unsafe');
    entries.push({ type: 'directory', source, relativePath, stat });
    for (const name of readdirSync(source)) {
      if (relativePath === 'runtime' && name === 'm4') continue;
      const childSource = join(source, name);
      const childRelative = `${relativePath}/${name}`;
      const childStat = lstatSync(childSource);
      if (childStat.isSymbolicLink()) throw failure('config_backup_entry_unsafe');
      if (childStat.isDirectory()) walk(childSource, childRelative);
      else if (childStat.isFile()) addFile(childSource, childRelative);
      else throw failure('config_backup_entry_unsafe');
    }
  };
  addFile(persistent.env[0], '.env');
  addFile(persistent.runtimeEnv[0], '.env.runtime');
  walk(persistent.runtime[0], 'runtime');
  return { entries, bytes, files };
}

function copyOpenFile(entry, target) {
  const sourceDescriptor = openSync(entry.source, constants.O_RDONLY | constants.O_NOFOLLOW);
  let targetDescriptor = null;
  try {
    const current = fstatSync(sourceDescriptor);
    if (!current.isFile() || current.nlink !== 1 || current.dev !== entry.stat.dev || current.ino !== entry.stat.ino) {
      throw failure('config_backup_entry_changed');
    }
    targetDescriptor = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < entry.stat.size) {
      const requested = Math.min(buffer.length, entry.stat.size - position);
      const count = readSync(sourceDescriptor, buffer, 0, requested, position);
      if (count === 0) throw failure('config_backup_entry_changed');
      writeAll(targetDescriptor, buffer.subarray(0, count));
      position += count;
    }
    if (readSync(sourceDescriptor, buffer, 0, 1, position) !== 0) throw failure('config_backup_entry_changed');
    const after = fstatSync(sourceDescriptor);
    if (after.dev !== entry.stat.dev || after.ino !== entry.stat.ino || after.size !== entry.stat.size
      || after.mtimeMs !== entry.stat.mtimeMs || after.ctimeMs !== entry.stat.ctimeMs) {
      throw failure('config_backup_entry_changed');
    }
    fchmodSync(targetDescriptor, entry.stat.mode & 0o777);
    fchownSync(targetDescriptor, entry.stat.uid, entry.stat.gid);
  } finally {
    if (targetDescriptor !== null) closeSync(targetDescriptor);
    closeSync(sourceDescriptor);
  }
}

function createConfigurationBackup(backupPath, inventory) {
  mkdirSync(backupPath, { mode: 0o700 });
  for (const entry of inventory.entries.filter(item => item.type === 'directory')) {
    const current = lstatSync(entry.source);
    if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== entry.stat.dev || current.ino !== entry.stat.ino) {
      throw failure('config_backup_entry_changed');
    }
    const target = join(backupPath, entry.relativePath);
    mkdirSync(target, { mode: entry.stat.mode & 0o777 });
    chmodSync(target, entry.stat.mode & 0o777);
    chownSync(target, entry.stat.uid, entry.stat.gid);
  }
  for (const entry of inventory.entries.filter(item => item.type === 'file')) {
    copyOpenFile(entry, join(backupPath, entry.relativePath));
  }
}

function validateDestinationLayout(releaseRoot, currentDirectories, currentFiles, previousFiles) {
  for (const entry of currentDirectories) {
    assertSafeParents(releaseRoot, `${entry}/placeholder`);
    const target = join(releaseRoot, entry);
    if (existsSync(target)) ordinaryDirectory(target, 'release_destination_path_unsafe');
  }
  for (const entry of new Set([...currentFiles, ...previousFiles])) {
    assertSafeParents(releaseRoot, entry);
    const target = join(releaseRoot, entry);
    if (existsSync(target)) ordinaryFile(target, 'release_destination_path_unsafe');
  }
  const legacyTemporaryManifest = join(releaseRoot, `${MANIFEST_NAME}.tmp`);
  if (existsSync(legacyTemporaryManifest)) ordinaryFile(legacyTemporaryManifest, 'release_manifest_temporary_path_unsafe');
}

function ensureReleaseParents(releaseRoot, entry, createdDirectories) {
  let current = releaseRoot;
  for (const segment of entry.split('/').slice(0, -1)) {
    current = join(current, segment);
    if (!existsSync(current)) {
      mkdirSync(current, { mode: 0o755 });
      createdDirectories.push(current);
    } else {
      ordinaryDirectory(current, 'release_parent_path_unsafe');
    }
  }
}

function ensurePrivateParents(root, entry) {
  let current = root;
  for (const segment of entry.split('/').slice(0, -1)) {
    current = join(current, segment);
    if (!existsSync(current)) mkdirSync(current, { mode: 0o700 });
    else ordinaryDirectory(current, 'release_rollback_path_unsafe');
  }
}

function moveForRollback(target, rollbackRoot, entry, journal) {
  const backup = join(rollbackRoot, entry);
  ensurePrivateParents(rollbackRoot, entry);
  const hadOriginal = existsSync(target);
  if (hadOriginal) renameSync(target, backup);
  const record = { target, backup: hadOriginal ? backup : null, published: false };
  journal.push(record);
  return record;
}

function restoreJournal(journal, createdDirectories, injectFault) {
  let rollbackError = null;
  for (const record of [...journal].reverse()) {
    try {
      injectFault('before_rollback_record');
      if (record.published && existsSync(record.target)) {
        const stat = lstatSync(record.target);
        if (stat.isDirectory()) throw failure('release_rollback_target_unsafe');
        unlinkSync(record.target);
      }
      if (record.backup && existsSync(record.backup)) {
        mkdirSync(dirname(record.target), { recursive: true, mode: 0o755 });
        renameSync(record.backup, record.target);
      }
    } catch (error) {
      rollbackError ||= error;
    }
  }
  for (const directory of [...createdDirectories].reverse()) {
    try {
      rmdirSync(directory);
    } catch (error) {
      if (!['ENOENT', 'ENOTEMPTY'].includes(error?.code)) rollbackError ||= error;
    }
  }
  if (rollbackError) throw failure('release_rollback_failed', rollbackError);
}

function removeEmptyParents(releaseRoot, entries) {
  const parents = new Set();
  for (const entry of entries) {
    let parent = dirname(join(releaseRoot, entry));
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
}

function enforceDeploymentRoot(releaseRoot, expectedUid, expectedGid) {
  chmodSync(releaseRoot, 0o711);
  const stat = lstatSync(releaseRoot);
  if (stat.uid !== expectedUid || stat.gid !== expectedGid) chownSync(releaseRoot, expectedUid, expectedGid);
}

function installReleaseUnlocked({
  archivePath,
  backupRoot,
  releaseRoot,
  revision,
  dryRun = false,
  expectedUid = 0,
  expectedGid = 0,
  clock = () => new Date(),
  filesystemStats = statfsSync,
  injectFault = () => {},
  configBackupMaxBytes = DEFAULT_CONFIG_BACKUP_MAX_BYTES,
  configBackupMaxFiles = DEFAULT_CONFIG_BACKUP_MAX_FILES
}) {
  if (!archivePath || !backupRoot || !releaseRoot || !revision) throw failure('argument_required');
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(revision)) throw failure('revision_invalid');
  if (!Number.isSafeInteger(configBackupMaxBytes) || configBackupMaxBytes < 1) throw failure('config_backup_limit_invalid');
  if (!Number.isSafeInteger(configBackupMaxFiles) || configBackupMaxFiles < 1) throw failure('config_backup_limit_invalid');
  if (!isAbsolute(releaseRoot) || !isAbsolute(backupRoot)) throw failure('path_must_be_absolute');

  const lexicalRelease = resolve(releaseRoot);
  const lexicalBackup = resolve(backupRoot);
  ordinaryDirectory(lexicalRelease, 'release_root_invalid');
  ordinaryDirectory(lexicalBackup, 'backup_root_invalid');
  const resolvedRelease = realpathSync(lexicalRelease);
  const resolvedBackup = realpathSync(lexicalBackup);
  if (within(resolvedRelease, resolvedBackup)) throw failure('backup_root_inside_release_forbidden');

  const releaseStat = lstatSync(resolvedRelease);
  if (releaseStat.uid !== expectedUid || releaseStat.gid !== expectedGid) throw failure('release_root_owner_invalid');
  const backupStat = lstatSync(resolvedBackup);
  if (backupStat.uid !== expectedUid || backupStat.gid !== expectedGid || (backupStat.mode & 0o777) !== 0o700) {
    throw failure('backup_root_permissions_invalid');
  }

  const persistent = {
    env: [join(resolvedRelease, '.env'), 'file'],
    runtimeEnv: [join(resolvedRelease, '.env.runtime'), 'file'],
    runtime: [join(resolvedRelease, 'runtime'), 'directory'],
    runtimeM4: [join(resolvedRelease, 'runtime/m4'), 'optional-directory'],
    data: [join(resolvedRelease, 'var/agent-memory-fabric'), 'directory']
  };
  const before = Object.fromEntries(Object.entries(persistent).map(([name, [path, type]]) => [name, identity(path, type)]));
  const configInventory = inspectConfiguration(persistent, configBackupMaxBytes, configBackupMaxFiles);
  const previousFiles = readPreviousManifest(resolvedRelease);

  const stage = mkdtempSync(join(dirname(resolvedRelease), '.amf-release-stage-'));
  let backupPath = null;
  let sourceMutationStarted = false;
  let preserveRecovery = false;
  const journal = [];
  const createdDirectories = [];
  try {
    const stagedArchive = join(stage, 'release.tar');
    if (archivePath === '-') writeFromStdin(stagedArchive);
    else {
      try {
        copyFileSync(resolve(archivePath), stagedArchive, constants.COPYFILE_EXCL);
      } catch (error) {
        throw failure('release_archive_read_failed', error);
      }
    }

    const archiveSize = BigInt(lstatSync(stagedArchive).size);
    const filesystem = filesystemStats(dirname(resolvedRelease), { bigint: true });
    const requiredFree = archiveSize * 3n + BigInt(configInventory.bytes) + 64n * 1024n * 1024n;
    if (BigInt(filesystem.bavail) * BigInt(filesystem.bsize) < requiredFree) {
      throw failure('release_staging_space_insufficient');
    }

    const archiveEntries = run('tar', ['-tf', stagedArchive], 'release_archive_list_failed').split('\n').filter(Boolean);
    const normalizedArchiveEntries = archiveEntries.map(normalizedEntry).filter(Boolean);
    if (new Set(normalizedArchiveEntries).size !== normalizedArchiveEntries.length) throw failure('release_archive_path_duplicate');

    const extracted = join(stage, 'extracted');
    mkdirSync(extracted, { mode: 0o700 });
    run('tar', ['--no-same-owner', '--no-same-permissions', '-xf', stagedArchive, '-C', extracted], 'release_archive_extract_failed');
    const tree = inspectReleaseTree(extracted);
    const currentFiles = tree.files.sort().map(validateRelativeCodePath);
    if (new Set(currentFiles).size !== currentFiles.length) throw failure('release_manifest_invalid');
    const manifestFiles = currentFiles.map(entry => ({ path: entry, sha256: fileSha256(join(extracted, entry)) }));
    const currentDirectories = tree.directories.sort().map(validateRelativeCodePath);
    for (const required of REQUIRED_RELEASE_FILES) {
      if (!currentFiles.includes(required)) throw failure('release_archive_incomplete');
    }
    validateDestinationLayout(resolvedRelease, currentDirectories, currentFiles, previousFiles);
    const currentFileSet = new Set(currentFiles);
    const staleFiles = previousFiles.filter(entry => !currentFileSet.has(entry));

    const plan = {
      ok: true,
      mode: dryRun ? 'dry-run' : 'apply',
      releaseRoot: resolvedRelease,
      revision,
      files: currentFiles.length,
      staleFiles: staleFiles.length,
      configBackupBytes: configInventory.bytes,
      configBackupFiles: configInventory.files,
      persistentPaths: Object.keys(persistent)
    };
    if (dryRun) return plan;

    backupPath = join(resolvedBackup, `config-pre-${revision}-${compactTimestamp(clock())}`);
    if (existsSync(backupPath)) throw failure('config_backup_exists');
    createConfigurationBackup(backupPath, configInventory);

    const rollbackRoot = join(stage, 'rollback');
    mkdirSync(rollbackRoot, { mode: 0o700 });
    sourceMutationStarted = true;
    for (const entry of currentFiles) {
      ensureReleaseParents(resolvedRelease, entry, createdDirectories);
      const target = join(resolvedRelease, entry);
      const record = moveForRollback(target, rollbackRoot, entry, journal);
      renameSync(join(extracted, entry), target);
      record.published = true;
      chownSync(target, expectedUid, expectedGid);
    }
    injectFault('after_source_publish');

    for (const entry of staleFiles) {
      const target = join(resolvedRelease, entry);
      if (existsSync(target)) moveForRollback(target, rollbackRoot, `stale/${entry}`, journal);
    }
    injectFault('after_stale_move');

    const manifestPath = join(resolvedRelease, MANIFEST_NAME);
    const manifestRecord = moveForRollback(manifestPath, rollbackRoot, 'manifest/previous.json', journal);
    const temporaryManifest = join(resolvedRelease, `.${MANIFEST_NAME}.${randomUUID()}.tmp`);
    const descriptor = openSync(temporaryManifest, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    try {
      const manifest = `${JSON.stringify({
        schema: MANIFEST_SCHEMA,
        revision,
        installedAt: clock().toISOString(),
        files: manifestFiles
      }, null, 2)}\n`;
      writeAll(descriptor, manifest);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporaryManifest, manifestPath);
    manifestRecord.published = true;
    injectFault('after_manifest_publish');

    enforceDeploymentRoot(resolvedRelease, expectedUid, expectedGid);
    const after = Object.fromEntries(Object.entries(persistent).map(([name, [path, type]]) => [name, identity(path, type)]));
    if (Object.keys(before).some(name => before[name] !== after[name])) throw failure('persistent_path_identity_changed');
    injectFault('after_persistent_verify');

    const verifiedRoot = lstatSync(resolvedRelease);
    if ((verifiedRoot.mode & 0o7777) !== 0o711 || verifiedRoot.uid !== expectedUid || verifiedRoot.gid !== expectedGid) {
      throw failure('deployment_root_mode_invalid');
    }
    removeEmptyParents(resolvedRelease, staleFiles);
    return {
      ...plan,
      backupPath,
      staleFilesRemoved: staleFiles.length,
      dataIdentityPreserved: true,
      rootMode: '0711'
    };
  } catch (error) {
    if (sourceMutationStarted) {
      try {
        restoreJournal(journal, createdDirectories, injectFault);
      } catch (rollbackError) {
        preserveRecovery = true;
        const recoveryFailure = failure('release_rollback_failed', new AggregateError([error, rollbackError]));
        recoveryFailure.recoveryRequired = true;
        recoveryFailure.recoveryPath = stage;
        throw recoveryFailure;
      }
    }
    throw error;
  } finally {
    if (sourceMutationStarted) enforceDeploymentRoot(resolvedRelease, expectedUid, expectedGid);
    if (!preserveRecovery) rmSync(stage, { recursive: true, force: true });
  }
}

export function installRelease(options) {
  if (!options?.releaseRoot || !isAbsolute(options.releaseRoot)) throw failure('path_must_be_absolute');
  const lexicalRelease = resolve(options.releaseRoot);
  ordinaryDirectory(lexicalRelease, 'release_root_invalid');
  const resolvedRelease = realpathSync(lexicalRelease);
  const lockPath = join(dirname(resolvedRelease), `.${basename(resolvedRelease)}.deploy.lock`);
  try {
    mkdirSync(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') throw failure('deploy_lock_held');
    throw error;
  }
  let preserveLock = false;
  try {
    return installReleaseUnlocked(options);
  } catch (error) {
    if (error?.code === 'release_rollback_failed') preserveLock = true;
    throw error;
  } finally {
    if (!preserveLock) rmdirSync(lockPath);
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

export function formatInstallError(error) {
  const report = { error: error?.code || 'internal_error' };
  if (error?.recoveryRequired && error?.recoveryPath) {
    report.recoveryRequired = true;
    report.recoveryPath = error.recoveryPath;
  }
  return `amf-install-release: ${JSON.stringify(report)}\n`;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.getuid?.() !== 0) throw failure('root_required');
    const result = installRelease(parseArgs(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(formatInstallError(error));
    process.exitCode = 1;
  }
}
