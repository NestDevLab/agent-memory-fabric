import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { ContextTokenVerifier, issueSessionRouteBinding, normalizeContextKeyRing } from '../context-token.mjs';

const INPUT_SCHEMA_V1 = 'amf.session-route-input/v1';
const INPUT_SCHEMA_V2 = 'amf.session-route-input/v2';
const MANIFEST_SCHEMA = 'amf.session-route-manifest/v1';
const DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;

function fail(code, cause = null) { const error = new Error(code); if (cause) error.cause = cause; return error; }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function exactKeys(value, keys) {
  return object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function allowedOwner(uid, serviceOwnerUid) { return uid === 0 || uid === serviceOwnerUid; }

function openPrivateDirectory(directoryPath, serviceOwnerUid) {
  const absolute = path.resolve(directoryPath); const before = fs.lstatSync(absolute);
  if (!before.isDirectory() || before.isSymbolicLink() || (before.mode & 0o077) !== 0
    || !allowedOwner(before.uid, serviceOwnerUid)) throw fail('session_route_directory_unsafe');
  const fd = fs.openSync(absolute, DIRECTORY_FLAGS); const opened = fs.fstatSync(fd);
  if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino
    || (opened.mode & 0o077) !== 0 || !allowedOwner(opened.uid, serviceOwnerUid)) {
    fs.closeSync(fd); throw fail('session_route_directory_unsafe');
  }
  return { fd, path: absolute };
}

function procChild(directory, name) {
  if (!directory || path.basename(name) !== name || !name || name.includes('/')) throw fail('session_route_path_invalid');
  return `/proc/self/fd/${directory.fd}/${name}`;
}

function readPrivateFile(filePath, serviceOwnerUid, { optional = false } = {}) {
  const absolute = path.resolve(filePath); const directory = openPrivateDirectory(path.dirname(absolute), serviceOwnerUid);
  let fd;
  try {
    const openedPath = procChild(directory, path.basename(absolute));
    let before;
    try { before = fs.lstatSync(openedPath); } catch (error) {
      if (optional && error?.code === 'ENOENT') return { directory, missing: true };
      throw error;
    }
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || (before.mode & 0o777) !== 0o600 || !allowedOwner(before.uid, serviceOwnerUid)
      || before.size < 2 || before.size > 1024 * 1024) throw fail('session_route_file_unsafe');
    fd = fs.openSync(openedPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1
      || (opened.mode & 0o777) !== 0o600 || !allowedOwner(opened.uid, serviceOwnerUid)
      || opened.size !== before.size) throw fail('session_route_file_unsafe');
    let value; let bytes;
    try { bytes = fs.readFileSync(fd); value = JSON.parse(bytes.toString('utf8')); }
    catch (error) { throw fail('session_route_json_invalid', error); }
    return { directory, value, stat: opened, digest: crypto.createHash('sha256').update(bytes).digest('hex'),
      missing: false };
  } catch (error) {
    fs.closeSync(directory.fd); throw error;
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function closeRecord(record) { if (record?.directory?.fd !== undefined) fs.closeSync(record.directory.fd); }

function validateInput(value, keyRing, defaultKeyVersion) {
  if (!exactKeys(value, ['schema', 'bindings']) || ![INPUT_SCHEMA_V1, INPUT_SCHEMA_V2].includes(value.schema)
    || !Array.isArray(value.bindings) || !value.bindings.length || value.bindings.length > 1000) {
    throw fail('session_route_input_invalid');
  }
  let normalizedRing;
  try { normalizedRing = normalizeContextKeyRing(keyRing); }
  catch (error) { throw fail('session_route_context_key_ring_invalid', error); }
  if (defaultKeyVersion !== undefined
    && (typeof defaultKeyVersion !== 'string' || !normalizedRing.keys.has(defaultKeyVersion))) {
    throw fail('session_route_key_version_invalid');
  }
  const seen = new Set();
  return value.bindings.map(candidate => {
    const expectedKeys = value.schema === INPUT_SCHEMA_V2
      ? ['actor', 'canonicalScope', 'conversationKind', 'contextTags', 'keyVersion']
      : ['actor', 'canonicalScope', 'conversationKind', 'contextTags'];
    if (!exactKeys(candidate, expectedKeys)) {
      throw fail('session_route_input_invalid');
    }
    if (value.schema === INPUT_SCHEMA_V2 && typeof candidate.keyVersion !== 'string') {
      throw fail('session_route_key_version_invalid');
    }
    const candidateKeyVersion = candidate.keyVersion === undefined ? defaultKeyVersion : candidate.keyVersion;
    if (candidate.keyVersion !== undefined && defaultKeyVersion !== undefined
      && candidate.keyVersion !== defaultKeyVersion) throw fail('session_route_key_version_conflict');
    if (candidateKeyVersion === undefined && normalizedRing.keys.size !== 1) {
      throw fail('session_route_key_version_required');
    }
    const keyVersion = candidateKeyVersion === undefined ? normalizedRing.currentKeyVersion : candidateKeyVersion;
    if (typeof keyVersion !== 'string' || !normalizedRing.keys.has(keyVersion)) {
      throw fail('session_route_key_version_invalid');
    }
    let binding;
    try { binding = issueSessionRouteBinding({ ...candidate, keyVersion }, normalizedRing); }
    catch (error) { throw fail('session_route_input_invalid', error); }
    const identity = `${binding.actor}\0${binding.conversationKind}\0${binding.canonicalScope}`;
    if (seen.has(identity)) throw fail('session_route_binding_duplicate');
    seen.add(identity); return binding;
  });
}

function validateExisting(value, verifier) {
  if (!exactKeys(value, ['schema', 'bindings']) || value.schema !== MANIFEST_SCHEMA
    || !Array.isArray(value.bindings) || value.bindings.length > 10000) throw fail('session_route_manifest_invalid');
  const seen = new Set();
  return value.bindings.map(candidate => {
    let binding;
    try { binding = { ...verifier.verifySessionRouteBinding(candidate), mac: candidate.mac }; }
    catch (error) { throw fail('session_route_manifest_invalid', error); }
    const identity = `${binding.actor}\0${binding.conversationKind}\0${binding.canonicalScope}`;
    if (seen.has(identity)) throw fail('session_route_binding_duplicate');
    seen.add(identity); return binding;
  });
}

function canonicalManifest(bindings) {
  return { schema: MANIFEST_SCHEMA, bindings: [...bindings].sort((a, b) => a.actor.localeCompare(b.actor)
    || a.conversationKind.localeCompare(b.conversationKind) || a.canonicalScope.localeCompare(b.canonicalScope)) };
}

function assertManifestSnapshot(record, directory, name, serviceOwnerUid) {
  const child = procChild(directory, name);
  if (record.missing) {
    try { fs.lstatSync(child); } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw fail('session_route_manifest_changed', error);
    }
    throw fail('session_route_manifest_changed');
  }
  let fd;
  try {
    const before = fs.lstatSync(child);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || (before.mode & 0o777) !== 0o600 || !allowedOwner(before.uid, serviceOwnerUid)
      || before.dev !== record.stat.dev || before.ino !== record.stat.ino || before.size !== record.stat.size) {
      throw fail('session_route_manifest_changed');
    }
    fd = fs.openSync(child, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd); const bytes = fs.readFileSync(fd);
    if (opened.dev !== record.stat.dev || opened.ino !== record.stat.ino || opened.size !== record.stat.size
      || crypto.createHash('sha256').update(bytes).digest('hex') !== record.digest) {
      throw fail('session_route_manifest_changed');
    }
  } catch (error) {
    if (error?.message === 'session_route_manifest_changed') throw error;
    throw fail('session_route_manifest_changed', error);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function provisionSessionRoutes({ inputPath, contextKeyRingPath, manifestPath, dryRun = false,
  serviceOwnerUid = process.geteuid?.() ?? 0, keyVersion, clock = () => new Date() }) {
  if (!inputPath || !contextKeyRingPath || !manifestPath || !Number.isSafeInteger(serviceOwnerUid)) {
    throw fail('session_route_options_invalid');
  }
  if (!dryRun && (process.geteuid?.() ?? -1) !== 0) throw fail('session_route_root_required');
  let input; let ring; let existing; let targetDirectory; let lockFd; let tempName; let backupName;
  let committed = false;
  const targetName = path.basename(path.resolve(manifestPath)); const lockName = `.${targetName}.lock`;
  try {
    input = readPrivateFile(inputPath, serviceOwnerUid);
    ring = readPrivateFile(contextKeyRingPath, serviceOwnerUid);
    if (dryRun) {
      existing = readPrivateFile(manifestPath, serviceOwnerUid, { optional: true });
    } else {
      targetDirectory = openPrivateDirectory(path.dirname(path.resolve(manifestPath)), serviceOwnerUid);
      try {
        lockFd = fs.openSync(procChild(targetDirectory, lockName), fs.constants.O_WRONLY | fs.constants.O_CREAT
          | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      } catch (error) {
        if (error?.code === 'EEXIST') throw fail('session_route_lock_held');
        throw error;
      }
      fs.fchmodSync(lockFd, 0o600); fs.fsyncSync(lockFd);
      existing = readPrivateFile(manifestPath, serviceOwnerUid, { optional: true });
      const lockedDirectory = fs.fstatSync(targetDirectory.fd);
      const readDirectory = fs.fstatSync(existing.directory.fd);
      if (lockedDirectory.dev !== readDirectory.dev || lockedDirectory.ino !== readDirectory.ino) {
        throw fail('session_route_directory_changed');
      }
      fs.closeSync(existing.directory.fd); existing.directory = targetDirectory;
    }
    const verifier = new ContextTokenVerifier({ keyRing: ring.value, policyRevision: '' });
    const replacements = validateInput(input.value, ring.value, keyVersion);
    const current = existing.missing ? [] : validateExisting(existing.value, verifier);
    const replacementIds = new Set(replacements.map(item => `${item.actor}\0${item.conversationKind}\0${item.canonicalScope}`));
    const manifest = canonicalManifest([...current.filter(item => !replacementIds.has(
      `${item.actor}\0${item.conversationKind}\0${item.canonicalScope}`)), ...replacements]);
    const action = existing.missing ? 'create' : 'update';
    const result = { ok: true, schema: MANIFEST_SCHEMA, action, dryRun, bindingCount: manifest.bindings.length,
      updatedBindingCount: replacements.length, manifestPath: path.resolve(manifestPath),
      concurrency: dryRun ? 'read_only_snapshot' : 'locked_cas' };
    if (dryRun) return result;
    assertManifestSnapshot(existing, targetDirectory, targetName, serviceOwnerUid);
    const stamp = clock().toISOString().replaceAll(':', '').replaceAll('.', '');
    if (!existing.missing) {
      backupName = `${targetName}.bak.${stamp}`;
      fs.copyFileSync(procChild(targetDirectory, targetName), procChild(targetDirectory, backupName),
        fs.constants.COPYFILE_EXCL);
      fs.chmodSync(procChild(targetDirectory, backupName), 0o600);
      fs.chownSync(procChild(targetDirectory, backupName), serviceOwnerUid, fs.fstatSync(targetDirectory.fd).gid);
      const backupFd = fs.openSync(procChild(targetDirectory, backupName), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try { fs.fsyncSync(backupFd); } finally { fs.closeSync(backupFd); }
      result.backupPath = path.join(targetDirectory.path, backupName);
    }
    tempName = `.${targetName}.tmp.${process.pid}.${Date.now()}`;
    const tempFd = fs.openSync(procChild(targetDirectory, tempName), fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
      fs.fchmodSync(tempFd, 0o600); fs.fchownSync(tempFd, serviceOwnerUid, fs.fstatSync(targetDirectory.fd).gid);
      fs.writeFileSync(tempFd, `${JSON.stringify(manifest)}\n`, 'utf8');
      fs.fsyncSync(tempFd);
    } finally { fs.closeSync(tempFd); }
    assertManifestSnapshot(existing, targetDirectory, targetName, serviceOwnerUid);
    if (existing.missing) {
      try { fs.linkSync(procChild(targetDirectory, tempName), procChild(targetDirectory, targetName)); }
      catch (error) {
        if (error?.code === 'EEXIST') throw fail('session_route_manifest_changed');
        throw error;
      }
      fs.unlinkSync(procChild(targetDirectory, tempName)); tempName = null;
    } else {
      fs.renameSync(procChild(targetDirectory, tempName), procChild(targetDirectory, targetName)); tempName = null;
    }
    committed = true;
    fs.fsyncSync(targetDirectory.fd);
    return result;
  } finally {
    if (tempName && targetDirectory) { try { fs.unlinkSync(procChild(targetDirectory, tempName)); } catch {} }
    if (backupName && !committed && targetDirectory) {
      try { fs.unlinkSync(procChild(targetDirectory, backupName)); } catch {}
    }
    if (lockFd !== undefined) {
      fs.closeSync(lockFd);
      try { fs.unlinkSync(procChild(targetDirectory, lockName)); } catch {}
    }
    closeRecord(input); closeRecord(ring); closeRecord(existing);
    if (targetDirectory && targetDirectory !== existing?.directory) fs.closeSync(targetDirectory.fd);
  }
}

// Preserve the original export for callers that use it as the legacy v1 schema identifier.
export const SESSION_ROUTE_INPUT_SCHEMA = INPUT_SCHEMA_V1;
export const SESSION_ROUTE_INPUT_SCHEMA_V2 = INPUT_SCHEMA_V2;
export const SESSION_ROUTE_MANIFEST_SCHEMA = MANIFEST_SCHEMA;
