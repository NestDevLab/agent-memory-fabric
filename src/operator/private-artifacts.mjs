import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

const PRIVATE_FILE_MAX_BYTES = 64 * 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }

export function canonicalDigest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

export function absolutePath(value, code = 'private_artifact_path_invalid') {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) fail(code);
  return value;
}

function assertNoSymlinkComponents(target, code) {
  const parsed = path.parse(target);
  let current = parsed.root;
  for (const component of target.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (error) { if (error?.code === 'ENOENT') return; throw error; }
    if (stat.isSymbolicLink()) fail(code);
  }
}

function ownerOnly(stat, code) {
  if (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) fail(code);
}

function identityFields(descriptor) {
  const stat = fs.fstatSync(descriptor, { bigint: true });
  return { dev: stat.dev.toString(), ino: stat.ino.toString(), size: Number(stat.size),
    mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString() };
}

export function assertPrivateFileIdentity(identity, code = 'private_artifact_file_changed') {
  let current;
  try { current = identityFields(identity.descriptor); } catch { fail(code); }
  if (Object.keys(current).some(name => current[name] !== identity.stat[name])) fail(code);
}

export function privateFileIdentity(filePath, {
  code = 'private_artifact_file_invalid',
  minBytes = 2,
  maxBytes = PRIVATE_FILE_MAX_BYTES,
} = {}) {
  const target = absolutePath(filePath, code);
  assertNoSymlinkComponents(target, code);
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || !Number.isSafeInteger(minBytes) || minBytes < 0
      || stat.size < minBytes || stat.size > maxBytes) fail(code);
    ownerOnly(stat, code);
    return { target, descriptor, stat: identityFields(descriptor) };
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error?.code === code) throw error;
    fail(code);
  }
}

export function readPrivateBuffer(filePath, options = {}) {
  const identity = privateFileIdentity(filePath, options);
  try {
    const value = fs.readFileSync(identity.descriptor);
    assertPrivateFileIdentity(identity, options.code ?? 'private_artifact_file_invalid');
    return value;
  } finally { fs.closeSync(identity.descriptor); }
}

export function readPrivateJson(filePath, code = 'private_artifact_json_invalid', options = {}) {
  try {
    const bytes = readPrivateBuffer(filePath, { ...options, code });
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

export function readPrivateJsonWithDigest(filePath, code = 'private_artifact_json_invalid', options = {}) {
  try {
    const bytes = readPrivateBuffer(filePath, { ...options, code });
    return { value: JSON.parse(bytes.toString('utf8')),
      digest: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}` };
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}

function digestIdentity(identity, code) {
  const hash = crypto.createHash('sha256'); const buffer = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  try {
    while (position < identity.stat.size) {
      const read = fs.readSync(identity.descriptor, buffer, 0,
        Math.min(buffer.length, identity.stat.size - position), position);
      if (read < 1) fail(code);
      hash.update(buffer.subarray(0, read)); position += read;
    }
    assertPrivateFileIdentity(identity, code);
    return `sha256:${hash.digest('hex')}`;
  } finally { buffer.fill(0); }
}

export function openPrivateDigest(filePath, code = 'private_artifact_file_invalid', options = {}) {
  const identity = privateFileIdentity(filePath, { ...options, code });
  try { return { ...identity, digest: digestIdentity(identity, code) }; }
  catch (error) { fs.closeSync(identity.descriptor); throw error; }
}

export function privateFileDigest(filePath, code = 'private_artifact_file_invalid', options = {}) {
  const identity = openPrivateDigest(filePath, code, options);
  try { return identity.digest; } finally { fs.closeSync(identity.descriptor); }
}

export function validateArtifactRoot(rootPath, code = 'private_artifact_root_invalid') {
  const root = absolutePath(rootPath, code);
  assertNoSymlinkComponents(root, code);
  let stat;
  try { stat = fs.statSync(root); } catch { fail(code); }
  if (!stat.isDirectory()) fail(code);
  ownerOnly(stat, code);
  return root;
}

function ensurePrivateDirectory(root, relative, code) {
  let current = root;
  for (const component of relative.split('/').filter(Boolean)) {
    current = path.join(current, component);
    try { fs.mkdirSync(current, { mode: 0o700 }); }
    catch (error) { if (error?.code !== 'EEXIST') fail(code); }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(code);
    ownerOnly(stat, code);
  }
  return current;
}

export function artifactPath(rootPath, stage, manifestId, revision) {
  const root = validateArtifactRoot(rootPath);
  if (!['reconciliation', 'recovery', 'canary', 'authorization'].includes(stage)
    || typeof manifestId !== 'string' || !/^[a-z][a-z0-9-]{2,79}$/.test(manifestId)
    || !Number.isSafeInteger(revision) || revision < 1) fail('private_artifact_target_invalid');
  return path.join(root, 'm4', stage, `${manifestId}-r${revision}.json`);
}

export function writePrivateArtifact(rootPath, stage, manifestId, revision, value) {
  const root = validateArtifactRoot(rootPath);
  const target = artifactPath(root, stage, manifestId, revision);
  const directory = ensurePrivateDirectory(root, `m4/${stage}`, 'private_artifact_target_invalid');
  const temporary = path.join(directory, `.${manifestId}-r${revision}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    fs.linkSync(temporary, target);
    fs.unlinkSync(temporary);
    const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
    try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
    return target;
  } catch (error) {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    try { fs.unlinkSync(temporary); } catch {}
    if (error?.code === 'EEXIST') fail('private_artifact_target_exists');
    if (error?.code?.startsWith?.('private_artifact_')) throw error;
    fail('private_artifact_write_failed');
  }
}
