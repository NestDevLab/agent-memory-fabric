import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from './ingest/transcripts/canonical.mjs';

const INPUT_SCHEMA = 'amf.migration-pause-checkpoints/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const MANIFEST_SCHEMA = 'amf.migration-manifest/v1';
const SIGNATURE_DOMAIN = 'amf.migration-manifest/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_SHA256 = /^[A-Za-z0-9_-]{43}$/;
const CHECKPOINT_NAMES = Object.freeze([
  'collectorCursor', 'pendingOutbox', 'acknowledgements', 'deadLetters',
  'sourceCheckpoint', 'nativeTranscriptAuthority', 'evidence'
]);
const VERIFIED_PAUSES = new WeakSet();

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function exactKeys(value, expected, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(code);
}

function validateId(value, code) {
  if (typeof value !== 'string' || !ID.test(value)) fail(code);
}

function validateCheckpoint(value) {
  exactKeys(value, ['id', 'digest'], 'migration_pause_checkpoint_invalid');
  validateId(value.id, 'migration_pause_checkpoint_invalid');
  if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail('migration_pause_checkpoint_invalid');
}

function validatePauseBody(value) {
  exactKeys(value, ['state', ...CHECKPOINT_NAMES], 'migration_pause_body_invalid');
  if (value.state !== 'paused') fail('migration_pause_body_invalid');
  for (const name of CHECKPOINT_NAMES) validateCheckpoint(value[name]);
}

export function validatePauseCheckpointInput(value) {
  exactKeys(value, ['schema', 'manifestId', 'revision', 'keyId', 'pause'], 'migration_pause_input_invalid');
  if (value.schema !== INPUT_SCHEMA) fail('migration_pause_input_invalid');
  validateId(value.manifestId, 'migration_pause_input_invalid');
  validateId(value.keyId, 'migration_pause_input_invalid');
  if (!Number.isSafeInteger(value.revision) || value.revision < 1) fail('migration_pause_input_invalid');
  validatePauseBody(value.pause);
  return value;
}

export function validatePauseManifest(value) {
  exactKeys(value, ['schema', 'manifestId', 'phase', 'revision', 'pause', 'integrity'], 'migration_pause_manifest_invalid');
  if (value.schema !== MANIFEST_SCHEMA || value.phase !== 'pause') fail('migration_pause_manifest_invalid');
  validateId(value.manifestId, 'migration_pause_manifest_invalid');
  if (!Number.isSafeInteger(value.revision) || value.revision < 1) fail('migration_pause_manifest_invalid');
  validatePauseBody(value.pause);
  exactKeys(value.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], 'migration_pause_integrity_invalid');
  if (value.integrity.algorithm !== 'hmac-sha256') fail('migration_pause_integrity_invalid');
  validateId(value.integrity.keyId, 'migration_pause_integrity_invalid');
  if (typeof value.integrity.payloadDigest !== 'string' || !DIGEST.test(value.integrity.payloadDigest)
      || typeof value.integrity.signature !== 'string' || !BASE64URL_SHA256.test(value.integrity.signature)) {
    fail('migration_pause_integrity_invalid');
  }
  return value;
}

function validateKeyDocument(value) {
  exactKeys(value, ['schema', 'keyId', 'key'], 'migration_pause_key_invalid');
  if (value.schema !== KEY_SCHEMA) fail('migration_pause_key_invalid');
  validateId(value.keyId, 'migration_pause_key_invalid');
  if (typeof value.key !== 'string' || !BASE64.test(value.key)) fail('migration_pause_key_invalid');
  const key = Buffer.from(value.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== value.key) fail('migration_pause_key_invalid');
  return { keyId: value.keyId, key };
}

function digestPayload(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function signatureFor(payloadDigest, keyId, key) {
  return crypto.createHmac('sha256', key)
    .update(canonicalJson([SIGNATURE_DOMAIN, payloadDigest, keyId]), 'utf8')
    .digest('base64url');
}

export function createPauseManifest(input, keyDocument) {
  validatePauseCheckpointInput(input);
  const loadedKey = validateKeyDocument(keyDocument);
  if (loadedKey.keyId !== input.keyId) fail('migration_pause_key_id_mismatch');
  const payload = {
    schema: MANIFEST_SCHEMA,
    manifestId: input.manifestId,
    phase: 'pause',
    revision: input.revision,
    pause: structuredClone(input.pause)
  };
  const payloadDigest = digestPayload(payload);
  return {
    ...payload,
    integrity: {
      algorithm: 'hmac-sha256',
      keyId: loadedKey.keyId,
      payloadDigest,
      signature: signatureFor(payloadDigest, loadedKey.keyId, loadedKey.key)
    }
  };
}

export function verifyPauseManifest(manifest, keyDocument) {
  validatePauseManifest(manifest);
  const loadedKey = validateKeyDocument(keyDocument);
  if (loadedKey.keyId !== manifest.integrity.keyId) fail('migration_pause_key_id_mismatch');
  const { integrity, ...payload } = manifest;
  const payloadDigest = digestPayload(payload);
  if (payloadDigest !== integrity.payloadDigest) fail('migration_pause_digest_mismatch');
  const expected = Buffer.from(signatureFor(payloadDigest, integrity.keyId, loadedKey.key), 'base64url');
  const received = Buffer.from(integrity.signature, 'base64url');
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) fail('migration_pause_signature_mismatch');
  const verified = Object.freeze({
    state: 'paused',
    health: 'degraded',
    verified: true,
    manifestId: manifest.manifestId,
    revision: manifest.revision,
    keyId: integrity.keyId
  });
  VERIFIED_PAUSES.add(verified);
  return verified;
}

export function isVerifiedMigrationPause(value) {
  return value === null || VERIFIED_PAUSES.has(value);
}

function safeAbsolutePath(value, code) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) fail(code);
  const parts = value.split(path.sep);
  if (parts.includes('.') || parts.includes('..') || path.normalize(value) !== value) fail(code);
  return value;
}

function assertOwner(stat, code) {
  if (typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) fail(code);
}

function assertNoSymlinkComponents(absolute, code, { includeLeaf = true } = {}) {
  const parsed = path.parse(absolute);
  const parts = absolute.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let current = parsed.root;
  const end = includeLeaf ? parts.length : Math.max(0, parts.length - 1);
  for (let index = 0; index < end; index += 1) {
    current = path.join(current, parts[index]);
    if (fs.lstatSync(current).isSymbolicLink()) fail(code);
  }
}

function readJsonFile(filePath, { privateOnly = false } = {}) {
  const absolute = safeAbsolutePath(filePath, 'migration_pause_path_invalid');
  let descriptor;
  try {
    assertNoSymlinkComponents(absolute, 'migration_pause_file_unsafe');
    const before = fs.lstatSync(absolute);
    if (!before.isFile() || before.isSymbolicLink()) fail('migration_pause_file_unsafe');
    assertOwner(before, 'migration_pause_file_owner_invalid');
    if ((before.mode & (privateOnly ? 0o077 : 0o022)) !== 0) fail('migration_pause_file_mode_invalid');
    descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const after = fs.fstatSync(descriptor);
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino || after.size > 1024 * 1024) fail('migration_pause_file_unsafe');
    return JSON.parse(fs.readFileSync(descriptor, 'utf8'));
  } catch (error) {
    if (error?.code?.startsWith?.('migration_pause_')) throw error;
    if (error instanceof SyntaxError) fail('migration_pause_json_invalid');
    fail('migration_pause_file_unavailable');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function readPauseCheckpointInput(filePath) {
  return validatePauseCheckpointInput(readJsonFile(filePath));
}

export function readMigrationKeyFile(filePath) {
  return readJsonFile(filePath, { privateOnly: true });
}

export function verifyPauseManifestFiles(manifestPath, keyPath) {
  return verifyPauseManifest(readJsonFile(manifestPath, { privateOnly: true }), readMigrationKeyFile(keyPath));
}

export function loadVerifiedMigrationPauseFromEnv(env = process.env) {
  const manifestPath = String(env.AMF_MIGRATION_PAUSE_MANIFEST_PATH || '').trim();
  const keyPath = String(env.AMF_MIGRATION_PAUSE_KEY_PATH || '').trim();
  if (!manifestPath && !keyPath) return null;
  if (!manifestPath || !keyPath) fail('migration_pause_config_incomplete');
  return verifyPauseManifestFiles(manifestPath, keyPath);
}

export function writeOwnerOnlyAtomic(filePath, value) {
  const target = safeAbsolutePath(filePath, 'migration_pause_path_invalid');
  const directory = path.dirname(target);
  assertNoSymlinkComponents(target, 'migration_pause_output_directory_unsafe', { includeLeaf: false });
  const directoryStat = fs.lstatSync(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) fail('migration_pause_output_directory_unsafe');
  assertOwner(directoryStat, 'migration_pause_output_directory_unsafe');
  if ((directoryStat.mode & 0o022) !== 0) fail('migration_pause_output_directory_unsafe');
  const temporary = path.join(directory, `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.linkSync(temporary, target);
    fs.unlinkSync(temporary);
    const directoryFd = fs.openSync(directory, fs.constants.O_RDONLY);
    try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch {}
    if (error?.code?.startsWith?.('migration_pause_')) throw error;
    if (error?.code === 'EEXIST') fail('migration_pause_output_exists');
    fail('migration_pause_output_failed');
  }
}

export const migrationPauseSchemas = Object.freeze({ input: INPUT_SCHEMA, key: KEY_SCHEMA, manifest: MANIFEST_SCHEMA });
