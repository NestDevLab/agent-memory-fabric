import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

const STATE_SCHEMA = 'amf.m4-native-paused-phase-receipts/v1';
const RECEIPT_SCHEMA = 'amf.m4-native-paused-phase-receipt/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const MAX_STATE_BYTES = 2_097_152;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value, keys) {
  return plain(value) && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function clone(value, code) {
  try { return structuredClone(value); } catch { fail(code); }
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function digest(value) {
  return crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function integrity(value, code) {
  if (!exact(value, ['algorithm', 'keyId', 'payloadDigest', 'signature'])
    || value.algorithm !== 'hmac-sha256' || typeof value.keyId !== 'string' || !ID.test(value.keyId)
    || typeof value.payloadDigest !== 'string' || !DIGEST.test(value.payloadDigest)
    || typeof value.signature !== 'string' || !SIGNATURE.test(value.signature)) fail(code);
  return { algorithm: 'hmac-sha256', keyId: value.keyId,
    payloadDigest: value.payloadDigest, signature: value.signature };
}

function binding(value, code) {
  if (!exact(value, ['runId', 'planDigest', 'catalogDigest'])
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || typeof value.planDigest !== 'string' || !DIGEST.test(value.planDigest)
    || typeof value.catalogDigest !== 'string' || !DIGEST.test(value.catalogDigest)) fail(code);
  return { runId: value.runId, planDigest: value.planDigest, catalogDigest: value.catalogDigest };
}

function receipt(value, expected, code) {
  const keys = ['schema', 'ordinal', 'runId', 'planConfirmationDigest', 'authorityDigest',
    'legacyCompletionDigest', 'terminalCheckpoint', 'resultDigest', 'integrity'];
  if (!exact(value, keys) || value.schema !== RECEIPT_SCHEMA
    || !Number.isSafeInteger(value.ordinal) || value.ordinal < 0 || value.ordinal >= expected.shardCount
    || typeof value.runId !== 'string' || !ID.test(value.runId)
    || ![value.planConfirmationDigest, value.authorityDigest, value.legacyCompletionDigest, value.resultDigest]
      .every(item => typeof item === 'string' && DIGEST.test(item))) fail(code);
  return {
    schema: RECEIPT_SCHEMA,
    ordinal: value.ordinal,
    runId: value.runId,
    planConfirmationDigest: value.planConfirmationDigest,
    authorityDigest: value.authorityDigest,
    legacyCompletionDigest: value.legacyCompletionDigest,
    terminalCheckpoint: checkpoint(value.terminalCheckpoint, code),
    resultDigest: value.resultDigest,
    integrity: integrity(value.integrity, code),
  };
}

function state(value, expected, code) {
  if (!exact(value, ['schema', 'binding', 'receipts']) || value.schema !== STATE_SCHEMA
    || !same(binding(value.binding, code), expected.binding) || !Array.isArray(value.receipts)
    || value.receipts.length > expected.shardCount) fail(code);
  const receipts = value.receipts.map(item => receipt(item, expected, code));
  for (let index = 0; index < receipts.length; index += 1) {
    if (receipts[index].ordinal !== index) fail(code);
  }
  return { schema: STATE_SCHEMA, binding: clone(expected.binding, code), receipts };
}

function ownerUid() {
  if (typeof process.geteuid === 'function') return process.geteuid();
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function assertOwner(stat, code) {
  const uid = ownerUid();
  if (uid !== null && stat.uid !== uid) fail(code);
}

function assertDirectory(stat) {
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) {
    fail('m4_native_phase_store_unsafe');
  }
  assertOwner(stat, 'm4_native_phase_store_unsafe');
}

function assertFile(stat) {
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) {
    fail('m4_native_phase_store_unsafe');
  }
  assertOwner(stat, 'm4_native_phase_store_unsafe');
}

function normalizedRoot(value) {
  if (typeof value !== 'string' || value.length < 1 || !path.isAbsolute(value)
    || path.resolve(value) !== value) fail('m4_native_phase_store_dependency_invalid');
  return value;
}

function assertExistingRootComponents(rootPath) {
  const parsed = path.parse(rootPath);
  let current = parsed.root;
  for (const component of rootPath.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) fail('m4_native_phase_store_unsafe');
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      if (error?.code === 'm4_native_phase_store_unsafe') throw error;
      fail('m4_native_phase_store_unsafe');
    }
  }
}

function openDirectory(rootPath) {
  assertExistingRootComponents(rootPath);
  try { fs.mkdirSync(rootPath, { recursive: true, mode: 0o700 }); }
  catch { fail('m4_native_phase_store_unsafe'); }
  let descriptor;
  try {
    descriptor = fs.openSync(rootPath, fs.constants.O_RDONLY
      | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
    assertDirectory(fs.fstatSync(descriptor));
    return descriptor;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error?.code === 'm4_native_phase_store_unsafe') throw error;
    fail('m4_native_phase_store_unsafe');
  }
}

function child(directory, name) {
  return `/proc/self/fd/${directory}/${name}`;
}

function fsyncDirectory(directory) {
  try { fs.fsyncSync(directory); }
  catch { fail('m4_native_phase_store_durability_failed'); }
}

function lstatChild(directory, name) {
  try { return fs.lstatSync(child(directory, name)); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    fail('m4_native_phase_store_unsafe');
  }
}

function readState(directory, name, expected) {
  const before = lstatChild(directory, name);
  if (before === null) return null;
  assertFile(before);
  let descriptor;
  try {
    descriptor = fs.openSync(child(directory, name), fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor);
    assertFile(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size > MAX_STATE_BYTES) {
      fail('m4_native_phase_store_unsafe');
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
      || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
      || bytes.length > MAX_STATE_BYTES) fail('m4_native_phase_store_unsafe');
    let parsed;
    try { parsed = JSON.parse(bytes.toString('utf8')); }
    catch { fail('m4_native_phase_store_corrupt'); }
    return state(parsed, expected, 'm4_native_phase_store_corrupt');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_native_phase_store_')) throw error;
    fail('m4_native_phase_store_unsafe');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function recoverTemps(directory, stateName) {
  let names;
  try { names = fs.readdirSync(child(directory, '.')); }
  catch { fail('m4_native_phase_store_unsafe'); }
  const temporary = new RegExp(`^\\.${stateName}\\.[a-f0-9-]{36}\\.tmp$`);
  for (const name of names) {
    if (!temporary.test(name)) continue;
    const stat = lstatChild(directory, name);
    if (stat === null) continue;
    assertFile(stat);
    try { fs.unlinkSync(child(directory, name)); }
    catch { fail('m4_native_phase_store_unsafe'); }
  }
  fsyncDirectory(directory);
}

function writeState(directory, name, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  if (bytes.length > MAX_STATE_BYTES) fail('m4_native_phase_store_state_invalid');
  const existing = lstatChild(directory, name);
  if (existing !== null) assertFile(existing);
  const temporary = `.${name}.${crypto.randomUUID()}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(child(directory, temporary), fs.constants.O_WRONLY
      | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(child(directory, temporary), child(directory, name));
    fsyncDirectory(directory);
  } catch (error) {
    if (error?.code?.startsWith?.('m4_native_phase_store_')) throw error;
    fail('m4_native_phase_store_durability_failed');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(child(directory, temporary)); }
    catch (error) {
      if (error?.code !== 'ENOENT') fail('m4_native_phase_store_durability_failed');
    }
  }
}

export class M4NativePausedPhaseStore {
  constructor({ rootPath, runId, planDigest, catalogDigest, shardCount } = {}) {
    rootPath = normalizedRoot(rootPath);
    this.binding = binding({ runId, planDigest, catalogDigest },
      'm4_native_phase_store_dependency_invalid');
    if (!Number.isSafeInteger(shardCount) || shardCount < 1 || shardCount > 1_000) {
      fail('m4_native_phase_store_dependency_invalid');
    }
    this.shardCount = shardCount;
    this.rootPath = rootPath;
    this.stateName = `m4-native-phase-${digest(this.binding)}.json`;
    this.directory = openDirectory(rootPath);
    try { recoverTemps(this.directory, this.stateName); }
    catch (error) { fs.closeSync(this.directory); throw error; }
  }

  load() {
    if (this.directory === null) fail('m4_native_phase_store_closed');
    const expected = { binding: this.binding, shardCount: this.shardCount };
    const value = readState(this.directory, this.stateName, expected);
    return value === null ? [] : clone(value.receipts, 'm4_native_phase_store_corrupt');
  }

  commit(input) {
    if (this.directory === null) fail('m4_native_phase_store_closed');
    const expected = { binding: this.binding, shardCount: this.shardCount };
    const next = receipt(input, expected, 'm4_native_phase_store_receipt_invalid');
    const current = this.load();
    if (next.ordinal < current.length) {
      if (!same(next, current[next.ordinal])) fail('m4_native_phase_store_substitution');
      return clone(next, 'm4_native_phase_store_receipt_invalid');
    }
    if (next.ordinal !== current.length) fail('m4_native_phase_store_gap');
    const value = { schema: STATE_SCHEMA, binding: clone(this.binding,
      'm4_native_phase_store_state_invalid'), receipts: [...current, next] };
    writeState(this.directory, this.stateName, value);
    return clone(next, 'm4_native_phase_store_receipt_invalid');
  }

  close() {
    if (this.directory !== null) {
      fs.closeSync(this.directory);
      this.directory = null;
    }
  }
}
