import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

const PROGRESS_SCHEMA = 'amf.m4-backfill-progress/v1';
const ACK_SCHEMA = 'amf.m4-backfill-progress-ack/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const PHASES = new Set(['v2-archive', 'paused-native']);
const MAX_STATE_BYTES = 4096;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function ownerUid() {
  if (typeof process.geteuid === 'function') return process.geteuid();
  return typeof process.getuid === 'function' ? process.getuid() : null;
}
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }

function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}

function namespace(value, code) {
  if (!exact(value, ['runId', 'phase']) || typeof value.runId !== 'string' || !ID.test(value.runId)
    || typeof value.phase !== 'string' || !PHASES.has(value.phase)) fail(code);
  return { runId: value.runId, phase: value.phase };
}

function progress(value, expected, code) {
  const keys = ['schema', 'runId', 'phase', 'planDigest', 'sequence', 'checkpoint', 'eventId', 'payloadDigest'];
  if (!exact(value, keys) || value.schema !== PROGRESS_SCHEMA || value.runId !== expected.runId
    || value.phase !== expected.phase || value.planDigest !== expected.planDigest
    || !Number.isSafeInteger(value.sequence) || value.sequence < 1
    || typeof value.eventId !== 'string' || !EVENT_ID.test(value.eventId)
    || typeof value.payloadDigest !== 'string' || !DIGEST.test(value.payloadDigest)) fail(code);
  return {
    schema: PROGRESS_SCHEMA, runId: value.runId, phase: value.phase, planDigest: value.planDigest,
    sequence: value.sequence, checkpoint: checkpoint(value.checkpoint, code), eventId: value.eventId,
    payloadDigest: value.payloadDigest,
  };
}

function assertOwner(stat, code) {
  const uid = ownerUid();
  if (uid !== null && stat.uid !== uid) fail(code);
}

function assertDirectory(stat) {
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) fail('m4_progress_storage_unsafe');
  assertOwner(stat, 'm4_progress_storage_unsafe');
}

function assertFile(stat) {
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) fail('m4_progress_storage_unsafe');
  assertOwner(stat, 'm4_progress_storage_unsafe');
}

function normalizedRoot(value) {
  if (typeof value !== 'string' || value.length < 1 || !path.isAbsolute(value) || path.resolve(value) !== value) {
    fail('m4_progress_dependency_invalid');
  }
  return value;
}

function assertExistingRootComponents(rootPath) {
  const parsed = path.parse(rootPath);
  let current = parsed.root;
  for (const component of rootPath.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) fail('m4_progress_storage_unsafe');
      if (!stat.isDirectory()) fail('m4_progress_storage_unsafe');
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      if (error?.code === 'm4_progress_storage_unsafe') throw error;
      fail('m4_progress_storage_unsafe');
    }
  }
}

function openDirectory(rootPath) {
  assertExistingRootComponents(rootPath);
  try { fs.mkdirSync(rootPath, { recursive: true, mode: 0o700 }); }
  catch { fail('m4_progress_storage_unsafe'); }
  let descriptor;
  try {
    descriptor = fs.openSync(rootPath, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
    assertDirectory(fs.fstatSync(descriptor));
    return descriptor;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error?.code === 'm4_progress_storage_unsafe') throw error;
    fail('m4_progress_storage_unsafe');
  }
}

function child(directory, name) { return `/proc/self/fd/${directory}/${name}`; }
function fsyncDirectory(directory) {
  try { fs.fsyncSync(directory); }
  catch { fail('m4_progress_durability_failed'); }
}

function lstatChild(directory, name) {
  try { return fs.lstatSync(child(directory, name)); }
  catch (error) { if (error?.code === 'ENOENT') return null; fail('m4_progress_storage_unsafe'); }
}

function readState(directory, name, expected) {
  const before = lstatChild(directory, name);
  if (before === null) return null;
  assertFile(before);
  let descriptor;
  try {
    descriptor = fs.openSync(child(directory, name), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(descriptor);
    assertFile(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size > MAX_STATE_BYTES) fail('m4_progress_storage_unsafe');
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
      || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      fail('m4_progress_storage_unsafe');
    }
    if (bytes.length > MAX_STATE_BYTES) fail('m4_progress_storage_unsafe');
    let parsed;
    try { parsed = JSON.parse(bytes.toString('utf8')); } catch { fail('m4_progress_state_invalid'); }
    return progress(parsed, expected, 'm4_progress_state_invalid');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_progress_')) throw error;
    fail('m4_progress_storage_unsafe');
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function recoverTemps(directory, stateName) {
  let names;
  try { names = fs.readdirSync(child(directory, '.')); }
  catch { fail('m4_progress_storage_unsafe'); }
  const temporary = new RegExp(`^\\.${stateName}\\.[a-f0-9-]{36}\\.tmp$`);
  for (const name of names) {
    if (!temporary.test(name)) continue;
    const stat = lstatChild(directory, name);
    if (stat === null) continue;
    assertFile(stat);
    try { fs.unlinkSync(child(directory, name)); }
    catch { fail('m4_progress_storage_unsafe'); }
  }
  fsyncDirectory(directory);
}

function writeState(directory, name, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  if (bytes.length > MAX_STATE_BYTES) fail('m4_progress_state_invalid');
  const existing = lstatChild(directory, name);
  if (existing !== null) assertFile(existing);
  const temporary = `.${name}.${crypto.randomUUID()}.tmp`;
  let descriptor;
  try {
    descriptor = fs.openSync(child(directory, temporary), fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    fs.renameSync(child(directory, temporary), child(directory, name));
    fsyncDirectory(directory);
  } catch (error) {
    if (error?.code?.startsWith?.('m4_progress_')) throw error;
    fail('m4_progress_durability_failed');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(child(directory, temporary)); }
    catch (error) { if (error?.code !== 'ENOENT') fail('m4_progress_durability_failed'); }
  }
}

export class M4ProgressStore {
  constructor({ rootPath, runId, phase, planDigest } = {}) {
    rootPath = normalizedRoot(rootPath);
    const binding = namespace({ runId, phase }, 'm4_progress_dependency_invalid');
    if (typeof planDigest !== 'string' || !DIGEST.test(planDigest)) fail('m4_progress_dependency_invalid');
    this.binding = { ...binding, planDigest };
    this.rootPath = rootPath;
    this.stateName = `m4-progress-${binding.runId}-${binding.phase}-${planDigest.slice(7)}.json`;
    this.directory = openDirectory(this.rootPath);
    try { recoverTemps(this.directory, this.stateName); }
    catch (error) { fs.closeSync(this.directory); throw error; }
  }

  load(input) {
    const requested = namespace(input, 'm4_progress_request_invalid');
    if (requested.runId !== this.binding.runId || requested.phase !== this.binding.phase) fail('m4_progress_namespace_invalid');
    const value = readState(this.directory, this.stateName, this.binding);
    return value === null ? null : structuredClone(value);
  }

  commit(input) {
    const next = progress(input, this.binding, 'm4_progress_commit_invalid');
    const current = readState(this.directory, this.stateName, this.binding);
    if (current === null) {
      if (next.sequence !== 1) fail('m4_progress_sequence_invalid');
    } else if (next.sequence === current.sequence) {
      if (!same(next, current)) fail('m4_progress_drift');
      return this.#ack(current);
    } else {
      if (next.sequence < current.sequence) fail('m4_progress_rollback');
      if (next.sequence !== current.sequence + 1) fail('m4_progress_sequence_invalid');
      if (same(next.checkpoint, current.checkpoint)) fail('m4_progress_checkpoint_invalid');
    }
    writeState(this.directory, this.stateName, next);
    return this.#ack(next);
  }

  #ack(value) {
    return {
      schema: ACK_SCHEMA, committed: true, runId: value.runId, phase: value.phase,
      planDigest: value.planDigest, sequence: value.sequence, checkpoint: structuredClone(value.checkpoint),
    };
  }

  close() {
    if (this.directory !== null) { fs.closeSync(this.directory); this.directory = null; }
  }
}
