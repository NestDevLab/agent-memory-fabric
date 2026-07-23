import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { m4AuthorityEvidence, timestampWithin, verifyM4SelectorScopeSnapshot } from '../migration/m4-authority-snapshots.mjs';
import { verifyM4CutoverAuthorization } from '../migration/m4-cutover-authorization.mjs';

export const M4_ROUTE_EXECUTOR_INPUT_SCHEMA = 'amf.m4-route-executor-input/v1';
export const M4_ROUTE_EXECUTION_PLAN_SCHEMA = 'amf.m4-route-execution-plan/v1';
export const M4_ROUTE_EXECUTION_RESULT_SCHEMA = 'amf.m4-route-execution-result/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const KEYS = ['schema', 'executionId', 'revision', 'artifactRoot', 'authorizationManifestPath', 'authorizationKeyPath',
  'selectorScopeManifestPath', 'selectorScopeTrustKeyPath', 'runtimeConfigPath', 'backupRoot', 'deploymentAdapter',
  'postCommitHook', 'readinessHook', 'rollbackHook'];
const MAX_CONFIG = 16 * 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`; }
function shaCanonical(value) { return digest(Buffer.from(canonicalJson(value), 'utf8')); }
function exact(value, keys) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)); }
function absolute(value, code) { if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) fail(code); return value; }
function noLinks(target, code) {
  let current = path.parse(target).root;
  for (const part of target.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); let stat;
    try { stat = fs.lstatSync(current); } catch { fail(code); }
    if (stat.isSymbolicLink()) fail(code);
  }
}
function ownerMode(stat, mode, code) { if (stat.uid !== process.getuid() || (stat.mode & 0o777) !== mode) fail(code); }
function parentSafe(target, code) {
  const parent = path.dirname(target); noLinks(parent, code);
  let current = path.parse(parent).root;
  for (const part of parent.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const stat = fs.statSync(current);
    if (!stat.isDirectory() || ![0, process.getuid()].includes(stat.uid) || (stat.mode & 0o022) !== 0) fail(code);
  }
  const final = fs.statSync(parent); const mode = final.mode & 0o777;
  if (final.uid !== process.getuid() || ![0o700, 0o711].includes(mode)) fail(code);
  return parent;
}
function identity(fd) { const s = fs.fstatSync(fd, { bigint: true }); return { dev: String(s.dev), ino: String(s.ino), size: Number(s.size), mtimeNs: String(s.mtimeNs), ctimeNs: String(s.ctimeNs) }; }
function sameIdentity(a, b) { return Object.keys(a).every(k => a[k] === b[k]); }
function readFile(target, code, maximum = MAX_CONFIG) {
  absolute(target, code); noLinks(target, code); let fd;
  try { fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > maximum) fail(code);
    const pin = identity(fd); const bytes = fs.readFileSync(fd); if (!sameIdentity(pin, identity(fd))) fail(code);
    return { target, bytes, digest: digest(bytes), identity: pin };
  } catch (error) { if (error?.code === code) throw error; fail(code); } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function validateRoot(root, code) { absolute(root, code); noLinks(root, code); const s = fs.statSync(root); if (!s.isDirectory()) fail(code); ownerMode(s, 0o700, code); return { target: root, identity: { dev: String(s.dev), ino: String(s.ino) } }; }
function assertRoot(pin, code) { const s = fs.statSync(pin.target); if (!s.isDirectory() || String(s.dev) !== pin.identity.dev || String(s.ino) !== pin.identity.ino) fail(code); ownerMode(s, 0o700, code); noLinks(pin.target, code); }
function parseJson(ref, code) { try { return JSON.parse(ref.bytes.toString('utf8')); } catch { fail(code); } }
function assertIndependentAuthorityKeys(left, right) {
  const code = 'm4_route_executor_evidence_invalid';
  const normalize = document => {
    if (!exact(document, ['schema', 'keyId', 'key']) || document.schema !== 'amf.migration-signing-key/v1'
      || !ID.test(document.keyId) || typeof document.key !== 'string') fail(code);
    const decoded = Buffer.from(document.key, 'base64');
    if (decoded.length < 32 || decoded.length > 64 || decoded.toString('base64') !== document.key) {
      decoded.fill(0); fail(code);
    }
    const block = Buffer.alloc(64); decoded.copy(block); decoded.fill(0); return { keyId: document.keyId, block };
  };
  const first = normalize(left); const second = normalize(right);
  try {
    if (first.keyId === second.keyId || crypto.timingSafeEqual(first.block, second.block)) fail(code);
  } finally { first.block.fill(0); second.block.fill(0); }
}
function clockNow(clock) { let value; try { value = clock().toISOString(); } catch { fail('m4_route_executor_clock_invalid'); } try { if (!timestampWithin(value, value, value)) fail('m4_route_executor_clock_invalid'); } catch { fail('m4_route_executor_clock_invalid'); } return value; }
function envSpans(bytes) {
  if (bytes.includes(0x00) || bytes.includes(0x0d)) fail('m4_route_executor_runtime_config_invalid');
  const text = bytes.toString('utf8'); if (!Buffer.from(text, 'utf8').equals(bytes)) fail('m4_route_executor_runtime_config_invalid');
  const found = {};
  let offset = 0;
  for (const line of text.split('\n')) { const length = Buffer.byteLength(line); const match = /^(AMF_CONVERSATION_(?:READER|EXTRACTOR)_MODE)=([A-Za-z0-9-]+)$/.exec(line);
    if (/^\s*(?:export\s+)?AMF_CONVERSATION_(?:READER|EXTRACTOR)_MODE\b/.test(line) && !match) fail('m4_route_executor_runtime_config_invalid');
    if (match) { if (found[match[1]]) fail('m4_route_executor_runtime_config_invalid'); found[match[1]] = { start: offset + Buffer.byteLength(match[1]) + 1, end: offset + length, value: match[2] }; }
    offset += length + 1;
  }
  const reader = found.AMF_CONVERSATION_READER_MODE; const extractor = found.AMF_CONVERSATION_EXTRACTOR_MODE;
  if (!reader || !extractor || !['disabled', 'shadow'].includes(reader.value) || extractor.value !== 'legacy') fail('m4_route_executor_runtime_config_invalid');
  return { reader, extractor };
}
export function m4RouteCheckpoint(beforeDigest, afterDigest, currentReaderMode, currentExtractorMode) {
  if (!DIGEST.test(beforeDigest) || !DIGEST.test(afterDigest) || !['disabled', 'shadow'].includes(currentReaderMode)
    || currentExtractorMode !== 'legacy') fail('m4_route_executor_revision_input_invalid');
  return { publicReader: { id: 'm4-public-reader-active', digest: shaCanonical(['amf.m4-route-revision/v1', 'public-reader', 'active', afterDigest]) },
    extractorReader: { id: 'm4-extractor-reader-v3', digest: shaCanonical(['amf.m4-route-revision/v1', 'extractor-reader', 'v3', 'conversation-v3', afterDigest]) },
    rollback: { id: 'm4-route-rollback', digest: shaCanonical(['amf.m4-route-revision/v1', 'rollback', currentReaderMode, currentExtractorMode, beforeDigest]) } };
}
function replaceSpans(before, spans) {
  const replacements = [
    { ...spans.reader, replacement: Buffer.from('active') },
    { ...spans.extractor, replacement: Buffer.from('v3') }
  ].sort((left, right) => left.start - right.start);
  const chunks = []; let cursor = 0;
  for (const item of replacements) {
    if (item.start < cursor || before.subarray(item.start, item.end).toString('utf8') !== item.value) {
      fail('m4_route_executor_runtime_config_invalid');
    }
    chunks.push(before.subarray(cursor, item.start), item.replacement); cursor = item.end;
  }
  chunks.push(before.subarray(cursor));
  const result = Buffer.concat(chunks);
  if (!envSpansAfter(result)) fail('m4_route_executor_runtime_config_invalid');
  return result;
}
function envSpansAfter(bytes) { const text = bytes.toString('utf8'); const lines = text.split('\n'); return lines.filter(l => l === 'AMF_CONVERSATION_READER_MODE=active').length === 1 && lines.filter(l => l === 'AMF_CONVERSATION_EXTRACTOR_MODE=v3').length === 1; }
function ensureDirectory(root, relative, code) { let current = root; for (const part of relative.split('/')) { current = path.join(current, part); try { fs.mkdirSync(current, { mode: 0o700 }); } catch (e) { if (e?.code !== 'EEXIST') fail(code); } const s = fs.lstatSync(current); if (!s.isDirectory() || s.isSymbolicLink()) fail(code); ownerMode(s, 0o700, code); } return current; }
function fsyncDirectory(directory) { const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function writeAtomic(target, bytes, code, noReplace = false) { const dir = path.dirname(target); const temp = path.join(dir, `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}`); let fd;
  try { fd = fs.openSync(temp, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600); fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    if (noReplace) { fs.linkSync(temp, target); fs.unlinkSync(temp); } else fs.renameSync(temp, target);
    fsyncDirectory(dir);
  } catch (e) { if (fd !== undefined) try { fs.closeSync(fd); } catch {} try { fs.unlinkSync(temp); } catch {} if (e?.code === 'EEXIST') fail(`${code}_exists`); fail(code); }
}
function dataProperty(object, key, code) {
  let descriptor; try { descriptor = Object.getOwnPropertyDescriptor(object, key); } catch { fail(code); }
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
  return descriptor.value;
}
function adapterFor(config, dependencies) {
  const code = 'm4_route_executor_adapter_invalid';
  let registry; try { registry = dataProperty(dependencies, 'adapters', code); } catch { fail(code); }
  if (!exact(registry, Object.keys(registry))) fail(code);
  const adapter = dataProperty(registry, config.deploymentAdapter, code);
  if (!exact(adapter, ['postCommit', 'readiness', 'rollback'])) fail(code);
  const hooks = {};
  for (const [kind, id] of [['postCommit', config.postCommitHook], ['readiness', config.readinessHook], ['rollback', config.rollbackHook]]) {
    const map = dataProperty(adapter, kind, code);
    if (!exact(map, Object.keys(map))) fail(code);
    const fn = dataProperty(map, id, code); if (typeof fn !== 'function') fail(code); hooks[kind] = fn;
  }
  return hooks;
}
function authorizationEvidence(manifest) { return { manifestId: manifest.manifestId, digest: manifest.integrity.payloadDigest, signature: manifest.integrity.signature }; }
function prepare(configPath, dependencies) {
  const configRef = readFile(configPath, 'm4_route_executor_input_invalid'); const config = parseJson(configRef, 'm4_route_executor_input_invalid');
  if (!exact(config, KEYS) || config.schema !== M4_ROUTE_EXECUTOR_INPUT_SCHEMA || !ID.test(config.executionId) || !Number.isSafeInteger(config.revision) || config.revision < 1
    || ![config.deploymentAdapter, config.postCommitHook, config.readinessHook, config.rollbackHook].every(value => typeof value === 'string' && ID.test(value))) fail('m4_route_executor_input_invalid');
  const artifacts = validateRoot(config.artifactRoot, 'm4_route_executor_input_invalid'); const backups = validateRoot(config.backupRoot, 'm4_route_executor_input_invalid'); parentSafe(config.runtimeConfigPath, 'm4_route_executor_input_invalid');
  const refs = Object.fromEntries([['authorization', config.authorizationManifestPath], ['authorizationKey', config.authorizationKeyPath], ['scope', config.selectorScopeManifestPath], ['scopeKey', config.selectorScopeTrustKeyPath], ['runtime', config.runtimeConfigPath]].map(([k,p]) => [k, readFile(p, 'm4_route_executor_input_invalid')]));
  const authorization = parseJson(refs.authorization, 'm4_route_executor_input_invalid'); const authorizationKey = parseJson(refs.authorizationKey, 'm4_route_executor_input_invalid'); const scope = parseJson(refs.scope, 'm4_route_executor_input_invalid'); const scopeKey = parseJson(refs.scopeKey, 'm4_route_executor_input_invalid');
  let verifiedAuthorization; let verifiedScope; try { verifiedAuthorization = verifyM4CutoverAuthorization(authorization, authorizationKey); verifiedScope = verifyM4SelectorScopeSnapshot(scope, scopeKey); } catch { fail('m4_route_executor_evidence_invalid'); }
  assertIndependentAuthorityKeys(authorizationKey, scopeKey);
  if (canonicalJson(verifiedAuthorization.selectorScopeEvidence) !== canonicalJson(m4AuthorityEvidence(verifiedScope))) fail('m4_route_executor_scope_mismatch');
  const spans = envSpans(refs.runtime.bytes); const after = replaceSpans(refs.runtime.bytes, spans); const checkpoints = m4RouteCheckpoint(refs.runtime.digest, digest(after), spans.reader.value, spans.extractor.value);
  if (canonicalJson(checkpoints.publicReader) !== canonicalJson(verifiedAuthorization.routeConfiguration.publicReader.revision) || canonicalJson(checkpoints.extractorReader) !== canonicalJson(verifiedAuthorization.routeConfiguration.extractorReader.revision) || canonicalJson(checkpoints.rollback) !== canonicalJson(verifiedAuthorization.rollbackRevision)) fail('m4_route_executor_revision_mismatch');
  const target = path.join(config.artifactRoot, 'm4', 'route-execution', `${config.executionId}-r${config.revision}.json`); const lock = `${config.runtimeConfigPath}.m4-route-executor.lock`; const backupDir = path.join(config.backupRoot, 'm4', 'route-execution', `${config.executionId}-r${config.revision}`);
  const backupId = `${config.executionId}-r${config.revision}`; if (!ID.test(backupId)) fail('m4_route_executor_input_invalid');
  const hooks = adapterFor(config, dependencies); const inputs = Object.fromEntries(Object.entries(refs).map(([k,v]) => [k, { digest: v.digest, identity: v.identity }]));
  const binding = { schema: M4_ROUTE_EXECUTION_PLAN_SCHEMA, executionId: config.executionId, revision: config.revision, inputs, roots: [artifacts.identity, backups.identity], adapter: config.deploymentAdapter, hooks: [config.postCommitHook, config.readinessHook, config.rollbackHook], target, lock, backupDir, checkpoints, scope: m4AuthorityEvidence(verifiedScope), scopeWindow: [verifiedScope.observedAt, verifiedScope.validThrough] };
  const plan = { schema: M4_ROUTE_EXECUTION_PLAN_SCHEMA, executionId: config.executionId, revision: config.revision, state: 'planned', authorization: authorizationEvidence(verifiedAuthorization), selectorEvidence: m4AuthorityEvidence(verifiedScope), targetRouteRevisions: { publicReader: checkpoints.publicReader, extractorReader: checkpoints.extractorReader }, rollbackRevision: checkpoints.rollback, managedKeys: ['AMF_CONVERSATION_READER_MODE', 'AMF_CONVERSATION_EXTRACTOR_MODE'], beforeDigest: refs.runtime.digest, afterDigest: digest(after), executionProfileDigest: shaCanonical([config.deploymentAdapter, config.postCommitHook, config.readinessHook, config.rollbackHook]), confirmationDigest: shaCanonical(binding) };
  return { config, refs, artifacts, backups, verifiedScope, after, target, lock, backupDir, backupId, hooks, plan };
}
function freshness(prepared, dependencies) { const now = clockNow(dependencies?.clock ?? (() => new Date())); if (!timestampWithin(now, prepared.verifiedScope.observedAt, prepared.verifiedScope.validThrough)) fail('m4_route_executor_scope_stale'); }
function absent(target, code) { try { fs.lstatSync(target); fail(code); } catch (error) { if (error?.code !== 'ENOENT') throw error; } }
function acquireLock(target, confirmationDigest) {
  let fd;
  try {
    fd = fs.openSync(target, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, `${confirmationDigest}\n`); fs.fsyncSync(fd);
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o777n) !== 0o600n) {
      fail('m4_route_executor_lock_failed');
    }
    const pin = { fd, dev: String(stat.dev), ino: String(stat.ino) }; fsyncDirectory(path.dirname(target)); return pin;
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (error?.code === 'EEXIST') fail('m4_route_executor_lock_exists');
    if (error?.code?.startsWith?.('m4_route_executor_')) throw error;
    fail('m4_route_executor_lock_failed');
  }
}
function assertLockHeld(target, pin) {
  let stat;
  try { stat = fs.lstatSync(target, { bigint: true }); } catch { fail('m4_route_executor_lock_changed'); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.uid !== BigInt(process.getuid())
    || (stat.mode & 0o777n) !== 0o600n || String(stat.dev) !== pin.dev || String(stat.ino) !== pin.ino) {
    fail('m4_route_executor_lock_changed');
  }
}
function releaseLock(target, pin) {
  assertLockHeld(target, pin); fs.unlinkSync(target); fsyncDirectory(path.dirname(target)); fs.closeSync(pin.fd); pin.fd = undefined;
}
function cleanupBackup(directory, root) {
  if (!directory.startsWith(`${root}${path.sep}`)) return;
  let stat; try { stat = fs.lstatSync(directory); } catch { return; }
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) return;
  for (const name of fs.readdirSync(directory)) {
    const target = path.join(directory, name); const item = fs.lstatSync(target);
    if (!item.isFile() || item.isSymbolicLink() || item.uid !== process.getuid() || item.nlink !== 1 || (item.mode & 0o777) !== 0o600) return;
  }
  fs.rmSync(directory, { recursive: true }); fsyncDirectory(path.dirname(directory));
}
function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || !ID.test(value.id) || !DIGEST.test(value.digest)) fail(code);
  return value;
}
function evidence(value, code) {
  if (!exact(value, ['manifestId', 'digest', 'signature']) || !ID.test(value.manifestId)
    || !DIGEST.test(value.digest) || !SIGNATURE.test(value.signature)) fail(code);
  return value;
}
function routeResultBody(value, code) {
  const keys = ['schema', 'executionId', 'revision', 'state', 'planDigest', 'authorization', 'selectorEvidence',
    'targetRouteRevisions', 'rollbackRevision', 'beforeDigest', 'afterDigest', 'backup', 'postCommit', 'readiness', 'rollback'];
  if (!exact(value, keys) || value.schema !== M4_ROUTE_EXECUTION_RESULT_SCHEMA || !ID.test(value.executionId)
    || !Number.isSafeInteger(value.revision) || value.revision < 1 || !['active', 'rolled_back', 'rollback_failed'].includes(value.state)
    || !DIGEST.test(value.planDigest) || !DIGEST.test(value.beforeDigest) || !DIGEST.test(value.afterDigest)
    || !exact(value.targetRouteRevisions, ['publicReader', 'extractorReader'])
    || !exact(value.backup, ['id', 'digest']) || !ID.test(value.backup.id) || !DIGEST.test(value.backup.digest)
    || !exact(value.postCommit, ['state']) || !['passed', 'failed'].includes(value.postCommit.state)
    || !exact(value.readiness, ['state']) || !['passed', 'failed', 'not_run'].includes(value.readiness.state)
    || !exact(value.rollback, ['state']) || !['not_needed', 'passed', 'failed'].includes(value.rollback.state)) fail(code);
  evidence(value.authorization, code); evidence(value.selectorEvidence, code);
  checkpoint(value.targetRouteRevisions.publicReader, code); checkpoint(value.targetRouteRevisions.extractorReader, code);
  checkpoint(value.rollbackRevision, code);
  if (value.state === 'active' && (value.postCommit.state !== 'passed' || value.readiness.state !== 'passed' || value.rollback.state !== 'not_needed')) fail(code);
  if (value.state === 'rolled_back' && (value.rollback.state !== 'passed' || (value.postCommit.state === 'passed' && value.readiness.state === 'passed'))) fail(code);
  if (value.state === 'rollback_failed' && (value.rollback.state !== 'failed'
    || (value.postCommit.state === 'passed' && value.readiness.state === 'passed'))) fail(code);
  return value;
}
export function verifyM4RouteExecutionResult(value) {
  let item;
  try {
    if (!exact(value, ['schema', 'executionId', 'revision', 'state', 'planDigest', 'authorization', 'selectorEvidence',
      'targetRouteRevisions', 'rollbackRevision', 'beforeDigest', 'afterDigest', 'backup', 'postCommit', 'readiness', 'rollback', 'integrity'])
      || !exact(value.integrity, ['algorithm', 'payloadDigest']) || value.integrity.algorithm !== 'sha256'
      || !DIGEST.test(value.integrity.payloadDigest)) fail('m4_route_executor_result_invalid');
    const { integrity, ...body } = structuredClone(value); item = routeResultBody(body, 'm4_route_executor_result_invalid');
    if (shaCanonical(item) !== integrity.payloadDigest) fail('m4_route_executor_result_digest_mismatch');
    return structuredClone(value);
  } catch (error) {
    if (error?.code?.startsWith?.('m4_route_executor_')) throw error;
    fail('m4_route_executor_result_invalid');
  }
}
export function planM4RouteExecutor({ configPath } = {}, dependencies = {}) {
  try {
    const prepared = prepare(configPath, dependencies); freshness(prepared, dependencies);
    absent(prepared.target, 'm4_route_executor_artifact_exists'); absent(prepared.lock, 'm4_route_executor_lock_exists');
    return structuredClone(prepared.plan);
  } catch (error) {
    if (error?.code?.startsWith('m4_route_executor_')) throw error;
    fail('m4_route_executor_plan_invalid');
  }
}
export async function runM4RouteExecutor({ configPath, confirmedPlanDigest } = {}, dependencies = {}) {
  if (typeof confirmedPlanDigest !== 'string' || !DIGEST.test(confirmedPlanDigest)) fail('m4_route_executor_confirmation_invalid');
  let prepared;
  try {
    prepared = prepare(configPath, dependencies);
    if (prepared.plan.confirmationDigest !== confirmedPlanDigest) fail('m4_route_executor_confirmation_invalid');
    freshness(prepared, dependencies); assertRoot(prepared.artifacts, 'm4_route_executor_input_changed');
    assertRoot(prepared.backups, 'm4_route_executor_input_changed');
    for (const ref of Object.values(prepared.refs)) {
      const current = readFile(ref.target, 'm4_route_executor_input_changed');
      if (current.digest !== ref.digest || !sameIdentity(current.identity, ref.identity)) fail('m4_route_executor_input_changed');
    }
    absent(prepared.target, 'm4_route_executor_artifact_exists');
    absent(prepared.lock, 'm4_route_executor_lock_exists');
    parentSafe(prepared.config.runtimeConfigPath, 'm4_route_executor_input_changed');
  } catch (error) {
    if (error?.code?.startsWith?.('m4_route_executor_')) throw error;
    fail('m4_route_executor_run_invalid');
  }
  let lock = null; let mutationStarted = false; let backupCreated = false;
  try {
    lock = acquireLock(prepared.lock, prepared.plan.confirmationDigest);
    const reverified = prepare(configPath, dependencies);
    if (reverified.plan.confirmationDigest !== prepared.plan.confirmationDigest) fail('m4_route_executor_input_changed');
    prepared = reverified; freshness(prepared, dependencies);
    assertRoot(prepared.artifacts, 'm4_route_executor_input_changed'); assertRoot(prepared.backups, 'm4_route_executor_input_changed');
    assertLockHeld(prepared.lock, lock); absent(prepared.target, 'm4_route_executor_artifact_exists');
    const latest = readFile(prepared.config.runtimeConfigPath, 'm4_route_executor_input_changed');
    if (latest.digest !== prepared.refs.runtime.digest || !sameIdentity(latest.identity, prepared.refs.runtime.identity)) {
      fail('m4_route_executor_input_changed');
    }
    ensureDirectory(prepared.config.artifactRoot, 'm4/route-execution', 'm4_route_executor_write_failed');
    const backupParent = ensureDirectory(prepared.config.backupRoot, 'm4/route-execution', 'm4_route_executor_backup_failed');
    try { fs.mkdirSync(prepared.backupDir, { mode: 0o700 }); } catch (error) {
      if (error?.code === 'EEXIST') fail('m4_route_executor_backup_exists');
      fail('m4_route_executor_backup_failed');
    }
    backupCreated = true; ownerMode(fs.lstatSync(prepared.backupDir), 0o700, 'm4_route_executor_backup_failed');
    fsyncDirectory(backupParent);
    writeAtomic(path.join(prepared.backupDir, 'runtime-config.before'), latest.bytes, 'm4_route_executor_backup_failed', true);
    const backupDigest = digest(latest.bytes);
    const backupId = prepared.backupId;
    const metadata = { schema: 'amf.m4-route-backup/v1', backupId, beforeDigest: backupDigest, size: latest.bytes.length };
    writeAtomic(path.join(prepared.backupDir, 'metadata.json'), Buffer.from(`${canonicalJson(metadata)}\n`), 'm4_route_executor_backup_failed', true);
    assertLockHeld(prepared.lock, lock); freshness(prepared, dependencies);
    const finalVerification = prepare(configPath, dependencies);
    if (finalVerification.plan.confirmationDigest !== prepared.plan.confirmationDigest) fail('m4_route_executor_input_changed');
    mutationStarted = true;
    writeAtomic(prepared.config.runtimeConfigPath, prepared.after, 'm4_route_executor_write_failed');
    let state = 'active'; let postCommitState = 'failed'; let readinessState = 'not_run'; let rollbackState = 'not_needed';
    try {
      await prepared.hooks.postCommit(structuredClone(prepared.plan)); postCommitState = 'passed';
      if (await prepared.hooks.readiness(structuredClone(prepared.plan)) !== true) fail('m4_route_executor_readiness_failed');
      readinessState = 'passed';
    } catch {
      if (postCommitState === 'passed') readinessState = 'failed';
      rollbackState = 'failed';
      try {
        writeAtomic(prepared.config.runtimeConfigPath, latest.bytes, 'm4_route_executor_restore_failed');
        const restored = readFile(prepared.config.runtimeConfigPath, 'm4_route_executor_restore_failed');
        if (restored.digest !== backupDigest) fail('m4_route_executor_restore_failed');
        await prepared.hooks.rollback(structuredClone(prepared.plan)); rollbackState = 'passed'; state = 'rolled_back';
      } catch { state = 'rollback_failed'; }
    }
    const body = routeResultBody({
      schema: M4_ROUTE_EXECUTION_RESULT_SCHEMA, executionId: prepared.config.executionId, revision: prepared.config.revision,
      state, planDigest: prepared.plan.confirmationDigest, authorization: prepared.plan.authorization,
      selectorEvidence: prepared.plan.selectorEvidence, targetRouteRevisions: prepared.plan.targetRouteRevisions,
      rollbackRevision: prepared.plan.rollbackRevision, beforeDigest: prepared.plan.beforeDigest,
      afterDigest: prepared.plan.afterDigest, backup: { id: backupId, digest: backupDigest },
      postCommit: { state: postCommitState }, readiness: { state: readinessState }, rollback: { state: rollbackState }
    }, 'm4_route_executor_result_invalid');
    const result = { ...body, integrity: { algorithm: 'sha256', payloadDigest: shaCanonical(body) } };
    writeAtomic(prepared.target, Buffer.from(`${canonicalJson(result)}\n`), 'm4_route_executor_result_failed', true);
    if (state !== 'rollback_failed') releaseLock(prepared.lock, lock);
    else { fs.closeSync(lock.fd); lock.fd = undefined; }
    return structuredClone(result);
  } catch (error) {
    if (lock?.fd !== undefined) {
      if (!mutationStarted) {
        try { releaseLock(prepared.lock, lock); } catch { try { fs.closeSync(lock.fd); } catch {} }
      } else try { fs.closeSync(lock.fd); } catch {}
    }
    if (backupCreated && !mutationStarted) try { cleanupBackup(prepared.backupDir, prepared.config.backupRoot); } catch {}
    if (error?.code?.startsWith?.('m4_route_executor_')) throw error;
    fail('m4_route_executor_run_failed');
  }
}
