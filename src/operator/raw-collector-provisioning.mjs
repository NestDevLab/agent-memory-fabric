import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { normalizeIngestKeyRing } from '../ingest/raw-event-contract.mjs';
import { normalizeLogicalMessageKeyRing } from '../ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

export const RAW_COLLECTOR_HANDOFF_SCHEMA = 'amf.raw-collector-handoff/v1';
export const RAW_COLLECTOR_PERMISSIONS = Object.freeze(['memory:status', 'raw:ingest']);

const SAFE_PRINCIPAL = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HEX_DIGEST = /^[a-f0-9]{64}$/;
const AUTH_MODES = new Set(['allow_all', 'scoped', 'read_only_scoped', 'deny']);

function fail(code, cause = null) {
  const error = new Error(code);
  if (cause) error.cause = cause;
  return error;
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, allowed) {
  return object(value) && Object.keys(value).sort().join('\0') === [...allowed].sort().join('\0');
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function allowedOwner(uid, serviceOwnerUid) {
  return uid === 0 || uid === serviceOwnerUid;
}

function safePathComponents(target, serviceOwnerUid, code) {
  const resolved = path.resolve(target); const parsed = path.parse(resolved);
  let current = parsed.root;
  for (const component of resolved.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component); let stat;
    try { stat = fs.lstatSync(current); } catch (error) { throw fail(code, error); }
    if (stat.isSymbolicLink() || !allowedOwner(stat.uid, serviceOwnerUid)) throw fail(code);
  }
  return resolved;
}

function privateFile(filePath, serviceOwnerUid, code) {
  const resolved = safePathComponents(filePath, serviceOwnerUid, code); let stat; let fd;
  try { stat = fs.lstatSync(resolved); } catch (error) { throw fail(code, error); }
  const euid = process.geteuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0
    || !allowedOwner(stat.uid, serviceOwnerUid)
    || (euid !== undefined && euid !== 0 && euid !== serviceOwnerUid)) throw fail(code);
  try {
    fd = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (opened.dev !== stat.dev || opened.ino !== stat.ino || opened.nlink !== 1 || !opened.isFile()
      || !allowedOwner(opened.uid, serviceOwnerUid) || (opened.mode & 0o077) !== 0) throw fail(code);
    return { path: resolved, stat: opened, bytes: fs.readFileSync(fd) };
  } catch (error) {
    if (error?.message === code) throw error;
    throw fail(code, error);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function privateDirectory(directory, serviceOwnerUid, code) {
  const resolved = safePathComponents(directory, serviceOwnerUid, code); let stat;
  try { stat = fs.lstatSync(resolved); } catch (error) { throw fail(code, error); }
  const euid = process.geteuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
    || !allowedOwner(stat.uid, serviceOwnerUid)
    || (euid !== undefined && euid !== 0 && euid !== serviceOwnerUid)) throw fail(code);
  return resolved;
}

function parseJson(record, code) {
  try { return JSON.parse(record.bytes.toString('utf8')); } catch (error) { throw fail(code, error); }
}

function parseKey(value, code = 'collector_crypto_key_invalid') {
  const raw = String(value || '');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw fail(code);
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw fail(code);
  return decoded;
}

function normalizedList(value, { wildcard = false } = {}) {
  if (wildcard && value === '*') return ['*'];
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : null;
  if (!values) throw fail('collector_auth_registry_invalid');
  const output = values.map(item => String(item).trim()).filter(Boolean);
  if (output.length === 0 || new Set(output).size !== output.length) throw fail('collector_auth_registry_invalid');
  return output;
}

function authRows(registry) {
  if (Array.isArray(registry)) return { rows: registry, wrapper: 'array' };
  if (exactKeys(registry, ['rows']) && Array.isArray(registry.rows)) return { rows: registry.rows, wrapper: 'rows' };
  if (exactKeys(registry, ['data']) && Array.isArray(registry.data)) return { rows: registry.data, wrapper: 'data' };
  throw fail('collector_auth_registry_invalid');
}

function validateAuthRegistry(registry) {
  const extracted = authRows(registry); const actors = new Set(); const tokenDigests = new Set();
  for (const row of extracted.rows) {
    if (!object(row) || Object.hasOwn(row, 'token') || !SAFE_PRINCIPAL.test(String(row.actor || ''))
      || typeof row.active !== 'boolean' || !AUTH_MODES.has(String(row.mode || ''))
      || !HEX_DIGEST.test(String(row.tokenSha256 || ''))) throw fail('collector_auth_registry_invalid');
    normalizedList(row.allowedScopes, { wildcard: true }); normalizedList(row.permissions, { wildcard: true });
    if (actors.has(row.actor) || tokenDigests.has(row.tokenSha256)) throw fail('collector_auth_registry_invalid');
    actors.add(row.actor); tokenDigests.add(row.tokenSha256);
  }
  return extracted;
}

function withAuthRows(registry, wrapper, rows) {
  if (wrapper === 'array') return rows;
  return { ...registry, [wrapper]: rows };
}

function validatePolicy(policy) {
  if (!exactKeys(policy, ['actors', 'scopes']) || !object(policy.actors) || !object(policy.scopes)) throw fail('collector_policy_invalid');
  for (const [actor, entry] of Object.entries(policy.actors)) {
    if (!SAFE_PRINCIPAL.test(actor) || !object(entry) || !AUTH_MODES.has(String(entry.mode || ''))) throw fail('collector_policy_invalid');
    if (entry.allowedScopes !== undefined) {
      const scopes = normalizedList(entry.allowedScopes, { wildcard: true });
      if (scopes.some(scope => scope !== '*' && typeof scope !== 'string')) throw fail('collector_policy_invalid');
    }
  }
  for (const [scope, entry] of Object.entries(policy.scopes)) if (!scope || !object(entry)) throw fail('collector_policy_invalid');
  return policy;
}

function validateIngestRing(ring) {
  if (!exactKeys(ring, ['keys', 'digestKey', 'logicalMessageKeys', 'authorizations'])
    || !object(ring.keys) || !object(ring.authorizations)) throw fail('collector_ingest_key_ring_invalid');
  try { normalizeIngestKeyRing(ring); } catch (error) { throw fail('collector_ingest_key_ring_invalid', error); }
  if (!exactKeys(ring.logicalMessageKeys, ['currentKeyVersion', 'keys']) || !object(ring.logicalMessageKeys.keys)) throw fail('collector_ingest_key_ring_invalid');
  for (const keyId of Object.keys(ring.keys)) {
    const rule = ring.authorizations[keyId];
    if (!exactKeys(rule, ['actors', 'sourceInstances']) || !Array.isArray(rule.actors) || !Array.isArray(rule.sourceInstances)
      || rule.actors.length < 1 || rule.sourceInstances.length < 1
      || rule.actors.some(actor => !SAFE_PRINCIPAL.test(String(actor)))
      || rule.sourceInstances.some(instance => !SAFE_PRINCIPAL.test(String(instance)))) throw fail('collector_ingest_key_ring_invalid');
  }
  if (Object.keys(ring.authorizations).some(keyId => !Object.hasOwn(ring.keys, keyId))) throw fail('collector_ingest_key_ring_invalid');
  return ring;
}

function validateRoutingRing(ring) {
  if (!exactKeys(ring, ['currentKeyVersion', 'keys']) || !object(ring.keys)) throw fail('collector_routing_key_ring_invalid');
  try { normalizeLogicalMessageKeyRing(ring); } catch (error) { throw fail('collector_routing_key_ring_invalid', error); }
  return ring;
}

function cryptoInventory(ingestRing, routingRing) {
  const inventory = new Map();
  const add = (label, value) => {
    const encoded = parseKey(value).toString('hex');
    if (inventory.has(encoded)) throw fail('collector_crypto_key_reuse_detected');
    inventory.set(encoded, label);
  };
  for (const [id, value] of Object.entries(ingestRing.keys)) add(`ingest:${id}`, value);
  add('digest', ingestRing.digestKey);
  for (const [id, value] of Object.entries(ingestRing.logicalMessageKeys.keys)) add(`logical:${id}`, value);
  for (const [id, value] of Object.entries(routingRing.keys)) add(`routing:${id}`, value);
  return inventory;
}

function freshKey(randomBytes, inventory, label) {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const bytes = Buffer.from(randomBytes(32));
    if (bytes.length !== 32) throw fail('collector_random_source_invalid');
    const encoded = bytes.toString('hex');
    if (inventory.has(encoded)) continue;
    inventory.set(encoded, label);
    return bytes.toString('base64');
  }
  throw fail('collector_random_source_exhausted');
}

function freshBearer(randomBytes, inventory, tokenDigests) {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const bytes = Buffer.from(randomBytes(32));
    if (bytes.length !== 32) throw fail('collector_random_source_invalid');
    const encoded = bytes.toString('hex'); const bearer = bytes.toString('base64url');
    const digest = crypto.createHash('sha256').update(bearer, 'utf8').digest('hex');
    if (inventory.has(encoded) || tokenDigests.has(digest)) continue;
    inventory.set(encoded, 'bearer'); tokenDigests.add(digest);
    return { bearer, tokenSha256: digest };
  }
  throw fail('collector_random_source_exhausted');
}

function exactCollectorRow(row, actorId, scope) {
  try {
    return exactKeys(row, ['tokenSha256', 'active', 'actor', 'mode', 'allowedScopes', 'permissions'])
      && row.active === true && row.actor === actorId && row.mode === 'scoped'
      && canonicalJson(normalizedList(row.allowedScopes)) === canonicalJson([scope])
      && canonicalJson(normalizedList(row.permissions)) === canonicalJson(RAW_COLLECTOR_PERMISSIONS)
      && HEX_DIGEST.test(String(row.tokenSha256 || '')) && !Object.hasOwn(row, 'token');
  } catch { return false; }
}

function exactPolicyActor(entry, scope) {
  try {
    return exactKeys(entry, ['mode', 'allowedScopes']) && entry.mode === 'scoped'
      && canonicalJson(normalizedList(entry.allowedScopes)) === canonicalJson([scope]);
  } catch { return false; }
}

function exactAuthorization(rule, actorId, sourceInstanceId) {
  return exactKeys(rule, ['actors', 'sourceInstances'])
    && canonicalJson(rule.actors) === canonicalJson([actorId])
    && canonicalJson(rule.sourceInstances) === canonicalJson([sourceInstanceId]);
}

function authorizationTouchesIdentity(rule, actorId, sourceInstanceId) {
  return rule.actors.includes(actorId) || rule.sourceInstances.includes(sourceInstanceId);
}

function requireAbsentPath(filePath, serviceOwnerUid, parentCode, existsCode) {
  const resolved = path.resolve(filePath);
  privateDirectory(path.dirname(resolved), serviceOwnerUid, parentCode);
  try {
    fs.lstatSync(resolved);
    throw fail(existsCode);
  } catch (error) {
    if (error?.message === existsCode) throw error;
    if (error?.code !== 'ENOENT') throw fail(parentCode, error);
  }
  return resolved;
}

function ensureDirectory(directory, mode = 0o700) {
  fs.mkdirSync(directory, { recursive: false, mode });
  fs.chmodSync(directory, mode); fsyncDirectory(path.dirname(directory));
}

function writeExclusive(filePath, bytes, mode = 0o600) {
  const fd = fs.openSync(filePath, 'wx', mode);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.chmodSync(filePath, mode);
}

function writeReplacement(filePath, bytes, metadata) {
  const temporary = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600); fs.writeFileSync(fd, bytes);
    if (process.geteuid?.() === 0) fs.fchownSync(fd, metadata.uid, metadata.gid);
    fs.fchmodSync(fd, metadata.mode & 0o777); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    return temporary;
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function replacePrepared(temporary, target) {
  fs.renameSync(temporary, target);
}

function restoreRecord(record) {
  const temporary = writeReplacement(record.path, record.bytes, record.stat);
  replacePrepared(temporary, record.path); fsyncDirectory(path.dirname(record.path));
}

function acquireLock(lockPath, actorId, sourceInstanceId, keyId, clock) {
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx', 0o600);
    fs.writeFileSync(fd, canonicalBytes({ version: 1, pid: process.pid, actorId, sourceInstanceId, keyId, createdAt: clock().toISOString() }));
    fs.fsyncSync(fd); fs.closeSync(fd); fsyncDirectory(path.dirname(lockPath));
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (error?.code === 'EEXIST') throw fail('collector_provisioning_locked');
    throw fail('collector_provisioning_lock_failed', error);
  }
}

function releaseLock(lockPath) {
  fs.rmSync(lockPath, { force: true }); fsyncDirectory(path.dirname(lockPath));
}

function safeTimestamp(date) {
  return date.toISOString().replace(/[-:.]/g, '').replace('Z', 'Z');
}

function backupInputs(records, backupRoot, serviceOwnerUid, actorId, keyId, clock) {
  const root = privateDirectory(backupRoot, serviceOwnerUid, 'collector_backup_root_unsafe');
  const backupPath = path.join(root, `${safeTimestamp(clock())}-${actorId}-${keyId}-${crypto.randomUUID().slice(0, 8)}`);
  ensureDirectory(backupPath);
  for (const [name, record] of Object.entries(records)) writeExclusive(path.join(backupPath, `${name}.json`), record.bytes);
  fsyncDirectory(backupPath);
  return backupPath;
}

function stageHandoff({ handoffPath, serviceOwnerUid, actorId, sourceInstanceId, keyId, scope, bearer, ingestKey, digestKey,
  cursorKey, leaseKey, logicalMessageKeys, routingRing, clock }) {
  const finalPath = requireAbsentPath(handoffPath, serviceOwnerUid,
    'collector_handoff_parent_unsafe', 'collector_handoff_exists');
  const staging = `${finalPath}.tmp-${process.pid}-${crypto.randomUUID()}`; ensureDirectory(staging);
  const files = {
    'bearer.token': Buffer.from(`${bearer}\n`, 'utf8'),
    'ingest-master.key': Buffer.from(`${ingestKey}\n`, 'utf8'),
    'digest.key': Buffer.from(`${digestKey}\n`, 'utf8'),
    'cursor.key': Buffer.from(`${cursorKey}\n`, 'utf8'),
    'lease.key': Buffer.from(`${leaseKey}\n`, 'utf8'),
    'logical-message-key-ring.json': canonicalBytes(logicalMessageKeys),
    'routing-key-ring.json': canonicalBytes(routingRing),
    'manifest.json': canonicalBytes({ schema: RAW_COLLECTOR_HANDOFF_SCHEMA, actorId, sourceInstanceId, keyId,
      scope, permissions: RAW_COLLECTOR_PERMISSIONS, createdAt: clock().toISOString(), endpointPath: '/v2/ingest/raw-events' })
  };
  try {
    for (const [name, bytes] of Object.entries(files)) writeExclusive(path.join(staging, name), bytes);
    fsyncDirectory(staging); return { staging, finalPath };
  } catch (error) {
    fs.rmSync(staging, { recursive: true, force: true }); throw error;
  }
}

function invokeFault(faultAt, point) {
  if (faultAt === point || (Array.isArray(faultAt) && faultAt.includes(point))) throw fail(`collector_test_fault_${point}`);
}

export function provisionRawCollector({ authRegistryPath, policyPath, ingestKeyRingPath, routingKeyRingPath,
  actorId, sourceInstanceId, keyId, handoffPath, backupRoot, serviceOwnerUid, dryRun = false,
  clock = () => new Date(), randomBytes = crypto.randomBytes, faultAt = null } = {}) {
  if (![actorId, sourceInstanceId].every(value => SAFE_PRINCIPAL.test(String(value || '')))
    || !SAFE_KEY_ID.test(String(keyId || ''))) throw fail('collector_identity_invalid');
  if (![authRegistryPath, policyPath, ingestKeyRingPath, routingKeyRingPath, handoffPath, backupRoot]
    .every(value => typeof value === 'string' && path.isAbsolute(value))) throw fail('collector_path_invalid');
  if (!Number.isSafeInteger(serviceOwnerUid) || serviceOwnerUid < 0 || typeof dryRun !== 'boolean') throw fail('collector_option_invalid');
  if (!dryRun && process.geteuid?.() !== 0) throw fail('collector_root_required');
  const scope = `agent:${actorId}`; const lockPath = `${path.resolve(authRegistryPath)}.collector-provision.lock`;
  privateDirectory(path.dirname(path.resolve(authRegistryPath)), serviceOwnerUid, 'collector_lock_directory_unsafe');
  requireAbsentPath(lockPath, serviceOwnerUid, 'collector_lock_directory_unsafe', 'collector_provisioning_locked');
  privateDirectory(backupRoot, serviceOwnerUid, 'collector_backup_root_unsafe');
  requireAbsentPath(handoffPath, serviceOwnerUid, 'collector_handoff_parent_unsafe', 'collector_handoff_exists');
  let lockAcquired = false; let preserveLock = false;
  try {
    if (!dryRun) {
      acquireLock(lockPath, actorId, sourceInstanceId, keyId, clock); lockAcquired = true;
    }
    const records = {
      'auth-registry': privateFile(authRegistryPath, serviceOwnerUid, 'collector_auth_registry_file_unsafe'),
      policy: privateFile(policyPath, serviceOwnerUid, 'collector_policy_file_unsafe'),
      'ingest-key-ring': privateFile(ingestKeyRingPath, serviceOwnerUid, 'collector_ingest_key_ring_file_unsafe'),
      'routing-key-ring': privateFile(routingKeyRingPath, serviceOwnerUid, 'collector_routing_key_ring_file_unsafe')
    };
    for (const [label, record] of Object.entries(records)) record.label = label;
    const inputIdentities = new Set(Object.values(records).map(record => `${record.stat.dev}:${record.stat.ino}`));
    if (inputIdentities.size !== Object.keys(records).length) throw fail('collector_input_paths_conflict');
    const registry = parseJson(records['auth-registry'], 'collector_auth_registry_invalid');
    const extracted = validateAuthRegistry(registry);
    const policy = validatePolicy(parseJson(records.policy, 'collector_policy_invalid'));
    const ingestRing = validateIngestRing(parseJson(records['ingest-key-ring'], 'collector_ingest_key_ring_invalid'));
    const routingRing = validateRoutingRing(parseJson(records['routing-key-ring'], 'collector_routing_key_ring_invalid'));
    const inventory = cryptoInventory(ingestRing, routingRing);
    const actorRow = extracted.rows.find(row => row.actor === actorId) || null;
    const policyActor = policy.actors[actorId] || null; const policyScope = policy.scopes[scope] || null;
    const authorizationConflicts = Object.entries(ingestRing.authorizations)
      .filter(([, rule]) => authorizationTouchesIdentity(rule, actorId, sourceInstanceId));
    const actorExact = exactCollectorRow(actorRow, actorId, scope);
    const policyExact = exactPolicyActor(policyActor, scope) && object(policyScope);

    if (actorRow || policyActor || policyScope || authorizationConflicts.length || Object.hasOwn(ingestRing.keys, keyId)) {
      if (actorExact && policyExact && Object.hasOwn(ingestRing.keys, keyId)
        && authorizationConflicts.length === 1 && authorizationConflicts[0][0] === keyId
        && exactAuthorization(ingestRing.authorizations[keyId], actorId, sourceInstanceId)) {
        throw fail('collector_already_provisioned');
      }
      throw fail('collector_provisioning_conflict');
    }

    const safeResult = { ok: true, schema: RAW_COLLECTOR_HANDOFF_SCHEMA, action: 'provision',
      dryRun, actorId, sourceInstanceId, keyId, scope, permissions: RAW_COLLECTOR_PERMISSIONS,
      handoffPath: path.resolve(handoffPath), backupPath: null };
    if (dryRun) return safeResult;

    const tokenDigests = new Set(extracted.rows.map(row => row.tokenSha256));
    const { bearer, tokenSha256 } = freshBearer(randomBytes, inventory, tokenDigests);
    const ingestKey = freshKey(randomBytes, inventory, `ingest:${keyId}`);
    const cursorKey = freshKey(randomBytes, inventory, `cursor:${actorId}`);
    const leaseKey = freshKey(randomBytes, inventory, `lease:${actorId}`);
    const newRow = { tokenSha256, active: true, actor: actorId, mode: 'scoped', allowedScopes: [scope],
      permissions: RAW_COLLECTOR_PERMISSIONS };
    const newRows = actorRow ? extracted.rows.map(row => row.actor === actorId ? newRow : row) : [...extracted.rows, newRow];
    const nextRegistry = withAuthRows(registry, extracted.wrapper, newRows);
    const nextPolicy = { ...policy, actors: { ...policy.actors,
      [actorId]: { mode: 'scoped', allowedScopes: [scope] } }, scopes: { ...policy.scopes,
      [scope]: policyScope || { backendUserId: actorId } } };
    const nextIngestRing = { ...ingestRing, keys: { ...ingestRing.keys, [keyId]: ingestKey },
      authorizations: { ...ingestRing.authorizations,
        [keyId]: { actors: [actorId], sourceInstances: [sourceInstanceId] } } };
    validateAuthRegistry(nextRegistry); validatePolicy(nextPolicy); validateIngestRing(nextIngestRing);
    cryptoInventory(nextIngestRing, routingRing);

    const backupPath = backupInputs(records, backupRoot, serviceOwnerUid, actorId, keyId, clock);
    const handoff = stageHandoff({ handoffPath, serviceOwnerUid, actorId, sourceInstanceId, keyId, scope, bearer, ingestKey,
      digestKey: ingestRing.digestKey, cursorKey, leaseKey, logicalMessageKeys: ingestRing.logicalMessageKeys,
      routingRing, clock });
    const replacementSpecs = [
      [records['ingest-key-ring'], canonicalBytes(nextIngestRing), 'after-ingest-key-ring'],
      [records.policy, canonicalBytes(nextPolicy), 'after-policy'],
      [records['auth-registry'], canonicalBytes(nextRegistry), 'after-auth-registry']
    ];
    const replacements = []; const replaced = []; let handoffCommitted = false;
    try {
      for (const [record, bytes, point] of replacementSpecs) replacements.push({
        record, temporary: writeReplacement(record.path, bytes, record.stat), point
      });
      for (const replacement of replacements) {
        replacePrepared(replacement.temporary, replacement.record.path); replacement.temporary = null;
        replaced.push(replacement.record); invokeFault(faultAt, `${replacement.point}-before-fsync`);
        fsyncDirectory(path.dirname(replacement.record.path));
        invokeFault(faultAt, replacement.point);
      }
      fs.renameSync(handoff.staging, handoff.finalPath); handoffCommitted = true;
      invokeFault(faultAt, 'after-handoff-before-fsync');
      fsyncDirectory(path.dirname(handoff.finalPath));
      invokeFault(faultAt, 'after-handoff');
      return { ...safeResult, backupPath };
    } catch (error) {
      const rollbackErrors = [];
      const attempt = operation => { try { operation(); } catch (cause) { rollbackErrors.push(cause); } };
      attempt(() => fs.rmSync(handoffCommitted ? handoff.finalPath : handoff.staging, { recursive: true, force: true }));
      for (const record of [...replaced].reverse()) attempt(() => {
        invokeFault(faultAt, `rollback-${record.label}`); restoreRecord(record);
      });
      attempt(() => fsyncDirectory(path.dirname(handoff.finalPath)));
      for (const replacement of replacements) if (replacement.temporary) {
        attempt(() => fs.rmSync(replacement.temporary, { force: true }));
      }
      if (rollbackErrors.length) {
        preserveLock = true; throw fail('collector_provisioning_rollback_failed', rollbackErrors[0]);
      }
      throw error;
    }
  } finally {
    if (lockAcquired && !preserveLock) releaseLock(lockPath);
  }
}
