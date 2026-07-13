import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

export const RECALL_CONSUMER_HANDOFF_SCHEMA = 'amf.recall-consumer-handoff/v2';
export const RECALL_CONSUMER_ACTOR = 'agent:vitae';
export const RECALL_CONSUMER_CONTEXT_KEY_VERSION = 'ctx-vitae-v1';
export const RECALL_CONSUMER_SESSION_OWNER_ACTORS = Object.freeze(['ct110-hermes-vitae']);
export const RECALL_CONSUMER_PERMISSIONS = Object.freeze([
  'memory:search',
  'memory:read',
  'sessions:read',
  'purpose:conversation_recall'
]);
export const RECALL_CONSUMER_SCOPES = Object.freeze([
  'agent:vitae',
  'person:joseph',
  'relationship:vitae:joseph',
  'room:vitae:joseph-dm'
]);
export const RECALL_CONSUMER_MAX_ADDITIONAL_SCOPES = 32;
export const DOCUMENT_CLIENT_HANDOFF_SCHEMA = 'amf.document-client-handoff/v1';
export const DOCUMENT_CLIENT_PERMISSIONS = Object.freeze([
  'documents:write',
  'documents:search',
  'documents:read',
  'memory:search',
  'purpose:operator_review'
]);
export const DOCUMENT_CLIENT_MAX_SCOPES = 32;

const HEX_DIGEST = /^[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const AUTH_MODES = new Set(['allow_all', 'scoped', 'read_only_scoped', 'deny']);
const DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY
  | fs.constants.O_NOFOLLOW;

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

function recallProfile() {
  return {
    actor: RECALL_CONSUMER_ACTOR,
    contextKeyVersion: RECALL_CONSUMER_CONTEXT_KEY_VERSION,
    permissions: RECALL_CONSUMER_PERMISSIONS,
    sessionOwnerActors: RECALL_CONSUMER_SESSION_OWNER_ACTORS,
    allowedVaults: null,
    mode: 'read_only_scoped',
    purpose: 'conversation_recall',
    handoffSchema: RECALL_CONSUMER_HANDOFF_SCHEMA,
    backupSlug: 'vitae-recall',
    policyRevision: null,
    endpoint: null
  };
}

function normalizeDocumentClientOptions({ actor, vaultId, scopes, contextKeyVersion,
  policyRevision, endpoint }) {
  if (typeof actor !== 'string' || !/^client:obsidian:[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/.test(actor)
    || typeof vaultId !== 'string' || !SAFE_ID.test(vaultId) || vaultId.includes('*')
    || typeof contextKeyVersion !== 'string' || contextKeyVersion.length > 128
    || !/^ctx-obsidian-[A-Za-z0-9][A-Za-z0-9._-]*$/.test(contextKeyVersion)
    || typeof policyRevision !== 'string' || !SAFE_ID.test(policyRevision)
    || typeof endpoint !== 'string') throw fail('document_client_option_invalid');
  let parsedEndpoint;
  try { parsedEndpoint = new URL(endpoint); } catch { throw fail('document_client_option_invalid'); }
  if (!['http:', 'https:'].includes(parsedEndpoint.protocol) || parsedEndpoint.username || parsedEndpoint.password
    || parsedEndpoint.hash || parsedEndpoint.search || parsedEndpoint.pathname !== '/') {
    throw fail('document_client_option_invalid');
  }
  if (!Array.isArray(scopes) || !scopes.length || scopes.length > DOCUMENT_CLIENT_MAX_SCOPES
    || scopes.some(scope => typeof scope !== 'string' || scope !== scope.trim() || !SAFE_ID.test(scope)
      || scope.includes('*') || !/^(?:agent|person|relationship|room|domain|shared):/.test(scope))
    || new Set(scopes).size !== scopes.length) throw fail('document_client_scope_invalid');
  const normalizedScopes = [...scopes].sort();
  return {
    actor,
    contextKeyVersion,
    permissions: DOCUMENT_CLIENT_PERMISSIONS,
    sessionOwnerActors: [],
    allowedVaults: [vaultId],
    mode: 'scoped',
    purpose: 'operator_review',
    handoffSchema: DOCUMENT_CLIENT_HANDOFF_SCHEMA,
    backupSlug: `obsidian-${crypto.createHash('sha256').update(actor).digest('hex').slice(0, 12)}`,
    policyRevision,
    endpoint: parsedEndpoint.toString(),
    scopes: normalizedScopes
  };
}

export function normalizeRecallConsumerAdditionalScopes(value = []) {
  if (!Array.isArray(value) || value.length > RECALL_CONSUMER_MAX_ADDITIONAL_SCOPES
    || value.some(scope => typeof scope !== 'string' || scope !== scope.trim()
      || !/^(?:room|person|relationship):/.test(scope) || !SAFE_ID.test(scope) || scope.includes('*'))
    || new Set(value).size !== value.length || value.some(scope => RECALL_CONSUMER_SCOPES.includes(scope))) {
    throw fail('recall_consumer_scope_invalid');
  }
  return [...value].sort();
}

function scopeSet(additionalScopes) {
  const scopes = [...RECALL_CONSUMER_SCOPES, ...normalizeRecallConsumerAdditionalScopes(additionalScopes)];
  return { scopes, scopeSetSha256: crypto.createHash('sha256').update(canonicalJson(scopes), 'utf8').digest('hex') };
}

function allowedOwner(uid, serviceOwnerUid) {
  return uid === 0 || uid === serviceOwnerUid;
}

function procChild(directory, name) {
  if (!directory || !Number.isSafeInteger(directory.fd) || path.basename(name) !== name || !name || name.includes('/')) {
    throw fail('recall_consumer_dirfd_invalid');
  }
  return `/proc/self/fd/${directory.fd}/${name}`;
}

function pinDirectory(directory, serviceOwnerUid, code, { privateFinal = false } = {}) {
  if (process.platform !== 'linux' || !Number.isInteger(fs.constants.O_DIRECTORY)
    || !Number.isInteger(fs.constants.O_NOFOLLOW) || !fs.existsSync('/proc/self/fd')) {
    throw fail('recall_consumer_dirfd_unavailable');
  }
  const resolved = path.resolve(directory); const components = resolved.split(path.sep).filter(Boolean);
  let fd;
  try {
    fd = fs.openSync(path.parse(resolved).root, DIRECTORY_FLAGS);
    for (const component of components) {
      const next = fs.openSync(`/proc/self/fd/${fd}/${component}`, DIRECTORY_FLAGS);
      fs.closeSync(fd); fd = next;
      const stat = fs.fstatSync(fd);
      if (!stat.isDirectory() || !allowedOwner(stat.uid, serviceOwnerUid)) throw fail(code);
    }
    const stat = fs.fstatSync(fd); const euid = process.geteuid?.();
    if (!stat.isDirectory() || !allowedOwner(stat.uid, serviceOwnerUid)
      || (privateFinal && (stat.mode & 0o077) !== 0)
      || (euid !== undefined && euid !== 0 && euid !== serviceOwnerUid)) throw fail(code);
    return { fd, path: resolved, stat };
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (error?.message === code || error?.message === 'recall_consumer_dirfd_unavailable') throw error;
    throw fail(code, error);
  }
}

function closeDirectory(directory) {
  if (directory?.fd !== undefined) { fs.closeSync(directory.fd); directory.fd = undefined; }
}

function assertDirectoryStable(directory) {
  let current;
  try { current = fs.lstatSync(directory.path); } catch (error) { throw fail('recall_consumer_input_changed', error); }
  if (!current.isDirectory() || current.isSymbolicLink()
    || current.dev !== directory.stat.dev || current.ino !== directory.stat.ino) {
    throw fail('recall_consumer_input_changed');
  }
}

function fsyncDirectory(directory) {
  fs.fsyncSync(directory.fd);
}

function privateFile(directory, fileName, serviceOwnerUid, code) {
  const openedPath = procChild(directory, fileName); let stat; let fd;
  try { stat = fs.lstatSync(openedPath); } catch (error) { throw fail(code, error); }
  const euid = process.geteuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0
    || !allowedOwner(stat.uid, serviceOwnerUid)
    || (euid !== undefined && euid !== 0 && euid !== serviceOwnerUid)) throw fail(code);
  try {
    // Node/libuv opens descriptors close-on-exec; O_NOFOLLOW is explicit here.
    fd = fs.openSync(openedPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== stat.dev || opened.ino !== stat.ino
      || (opened.mode & 0o077) !== 0 || !allowedOwner(opened.uid, serviceOwnerUid)) throw fail(code);
    return { path: path.join(directory.path, fileName), directory, fileName, stat: opened, bytes: fs.readFileSync(fd) };
  } catch (error) {
    if (error?.message === code) throw error;
    throw fail(code, error);
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function parseJson(record, code) {
  try { return JSON.parse(record.bytes.toString('utf8')); } catch (error) { throw fail(code, error); }
}

function parseKey(value, code = 'recall_consumer_context_key_invalid') {
  const raw = String(value || '');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw fail(code);
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw fail(code);
  return decoded;
}

function normalizedList(value, { wildcard = false } = {}) {
  if (wildcard && value === '*') return ['*'];
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : null;
  if (!values) throw fail('recall_consumer_auth_registry_invalid');
  if (values.some(item => typeof item !== 'string')) throw fail('recall_consumer_auth_registry_invalid');
  const output = values.map(item => item.trim()).filter(Boolean);
  if (!output.length || output.some(item => !(wildcard && item === '*') && !SAFE_ID.test(item))
    || new Set(output).size !== output.length) {
    throw fail('recall_consumer_auth_registry_invalid');
  }
  return output;
}

function optionalList(row, field) {
  if (!Object.hasOwn(row, field)) return [];
  if (!Array.isArray(row[field])) throw fail('recall_consumer_auth_registry_invalid');
  return normalizedList(row[field]);
}

function authRows(registry) {
  if (Array.isArray(registry)) return { rows: registry, wrapper: 'array' };
  if (exactKeys(registry, ['rows']) && Array.isArray(registry.rows)) return { rows: registry.rows, wrapper: 'rows' };
  if (exactKeys(registry, ['data']) && Array.isArray(registry.data)) return { rows: registry.data, wrapper: 'data' };
  throw fail('recall_consumer_auth_registry_invalid');
}

function validateAuthRegistry(registry) {
  const extracted = authRows(registry); const actors = new Set(); const digests = new Set();
  const contextVersionOwners = new Map();
  for (const row of extracted.rows) {
    if (!object(row) || Object.hasOwn(row, 'token') || typeof row.actor !== 'string' || !SAFE_ID.test(row.actor)
      || typeof row.active !== 'boolean' || typeof row.mode !== 'string' || !AUTH_MODES.has(row.mode)
      || typeof row.tokenSha256 !== 'string' || !HEX_DIGEST.test(row.tokenSha256)) {
      throw fail('recall_consumer_auth_registry_invalid');
    }
    normalizedList(row.allowedScopes, { wildcard: true }); normalizedList(row.permissions, { wildcard: true });
    optionalList(row, 'sessionOwnerActors'); optionalList(row, 'contextKeyVersions'); optionalList(row, 'allowedVaults');
    for (const version of optionalList(row, 'contextKeyVersions')) {
      const existing = contextVersionOwners.get(version);
      if (existing && existing !== row.actor) throw fail('recall_consumer_auth_registry_invalid');
      contextVersionOwners.set(version, row.actor);
    }
    if (actors.has(row.actor) || digests.has(row.tokenSha256)) throw fail('recall_consumer_auth_registry_invalid');
    actors.add(row.actor); digests.add(row.tokenSha256);
  }
  const byActor = new Map(extracted.rows.map(row => [row.actor, row]));
  for (const row of extracted.rows) {
    for (const owner of optionalList(row, 'sessionOwnerActors')) {
      const target = byActor.get(owner);
      const targetPermissions = target ? normalizedList(target.permissions, { wildcard: true }) : [];
      if (owner === row.actor || !target?.active
        || !targetPermissions.some(permission => permission === '*' || permission === 'raw:ingest')
        || optionalList(target, 'sessionOwnerActors').length > 0) {
        throw fail('recall_consumer_auth_registry_invalid');
      }
    }
  }
  return extracted;
}

function withAuthRows(registry, wrapper, rows) {
  if (wrapper === 'array') return rows;
  return { ...registry, [wrapper]: rows };
}

function validatePolicy(policy) {
  if (!exactKeys(policy, ['actors', 'scopes']) || !object(policy.actors) || !object(policy.scopes)) {
    throw fail('recall_consumer_policy_invalid');
  }
  const contextVersionOwners = new Map();
  for (const [actor, entry] of Object.entries(policy.actors)) {
    if (!SAFE_ID.test(actor) || !object(entry) || typeof entry.mode !== 'string' || !AUTH_MODES.has(entry.mode)) {
      throw fail('recall_consumer_policy_invalid');
    }
    if (entry.allowedScopes !== undefined) normalizedList(entry.allowedScopes, { wildcard: true });
    if (entry.sessionOwnerActors !== undefined) {
      if (!Array.isArray(entry.sessionOwnerActors)) throw fail('recall_consumer_policy_invalid');
      normalizedList(entry.sessionOwnerActors);
    }
    if (entry.contextKeyVersions !== undefined) {
      if (!Array.isArray(entry.contextKeyVersions)) throw fail('recall_consumer_policy_invalid');
      for (const version of normalizedList(entry.contextKeyVersions)) {
        const existing = contextVersionOwners.get(version);
        if (existing && existing !== actor) throw fail('recall_consumer_policy_invalid');
        contextVersionOwners.set(version, actor);
      }
    }
  }
  for (const [scope, entry] of Object.entries(policy.scopes)) {
    if (!SAFE_ID.test(scope) || !object(entry) || typeof entry.backendUserId !== 'string' || !entry.backendUserId) {
      throw fail('recall_consumer_policy_invalid');
    }
  }
  return policy;
}

function validateContextRing(ring) {
  if (!exactKeys(ring, ['currentKeyVersion', 'keys']) || !object(ring.keys)
    || !SAFE_ID.test(String(ring.currentKeyVersion || '')) || !Object.hasOwn(ring.keys, ring.currentKeyVersion)) {
    throw fail('recall_consumer_context_key_ring_invalid');
  }
  const materials = new Set();
  for (const [version, key] of Object.entries(ring.keys)) {
    if (!SAFE_ID.test(version)) throw fail('recall_consumer_context_key_ring_invalid');
    const encoded = parseKey(key).toString('hex');
    if (materials.has(encoded)) throw fail('recall_consumer_context_key_reuse_detected');
    materials.add(encoded);
  }
  return { ring, materials };
}

function validateContextActorBindings(extracted, policy, contextRing) {
  const registryBindings = new Map();
  for (const row of extracted.rows) {
    for (const version of optionalList(row, 'contextKeyVersions')) registryBindings.set(version, row.actor);
  }
  const policyBindings = new Map();
  for (const [actor, entry] of Object.entries(policy.actors)) {
    for (const version of entry.contextKeyVersions === undefined ? [] : normalizedList(entry.contextKeyVersions)) {
      policyBindings.set(version, actor);
    }
  }
  const sortedBindings = bindings => [...bindings].sort(([leftVersion, leftActor], [rightVersion, rightActor]) =>
    leftVersion.localeCompare(rightVersion) || leftActor.localeCompare(rightActor));
  if (canonicalJson(sortedBindings(registryBindings)) !== canonicalJson(sortedBindings(policyBindings))) {
    throw fail('recall_consumer_context_actor_binding_invalid');
  }
  for (const version of registryBindings.keys()) {
    if (!Object.hasOwn(contextRing.keys, version)) throw fail('recall_consumer_context_actor_binding_invalid');
  }
}

function exactConsumerRow(row, scopes, profile) {
  try {
    const keys = ['tokenSha256', 'active', 'actor', 'mode', 'allowedScopes', 'permissions', 'contextKeyVersions'];
    if (profile.sessionOwnerActors.length) keys.push('sessionOwnerActors');
    if (profile.allowedVaults) keys.push('allowedVaults');
    return exactKeys(row, keys)
      && row.active === true && row.actor === profile.actor && row.mode === profile.mode
      && canonicalJson(normalizedList(row.allowedScopes)) === canonicalJson(scopes)
      && canonicalJson(normalizedList(row.permissions)) === canonicalJson(profile.permissions)
      && (!profile.sessionOwnerActors.length || canonicalJson(normalizedList(row.sessionOwnerActors))
        === canonicalJson(profile.sessionOwnerActors))
      && (!profile.allowedVaults || canonicalJson(normalizedList(row.allowedVaults))
        === canonicalJson(profile.allowedVaults))
      && canonicalJson(normalizedList(row.contextKeyVersions)) === canonicalJson([profile.contextKeyVersion])
      && typeof row.tokenSha256 === 'string' && HEX_DIGEST.test(row.tokenSha256) && !Object.hasOwn(row, 'token');
  } catch { return false; }
}

function exactPolicyActor(entry, scopes, profile) {
  try {
    const keys = ['mode', 'allowedScopes', 'contextKeyVersions'];
    if (profile.sessionOwnerActors.length) keys.push('sessionOwnerActors');
    return exactKeys(entry, keys)
      && entry.mode === profile.mode
      && canonicalJson(normalizedList(entry.allowedScopes)) === canonicalJson(scopes)
      && (!profile.sessionOwnerActors.length || canonicalJson(normalizedList(entry.sessionOwnerActors))
        === canonicalJson(profile.sessionOwnerActors))
      && canonicalJson(normalizedList(entry.contextKeyVersions)) === canonicalJson([profile.contextKeyVersion]);
  } catch { return false; }
}

function requireAbsent(directory, fileName, parentCode, existsCode) {
  try { fs.lstatSync(procChild(directory, fileName)); throw fail(existsCode); }
  catch (error) {
    if (error?.message === existsCode) throw error;
    if (error?.code !== 'ENOENT') throw fail(parentCode, error);
  }
  return path.join(directory.path, fileName);
}

function openChildDirectory(parent, name, serviceOwnerUid, code) {
  let fd;
  try {
    fd = fs.openSync(procChild(parent, name), DIRECTORY_FLAGS);
    const stat = fs.fstatSync(fd);
    if (!stat.isDirectory() || !allowedOwner(stat.uid, serviceOwnerUid) || (stat.mode & 0o077) !== 0) throw fail(code);
    return { fd, path: path.join(parent.path, name), stat };
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (error?.message === code) throw error;
    throw fail(code, error);
  }
}

function ensureDirectory(parent, name, serviceOwnerUid, code) {
  fs.mkdirSync(procChild(parent, name), { recursive: false, mode: 0o700 });
  const directory = openChildDirectory(parent, name, serviceOwnerUid, code);
  fs.fchmodSync(directory.fd, 0o700); directory.stat = fs.fstatSync(directory.fd); fsyncDirectory(parent);
  return directory;
}

function writeExclusive(directory, fileName, bytes) {
  const filePath = procChild(directory, fileName); const fd = fs.openSync(filePath, 'wx', 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fchmodSync(fd, 0o600); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function writeReplacement(record, bytes) {
  const name = `.${record.fileName}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const temporaryPath = procChild(record.directory, name);
  let fd;
  try {
    fd = fs.openSync(temporaryPath, 'wx', 0o600); fs.writeFileSync(fd, bytes);
    fs.fchmodSync(fd, 0o600); fs.fsyncSync(fd);
    const stat = fs.fstatSync(fd); return { name, fd, stat };
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temporaryPath, { force: true }); throw error;
  }
}

function assertPrepared(record, prepared) {
  const current = fs.lstatSync(procChild(record.directory, prepared.name));
  const opened = fs.fstatSync(prepared.fd);
  if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1
    || current.dev !== prepared.stat.dev || current.ino !== prepared.stat.ino
    || opened.dev !== prepared.stat.dev || opened.ino !== prepared.stat.ino || opened.nlink !== 1) {
    throw fail('recall_consumer_input_changed');
  }
}

function finishReplacement(record, prepared) {
  if (process.geteuid?.() === 0) fs.fchownSync(prepared.fd, record.stat.uid, record.stat.gid);
  fs.fchmodSync(prepared.fd, record.stat.mode & 0o777); fs.fsyncSync(prepared.fd);
  fs.closeSync(prepared.fd); prepared.fd = undefined;
}

function discardReplacement(record, prepared) {
  if (prepared?.fd !== undefined) { fs.closeSync(prepared.fd); prepared.fd = undefined; }
  if (prepared?.name) fs.rmSync(procChild(record.directory, prepared.name), { force: true });
}

function assertUnchanged(record, serviceOwnerUid) {
  const current = privateFile(record.directory, record.fileName, serviceOwnerUid, 'recall_consumer_input_changed');
  if (current.stat.dev !== record.stat.dev || current.stat.ino !== record.stat.ino
    || Buffer.compare(current.bytes, record.bytes) !== 0) throw fail('recall_consumer_input_changed');
}

function restoreRecord(record) {
  const prepared = writeReplacement(record, record.bytes);
  try {
    assertPrepared(record, prepared);
    fs.renameSync(procChild(record.directory, prepared.name), procChild(record.directory, record.fileName));
    prepared.name = null; finishReplacement(record, prepared); fsyncDirectory(record.directory);
  } catch (error) { discardReplacement(record, prepared); throw error; }
}

function acquireLock(directory, lockName, clock, profile) {
  let fd;
  try {
    fd = fs.openSync(procChild(directory, lockName), 'wx', 0o600);
    fs.writeFileSync(fd, canonicalBytes({ schema: 'amf.scoped-client-provision-lock/v1', pid: process.pid,
      actor: profile.actor, createdAt: clock().toISOString() }));
    fs.fsyncSync(fd); const stat = fs.fstatSync(fd); fsyncDirectory(directory);
    return { fd, stat };
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if (error?.code === 'EEXIST') throw fail('recall_consumer_provisioning_locked');
    throw fail('recall_consumer_provisioning_lock_failed', error);
  }
}

function assertLockHeld(directory, lockName, lock) {
  let current;
  try { current = fs.lstatSync(procChild(directory, lockName)); }
  catch (error) { throw fail('recall_consumer_provisioning_locked', error); }
  if (!current.isFile() || current.isSymbolicLink() || current.dev !== lock.stat.dev || current.ino !== lock.stat.ino) {
    throw fail('recall_consumer_provisioning_locked');
  }
}

function releaseLock(directory, lockName, lock) {
  assertLockHeld(directory, lockName, lock);
  fs.rmSync(procChild(directory, lockName), { force: true }); fsyncDirectory(directory);
  fs.closeSync(lock.fd); lock.fd = undefined;
}

function safeTimestamp(date) {
  return date.toISOString().replace(/[-:.]/g, '').replace('Z', 'Z');
}

function backupInputs(records, backupRoot, serviceOwnerUid, clock, profile) {
  const backupName = `${safeTimestamp(clock())}-${profile.backupSlug}-${crypto.randomUUID().slice(0, 8)}`;
  const backupDirectory = ensureDirectory(backupRoot, backupName, serviceOwnerUid, 'recall_consumer_backup_root_unsafe');
  try {
    for (const [name, record] of Object.entries(records)) writeExclusive(backupDirectory, `${name}.json`, record.bytes);
    fsyncDirectory(backupDirectory); return backupDirectory.path;
  } finally { closeDirectory(backupDirectory); }
}

function stageHandoff({ handoffParent, handoffName, serviceOwnerUid, bearer, contextKey, scopes,
  scopeSetSha256, clock, profile }) {
  const finalPath = requireAbsent(handoffParent, handoffName,
    'recall_consumer_handoff_parent_unsafe', 'recall_consumer_handoff_exists');
  const stagingName = `${handoffName}.tmp-${process.pid}-${crypto.randomUUID()}`;
  const staging = ensureDirectory(handoffParent, stagingName, serviceOwnerUid, 'recall_consumer_handoff_parent_unsafe');
  const contextRing = { currentKeyVersion: profile.contextKeyVersion,
    keys: { [profile.contextKeyVersion]: contextKey } };
  const manifest = { schema: profile.handoffSchema, actor: profile.actor,
    contextKeyVersion: profile.contextKeyVersion, permissions: profile.permissions,
    scopes, scopeSetSha256, purpose: profile.purpose, createdAt: clock().toISOString() };
  if (profile.sessionOwnerActors.length) manifest.sessionOwnerActors = profile.sessionOwnerActors;
  if (profile.allowedVaults) manifest.allowedVaults = profile.allowedVaults;
  if (profile.policyRevision) manifest.policyRevision = profile.policyRevision;
  if (profile.endpoint) manifest.endpoint = profile.endpoint;
  const files = {
    'bearer.token': Buffer.from(`${bearer}\n`, 'utf8'),
    'context-key-ring.json': canonicalBytes(contextRing),
    'manifest.json': canonicalBytes(manifest)
  };
  try {
    for (const [name, bytes] of Object.entries(files)) writeExclusive(staging, name, bytes);
    fsyncDirectory(staging); closeDirectory(staging);
    return { parent: handoffParent, stagingName, finalName: handoffName, finalPath };
  } catch (error) {
    closeDirectory(staging); fs.rmSync(procChild(handoffParent, stagingName), { recursive: true, force: true }); throw error;
  }
}

function freshSecrets(randomBytes, tokenDigests, contextMaterials) {
  let bearer = null; let tokenSha256 = null; let contextKey = null;
  for (let attempt = 0; attempt < 32 && (!bearer || !contextKey); attempt += 1) {
    const bytes = Buffer.from(randomBytes(32));
    if (bytes.length !== 32) throw fail('recall_consumer_random_source_invalid');
    const material = bytes.toString('hex');
    if (!bearer) {
      const candidate = bytes.toString('base64url');
      const digest = crypto.createHash('sha256').update(candidate, 'utf8').digest('hex');
      if (!tokenDigests.has(digest) && !contextMaterials.has(material)) {
        bearer = candidate; tokenSha256 = digest; tokenDigests.add(digest); contextMaterials.add(material); continue;
      }
    }
    if (!contextKey && !contextMaterials.has(material)) {
      contextKey = bytes.toString('base64'); contextMaterials.add(material);
    }
  }
  if (!bearer || !contextKey) throw fail('recall_consumer_random_source_exhausted');
  return { bearer, tokenSha256, contextKey };
}

function invokeFault(faultAt, point) {
  if (faultAt === point || (Array.isArray(faultAt) && faultAt.includes(point))) {
    throw fail(`recall_consumer_test_fault_${point}`);
  }
}

function provisionScopedConsumer({ authRegistryPath, policyPath, contextKeyRingPath, handoffPath,
  backupRoot, backendUserId, serviceOwnerUid, dryRun = false, clock = () => new Date(),
  randomBytes = crypto.randomBytes, faultAt = null } = {}, profile) {
  if (![authRegistryPath, policyPath, contextKeyRingPath, handoffPath, backupRoot]
    .every(value => typeof value === 'string' && path.isAbsolute(value))) throw fail('recall_consumer_path_invalid');
  if (typeof backendUserId !== 'string' || !SAFE_ID.test(backendUserId) || !Number.isSafeInteger(serviceOwnerUid)
    || serviceOwnerUid < 0 || typeof dryRun !== 'boolean') throw fail('recall_consumer_option_invalid');
  const scopes = profile.scopes;
  const scopeSetSha256 = crypto.createHash('sha256').update(canonicalJson(scopes), 'utf8').digest('hex');
  if (!dryRun && process.geteuid?.() !== 0) throw fail('recall_consumer_root_required');

  const resolved = {
    auth: path.resolve(authRegistryPath), policy: path.resolve(policyPath), context: path.resolve(contextKeyRingPath),
    handoff: path.resolve(handoffPath), backupRoot: path.resolve(backupRoot)
  };
  const directories = [];
  const pin = (directory, code, options) => {
    try {
      const pinned = pinDirectory(directory, serviceOwnerUid, code, options); directories.push(pinned); return pinned;
    } catch (error) {
      for (const opened of directories.reverse()) closeDirectory(opened);
      throw error;
    }
  };
  const authParent = pin(path.dirname(resolved.auth), 'recall_consumer_lock_directory_unsafe');
  const policyParent = pin(path.dirname(resolved.policy), 'recall_consumer_policy_file_unsafe');
  const contextParent = pin(path.dirname(resolved.context), 'recall_consumer_context_key_ring_file_unsafe');
  const backupDirectory = pin(resolved.backupRoot, 'recall_consumer_backup_root_unsafe', { privateFinal: true });
  const handoffParent = pin(path.dirname(resolved.handoff), 'recall_consumer_handoff_parent_unsafe', { privateFinal: true });
  const lockName = `${path.basename(resolved.auth)}.recall-consumer-provision.lock`;
  const handoffName = path.basename(resolved.handoff);
  let lock = null; let preserveLock = false;
  try {
    requireAbsent(authParent, lockName, 'recall_consumer_lock_directory_unsafe', 'recall_consumer_provisioning_locked');
    requireAbsent(handoffParent, handoffName, 'recall_consumer_handoff_parent_unsafe', 'recall_consumer_handoff_exists');
    if (!dryRun) lock = acquireLock(authParent, lockName, clock, profile);
    const records = {
      'auth-registry': privateFile(authParent, path.basename(resolved.auth), serviceOwnerUid,
        'recall_consumer_auth_registry_file_unsafe'),
      policy: privateFile(policyParent, path.basename(resolved.policy), serviceOwnerUid,
        'recall_consumer_policy_file_unsafe'),
      'context-key-ring': privateFile(contextParent, path.basename(resolved.context), serviceOwnerUid,
        'recall_consumer_context_key_ring_file_unsafe')
    };
    for (const [label, record] of Object.entries(records)) record.label = label;
    if (new Set(Object.values(records).map(record => `${record.stat.dev}:${record.stat.ino}`)).size !== 3) {
      throw fail('recall_consumer_input_paths_conflict');
    }
    const registry = parseJson(records['auth-registry'], 'recall_consumer_auth_registry_invalid');
    const extracted = validateAuthRegistry(registry);
    const policy = validatePolicy(parseJson(records.policy, 'recall_consumer_policy_invalid'));
    const { ring: contextRing, materials } = validateContextRing(parseJson(records['context-key-ring'],
      'recall_consumer_context_key_ring_invalid'));
    validateContextActorBindings(extracted, policy, contextRing);
    const actorRow = extracted.rows.find(row => row.actor === profile.actor) || null;
    const policyActor = policy.actors[profile.actor] || null;
    const scopeEntries = scopes.map(scope => policy.scopes[scope] || null);
    const hasContextKey = Object.hasOwn(contextRing.keys, profile.contextKeyVersion);
    if (actorRow || policyActor || hasContextKey) {
      const scopesExact = scopeEntries.every(entry => object(entry));
      if (exactConsumerRow(actorRow, scopes, profile) && exactPolicyActor(policyActor, scopes, profile)
        && scopesExact && hasContextKey) {
        throw fail('recall_consumer_already_provisioned');
      }
      throw fail('recall_consumer_provisioning_conflict');
    }

    const safeResult = { ok: true, schema: profile.handoffSchema, action: 'provision', dryRun,
      actor: profile.actor, contextKeyVersion: profile.contextKeyVersion,
      permissions: profile.permissions, scopes, scopeSetSha256,
      handoffPath: resolved.handoff, backupPath: null };
    if (profile.sessionOwnerActors.length) safeResult.sessionOwnerActors = profile.sessionOwnerActors;
    if (profile.allowedVaults) safeResult.allowedVaults = profile.allowedVaults;
    if (dryRun) return safeResult;

    const tokenDigests = new Set(extracted.rows.map(row => row.tokenSha256));
    const { bearer, tokenSha256, contextKey } = freshSecrets(randomBytes, tokenDigests, materials);
    const newRow = { tokenSha256, active: true, actor: profile.actor, mode: profile.mode,
      allowedScopes: scopes, permissions: profile.permissions,
      contextKeyVersions: [profile.contextKeyVersion] };
    if (profile.sessionOwnerActors.length) newRow.sessionOwnerActors = profile.sessionOwnerActors;
    if (profile.allowedVaults) newRow.allowedVaults = profile.allowedVaults;
    const nextRegistry = withAuthRows(registry, extracted.wrapper, [...extracted.rows, newRow]);
    const newScopes = Object.fromEntries(scopes
      .map(scope => [scope, policy.scopes[scope] || { backendUserId }]));
    const nextPolicy = { ...policy,
      actors: { ...policy.actors, [profile.actor]: { mode: profile.mode,
        allowedScopes: scopes, contextKeyVersions: [profile.contextKeyVersion] } },
      scopes: { ...policy.scopes, ...newScopes } };
    if (profile.sessionOwnerActors.length) {
      nextPolicy.actors[profile.actor].sessionOwnerActors = profile.sessionOwnerActors;
    }
    const nextContextRing = { ...contextRing, keys: { ...contextRing.keys,
      [profile.contextKeyVersion]: contextKey } };
    const nextExtracted = validateAuthRegistry(nextRegistry); const validatedNextPolicy = validatePolicy(nextPolicy);
    const { ring: validatedNextRing } = validateContextRing(nextContextRing);
    validateContextActorBindings(nextExtracted, validatedNextPolicy, validatedNextRing);

    assertLockHeld(authParent, lockName, lock);
    for (const directory of directories) assertDirectoryStable(directory);
    for (const record of Object.values(records)) assertUnchanged(record, serviceOwnerUid);
    const backupPath = backupInputs(records, backupDirectory, serviceOwnerUid, clock, profile);
    const handoff = stageHandoff({ handoffParent, handoffName, serviceOwnerUid, bearer, contextKey,
      scopes, scopeSetSha256, clock, profile });
    const specs = [
      [records['context-key-ring'], canonicalBytes(nextContextRing), 'after-context-key-ring'],
      [records.policy, canonicalBytes(nextPolicy), 'after-policy'],
      [records['auth-registry'], canonicalBytes(nextRegistry), 'after-auth-registry']
    ];
    const replacements = []; const replaced = []; let handoffCommitted = false;
    try {
      for (const [record, bytes, point] of specs) replacements.push({ record,
        prepared: writeReplacement(record, bytes), point });
      for (const replacement of replacements) {
        assertLockHeld(authParent, lockName, lock);
        assertDirectoryStable(replacement.record.directory);
        assertUnchanged(replacement.record, serviceOwnerUid);
        assertPrepared(replacement.record, replacement.prepared);
        fs.renameSync(procChild(replacement.record.directory, replacement.prepared.name),
          procChild(replacement.record.directory, replacement.record.fileName)); replacement.prepared.name = null;
        replaced.push(replacement.record); finishReplacement(replacement.record, replacement.prepared);
        invokeFault(faultAt, `${replacement.point}-before-fsync`);
        fsyncDirectory(replacement.record.directory); invokeFault(faultAt, replacement.point);
      }
      assertLockHeld(authParent, lockName, lock);
      assertDirectoryStable(handoff.parent);
      fs.renameSync(procChild(handoff.parent, handoff.stagingName), procChild(handoff.parent, handoff.finalName));
      handoffCommitted = true;
      invokeFault(faultAt, 'after-handoff-before-fsync'); fsyncDirectory(handoff.parent);
      invokeFault(faultAt, 'after-handoff');
      assertLockHeld(authParent, lockName, lock);
      for (const directory of directories) assertDirectoryStable(directory);
      return { ...safeResult, backupPath };
    } catch (error) {
      const rollbackErrors = [];
      const attempt = operation => { try { operation(); } catch (cause) { rollbackErrors.push(cause); } };
      attempt(() => fs.rmSync(procChild(handoff.parent, handoffCommitted ? handoff.finalName : handoff.stagingName),
        { recursive: true, force: true }));
      for (const record of [...replaced].reverse()) attempt(() => {
        invokeFault(faultAt, `rollback-${record.label}`); restoreRecord(record);
      });
      attempt(() => fsyncDirectory(handoff.parent));
      for (const replacement of replacements) attempt(() => discardReplacement(replacement.record, replacement.prepared));
      if (rollbackErrors.length) { preserveLock = true; throw fail('recall_consumer_provisioning_rollback_failed', rollbackErrors[0]); }
      throw error;
    }
  } finally {
    try {
      if (lock && !preserveLock) releaseLock(authParent, lockName, lock);
      else if (lock?.fd !== undefined) { fs.closeSync(lock.fd); lock.fd = undefined; }
    }
    finally { for (const directory of directories.reverse()) closeDirectory(directory); }
  }
}

export function provisionRecallConsumer(options = {}) {
  const { scopes } = scopeSet(options.additionalScopes || []);
  return provisionScopedConsumer(options, { ...recallProfile(), scopes });
}

export function provisionDocumentClient(options = {}) {
  const profile = normalizeDocumentClientOptions(options);
  return provisionScopedConsumer(options, profile);
}
