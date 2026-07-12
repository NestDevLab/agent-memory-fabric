import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import pg from 'pg';
import { ciphertextContentId, ciphertextPayloadDigest, decryptClientCiphertext, normalizeIngestKeyRing, validateClientCiphertext } from './ingest/raw-event-contract.mjs';

const { Pool } = pg;

const RAW_FORMAT_VERSION = 2;
const HKDF_SALT = Buffer.from('agent-memory-fabric/raw/v2', 'utf8');
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function createError(message, status, data) {
  const error = new Error(message);
  error.status = status;
  error.data = data;
  return error;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const DIRECTORY_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0);
const READ_NOFOLLOW_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);

function procFdChild(directoryFd, name) {
  if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\0')) throw createError('raw_object_unsafe', 500);
  return `/proc/self/fd/${directoryFd}/${name}`;
}

function mapSecurePathError(error) {
  if (['ELOOP', 'ENOTDIR', 'EINVAL'].includes(error?.code)) throw createError('raw_object_unsafe', 500);
  throw error;
}

function openSecureDirectoryComponent(parentFd, name, { create = false } = {}) {
  const target = procFdChild(parentFd, name);
  if (create) {
    try { fs.mkdirSync(target, { mode: 0o700 }); }
    catch (error) { if (error?.code !== 'EEXIST') mapSecurePathError(error); }
  }
  try {
    const fd = fs.openSync(target, DIRECTORY_FLAGS);
    if (!fs.fstatSync(fd).isDirectory()) { fs.closeSync(fd); throw createError('raw_object_unsafe', 500); }
    return fd;
  } catch (error) { mapSecurePathError(error); }
}

function openSecureAbsoluteDirectory(directory, { create = false } = {}) {
  const resolved = path.resolve(directory);
  let current;
  try { current = fs.openSync('/', DIRECTORY_FLAGS); }
  catch { throw createError('raw_store_procfd_unavailable', 500); }
  try {
    for (const component of resolved.split(path.sep).filter(Boolean)) {
      const next = openSecureDirectoryComponent(current, component, { create });
      fs.closeSync(current);
      current = next;
    }
    return current;
  } catch (error) {
    fs.closeSync(current);
    throw error;
  }
}

function openSecureSubdirectory(rootFd, components, { create = false } = {}) {
  let current = rootFd;
  let owned = false;
  try {
    for (const component of components) {
      const next = openSecureDirectoryComponent(current, component, { create });
      if (owned) fs.closeSync(current);
      current = next;
      owned = true;
    }
    if (!owned) throw createError('raw_object_unsafe', 500);
    return current;
  } catch (error) {
    if (owned) fs.closeSync(current);
    throw error;
  }
}

function secureWriteExclusive(directoryFd, filename, bytes) {
  const target = procFdChild(directoryFd, filename);
  const temporaryName = `.${filename}.${process.pid}.${crypto.randomUUID()}.tmp`;
  const temporary = procFdChild(directoryFd, temporaryName);
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    fs.linkSync(temporary, target);
    fs.fsyncSync(directoryFd);
    return true;
  } catch (error) {
    if (error?.code === 'EEXIST') return false;
    mapSecurePathError(error);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}

function secureReadFile(directoryFd, filename) {
  let fd;
  try {
    fd = fs.openSync(procFdChild(directoryFd, filename), READ_NOFOLLOW_FLAGS);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw createError('raw_object_unsafe', 500);
    return fs.readFileSync(fd, 'utf8');
  } catch (error) { mapSecurePathError(error); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

function secureRemoveFile(directoryFd, filename) {
  try { fs.unlinkSync(procFdChild(directoryFd, filename)); fs.fsyncSync(directoryFd); }
  catch (error) { if (error?.code !== 'ENOENT') mapSecurePathError(error); }
}

function parseMasterKey(value) {
  const original = String(value || '');
  const raw = original.trim();
  if (original !== raw) throw createError('raw_encryption_key_invalid', 500);
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw createError('raw_encryption_key_invalid', 500);
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw createError('raw_encryption_key_invalid', 500);
  return decoded;
}

function deriveKey(master, purpose) {
  return Buffer.from(crypto.hkdfSync('sha256', master, HKDF_SALT, Buffer.from(purpose, 'utf8'), 32));
}

function validateKeyId(value) {
  const id = String(value);
  if (!SAFE_KEY_ID.test(id)) throw createError('raw_key_id_invalid', 500, { keyId: id });
  return id;
}

function buildKeyRing({ encryptionKey, keyId = 'default', keyRing } = {}) {
  if (keyRing?.currentKeyId && keyRing?.keys) {
    const currentKeyId = validateKeyId(keyRing.currentKeyId);
    const keys = new Map(Object.entries(keyRing.keys).map(([id, value]) => [validateKeyId(id), parseMasterKey(value)]));
    if (!keys.has(currentKeyId)) throw createError('raw_current_key_missing', 500);
    return { currentKeyId, keys };
  }
  if (!encryptionKey) throw createError('raw_encryption_key_required', 500);
  const currentKeyId = validateKeyId(keyId);
  return { currentKeyId, keys: new Map([[currentKeyId, parseMasterKey(encryptionKey)]]) };
}

function keyMaterial(keyRing, keyId) {
  const master = keyRing.keys.get(String(keyId));
  if (!master) throw createError('raw_key_unavailable', 500, { keyId: String(keyId) });
  return {
    encryption: deriveKey(master, 'encryption'),
    addressing: deriveKey(master, 'content-address'),
    catalog: deriveKey(master, 'catalog-tags')
  };
}

function contentAddress(plaintext, material) {
  return crypto.createHmac('sha256', material.addressing).update(plaintext).digest('hex');
}

function aadFor({ version, contentId, keyId }) {
  return Buffer.from(canonicalJson({ version, contentId, keyId }), 'utf8');
}

function preparePayload(payload, keyRing) {
  const keyId = keyRing.currentKeyId;
  const material = keyMaterial(keyRing, keyId);
  const plaintext = Buffer.from(canonicalJson(payload), 'utf8');
  const contentId = contentAddress(plaintext, material);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', material.encryption, iv);
  cipher.setAAD(aadFor({ version: RAW_FORMAT_VERSION, contentId, keyId }));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    contentId,
    plaintextBytes: plaintext.length,
    envelope: {
      version: RAW_FORMAT_VERSION,
      algorithm: 'aes-256-gcm',
      contentId,
      keyId,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64')
    }
  };
}

function decryptPayload(envelope, requestedContentId, keyRing) {
  if (envelope?.version !== RAW_FORMAT_VERSION || envelope?.algorithm !== 'aes-256-gcm') {
    throw createError('raw_envelope_unsupported', 500);
  }
  if (envelope.contentId !== requestedContentId) throw createError('raw_content_id_mismatch', 500);
  const material = keyMaterial(keyRing, envelope.keyId);
  const decipher = crypto.createDecipheriv('aes-256-gcm', material.encryption, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(aadFor({ version: envelope.version, contentId: envelope.contentId, keyId: envelope.keyId }));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  } catch {
    throw createError('raw_authentication_failed', 500);
  }
  if (contentAddress(plaintext, material) !== requestedContentId) throw createError('raw_content_verification_failed', 500);
  return JSON.parse(plaintext.toString('utf8'));
}

class RawStoreBase {
  constructor(options) {
    this.keyRing = buildKeyRing(options);
  }

  prepare(payload) {
    return preparePayload(payload, this.keyRing);
  }

  opaqueTag(purpose, value, keyId = this.keyRing.currentKeyId) {
    const material = keyMaterial(this.keyRing, keyId);
    const digest = crypto.createHmac('sha256', material.catalog).update(`${purpose}\u0000${String(value)}`).digest('hex');
    return `${keyId}:${digest}`;
  }

  opaqueTags(purpose, value) {
    return [...this.keyRing.keys.keys()].map(keyId => this.opaqueTag(purpose, value, keyId));
  }
}

export class MemoryRawStore extends RawStoreBase {
  constructor({ encryptionKey = crypto.randomBytes(32).toString('base64'), keyId = 'test', keyRing } = {}) {
    super({ encryptionKey, keyId, keyRing });
    this.blobs = new Map();
    this.clientBlobs = new Map();
  }

  async commit(prepared) {
    const created = !this.blobs.has(prepared.contentId);
    if (created) this.blobs.set(prepared.contentId, prepared.envelope);
    return { contentId: prepared.contentId, storageRef: `memory://${prepared.contentId}`, byteLength: prepared.plaintextBytes, created };
  }

  async put(payload) { return this.commit(this.prepare(payload)); }

  async get(contentId) {
    const envelope = this.blobs.get(contentId);
    if (!envelope) throw createError('raw_object_not_found', 404);
    return decryptPayload(envelope, contentId, this.keyRing);
  }

  async remove(contentId) { this.blobs.delete(contentId); }
  getEncryptedEnvelope(contentId) { return this.blobs.get(contentId) || null; }
  async commitClientCiphertext(contentId, envelope) {
    const created = !this.clientBlobs.has(contentId);
    if (created) this.clientBlobs.set(contentId, structuredClone(envelope));
    return { contentId, storageRef: `memory-client://${contentId}`, byteLength: Buffer.byteLength(JSON.stringify(envelope)), created };
  }
  async getClientCiphertext(contentId) {
    const envelope = this.clientBlobs.get(contentId);
    if (!envelope) throw createError('raw_object_not_found', 404);
    return structuredClone(envelope);
  }
}

export class FileRawStore extends RawStoreBase {
  constructor({ rootPath, encryptionKey, keyId = 'default', keyRing }) {
    super({ encryptionKey, keyId, keyRing });
    this.rootPath = path.resolve(rootPath);
    const rootFd = openSecureAbsoluteDirectory(this.rootPath, { create: true });
    try { fs.fchmodSync(rootFd, 0o700); fs.fsyncSync(rootFd); } finally { fs.closeSync(rootFd); }
  }

  blobPath(contentId) {
    if (!/^[a-f0-9]{64}$/.test(contentId)) throw createError('raw_content_id_invalid', 400);
    return path.join(this.rootPath, contentId.slice(0, 2), contentId.slice(2, 4), `${contentId}.enc.json`);
  }

  async commit(prepared) {
    this.blobPath(prepared.contentId);
    const components = [prepared.contentId.slice(0, 2), prepared.contentId.slice(2, 4)];
    const filename = `${prepared.contentId}.enc.json`;
    const rootFd = openSecureAbsoluteDirectory(this.rootPath);
    let directoryFd;
    try {
      directoryFd = openSecureSubdirectory(rootFd, components, { create: true });
      const serialized = JSON.stringify(prepared.envelope);
      const created = secureWriteExclusive(directoryFd, filename, Buffer.from(serialized, 'utf8'));
      if (!created) {
        const existing = JSON.parse(secureReadFile(directoryFd, filename));
        const existingPayload = decryptPayload(existing, prepared.contentId, this.keyRing);
        const proposedPayload = decryptPayload(prepared.envelope, prepared.contentId, this.keyRing);
        if (canonicalJson(existingPayload) !== canonicalJson(proposedPayload)) throw createError('raw_object_conflict', 409);
      }
      return { contentId: prepared.contentId, storageRef: path.join(...components, filename), byteLength: prepared.plaintextBytes, created };
    } finally { if (directoryFd !== undefined) fs.closeSync(directoryFd); fs.closeSync(rootFd); }
  }

  async put(payload) { return this.commit(this.prepare(payload)); }

  async get(contentId) {
    this.blobPath(contentId);
    let envelope;
    const components = [contentId.slice(0, 2), contentId.slice(2, 4)];
    const rootFd = openSecureAbsoluteDirectory(this.rootPath);
    let directoryFd;
    try {
      directoryFd = openSecureSubdirectory(rootFd, components);
      envelope = JSON.parse(secureReadFile(directoryFd, `${contentId}.enc.json`));
    } catch (error) {
      if (error?.code === 'ENOENT') throw createError('raw_object_not_found', 404);
      throw error;
    } finally { if (directoryFd !== undefined) fs.closeSync(directoryFd); fs.closeSync(rootFd); }
    return decryptPayload(envelope, contentId, this.keyRing);
  }

  async remove(contentId) {
    this.blobPath(contentId);
    const rootFd = openSecureAbsoluteDirectory(this.rootPath);
    let directoryFd;
    try { directoryFd = openSecureSubdirectory(rootFd, [contentId.slice(0, 2), contentId.slice(2, 4)]); secureRemoveFile(directoryFd, `${contentId}.enc.json`); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
    finally { if (directoryFd !== undefined) fs.closeSync(directoryFd); fs.closeSync(rootFd); }
  }
  clientBlobPath(contentId) {
    if (!/^[a-f0-9]{64}$/.test(contentId)) throw createError('raw_content_id_invalid', 400);
    return path.join(this.rootPath, 'client-events', contentId.slice(0, 2), `${contentId}.enc.json`);
  }
  async commitClientCiphertext(contentId, envelope) {
    this.clientBlobPath(contentId);
    const components = ['client-events', contentId.slice(0, 2)];
    const filename = `${contentId}.enc.json`;
    const serialized = canonicalJson(envelope);
    const rootFd = openSecureAbsoluteDirectory(this.rootPath);
    let directoryFd;
    try {
      directoryFd = openSecureSubdirectory(rootFd, components, { create: true });
      const created = secureWriteExclusive(directoryFd, filename, Buffer.from(serialized, 'utf8'));
      if (!created) {
        const existing = secureReadFile(directoryFd, filename);
        if (existing !== serialized || ciphertextContentId(JSON.parse(existing)) !== contentId) throw createError('raw_object_conflict', 409);
      }
      return { contentId, storageRef: path.join(...components, filename), byteLength: Buffer.byteLength(serialized), created };
    } finally { if (directoryFd !== undefined) fs.closeSync(directoryFd); fs.closeSync(rootFd); }
  }
  async getClientCiphertext(contentId) {
    this.clientBlobPath(contentId);
    const rootFd = openSecureAbsoluteDirectory(this.rootPath);
    let directoryFd;
    try {
      directoryFd = openSecureSubdirectory(rootFd, ['client-events', contentId.slice(0, 2)]);
      const envelope = JSON.parse(secureReadFile(directoryFd, `${contentId}.enc.json`));
      if (ciphertextContentId(envelope) !== contentId) throw createError('raw_object_conflict', 409);
      return envelope;
    }
    catch (error) { if (error?.code === 'ENOENT') throw createError('raw_object_not_found', 404); throw error; }
    finally { if (directoryFd !== undefined) fs.closeSync(directoryFd); fs.closeSync(rootFd); }
  }
}

export class MemoryCatalog {
  constructor() {
    this.rawObjects = new Map();
    this.proposals = new Map();
    this.idempotency = new Map();
    this.auditEvents = [];
    this.rawEvents = new Map();
    this.rawSessions = new Map();
  }
  findProposal(ownerTags, idempotencyTags) {
    for (const ownerTag of ownerTags) for (const idempotencyTag of idempotencyTags) {
      const id = this.idempotency.get(`${ownerTag}\u0000${idempotencyTag}`);
      if (id) return this.proposals.get(id) || null;
    }
    return null;
  }
  enqueueProposalWithRaw(record, rawRecord) {
    const existing = this.findProposal([record.ownerTag], [record.idempotencyTag]);
    if (existing) return { record: existing, duplicate: true };
    this.rawObjects.set(rawRecord.contentId, { ...rawRecord });
    this.proposals.set(record.id, { ...record });
    this.idempotency.set(`${record.ownerTag}\u0000${record.idempotencyTag}`, record.id);
    return { record: this.proposals.get(record.id), duplicate: false };
  }
  getProposal(id) { return this.proposals.get(id) || null; }
  appendAudit(event) { this.auditEvents.push({ ...event }); }
  ingestRawEvent(record, rawRecord, auditEvent) {
    const existing = this.rawEvents.get(record.eventId);
    if (existing) { this.auditEvents.push({ ...auditEvent, outcome: 'duplicate' }); return { record: existing, duplicate: true }; }
    const bound = this.rawSessions.get(record.sessionId);
    if (bound && (bound.ownerTag !== record.ownerTag || bound.runtime !== record.projection.runtime || bound.sourceTag !== record.sourceTag)) throw createError('raw_session_binding_conflict', 409);
    this.rawObjects.set(rawRecord.contentId, { ...rawRecord });
    this.rawEvents.set(record.eventId, structuredClone(record));
    const session = this.rawSessions.get(record.sessionId) || {
      id: record.sessionId, runtime: record.projection.runtime, ownerTag: record.ownerTag,
      sourceTag: record.sourceTag, firstOccurredAt: record.projection.occurredAt,
      lastOccurredAt: record.projection.occurredAt, eventCount: 0, createdAt: record.createdAt
    };
    session.eventCount += 1;
    session.firstOccurredAt = earlierTimestamp(session.firstOccurredAt, record.projection.occurredAt);
    session.lastOccurredAt = laterTimestamp(session.lastOccurredAt, record.projection.occurredAt);
    this.rawSessions.set(record.sessionId, session);
    this.auditEvents.push({ ...auditEvent, outcome: 'stored' });
    return { record: this.rawEvents.get(record.eventId), duplicate: false };
  }
  getRawEvent(id) { return this.rawEvents.get(id) || null; }
  searchSessions({ ownerTags = [], query = '', limit = 20 }) {
    const needle = query.toLowerCase();
    const allowed = new Set(ownerTags);
    return [...this.rawSessions.values()].filter(item => allowed.has(item.ownerTag) && (!needle || `${item.id} ${item.runtime}`.toLowerCase().includes(needle))).sort(compareSessions).slice(0, limit);
  }
  getSession(id) { return this.rawSessions.get(id) || null; }
  listSessionEvents(id) { return [...this.rawEvents.values()].filter(item => item.sessionId === id).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.eventId.localeCompare(b.eventId)); }
  status() {
    return { backend: 'memory', rawObjects: this.rawObjects.size, queuedProposals: [...this.proposals.values()].filter(item => item.status === 'queued').length, auditEvents: this.auditEvents.length };
  }
}

function earlierTimestamp(current, candidate) {
  if (!candidate) return current || null;
  if (!current) return candidate;
  return Date.parse(candidate) < Date.parse(current) ? candidate : current;
}

function laterTimestamp(current, candidate) {
  if (!candidate) return current || null;
  if (!current) return candidate;
  return Date.parse(candidate) > Date.parse(current) ? candidate : current;
}

function compareSessions(a, b) {
  const aTime = a.lastOccurredAt ? Date.parse(a.lastOccurredAt) : -Infinity;
  const bTime = b.lastOccurredAt ? Date.parse(b.lastOccurredAt) : -Infinity;
  return bTime - aTime || String(b.createdAt).localeCompare(String(a.createdAt)) || a.id.localeCompare(b.id);
}

function escapedLike(value) { return `%${String(value).replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_')}%`; }

export class SqliteCatalog {
  constructor({ databasePath }) {
    this.databasePath = path.resolve(databasePath);
    fs.mkdirSync(path.dirname(this.databasePath), { recursive: true, mode: 0o700 });
    this.db = new Database(this.databasePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS raw_objects_v2 (content_id TEXT PRIMARY KEY, media_type TEXT NOT NULL, byte_length INTEGER NOT NULL, storage_ref TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS fabric_proposals (id TEXT PRIMARY KEY, owner_tag TEXT NOT NULL, scope_tag TEXT NOT NULL, status TEXT NOT NULL, content_id TEXT NOT NULL REFERENCES raw_objects_v2(content_id), idempotency_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(owner_tag, idempotency_tag));
      CREATE INDEX IF NOT EXISTS fabric_proposals_status_created_idx ON fabric_proposals(status, created_at);
      CREATE TABLE IF NOT EXISTS raw_sessions_v1 (session_id TEXT PRIMARY KEY, runtime TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, first_occurred_at TEXT, last_occurred_at TEXT, event_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS raw_events_v1 (event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES raw_sessions_v1(session_id), content_id TEXT NOT NULL REFERENCES raw_objects_v2(content_id), payload_digest TEXT NOT NULL, projection_json TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS raw_sessions_v1_owner_tag_idx ON raw_sessions_v1(owner_tag,last_occurred_at);
      CREATE INDEX IF NOT EXISTS raw_events_v1_session_created_idx ON raw_events_v1(session_id,created_at,event_id);
      CREATE TABLE IF NOT EXISTS audit_events_v2 (id TEXT PRIMARY KEY, ts TEXT NOT NULL, actor_tag TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, request_id TEXT, target_id TEXT, scope_tag TEXT, details_json TEXT NOT NULL);
    `);
    this.selectProposal = this.db.prepare('SELECT * FROM fabric_proposals WHERE id = ?');
    this.selectProposalByTags = this.db.prepare('SELECT * FROM fabric_proposals WHERE owner_tag = ? AND idempotency_tag = ?');
    this.insertBoth = this.db.transaction((record, raw) => {
      const existing = this.selectProposalByTags.get(record.ownerTag, record.idempotencyTag);
      if (existing) return { record: this.mapProposal(existing), duplicate: true };
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(raw);
      this.db.prepare('INSERT INTO fabric_proposals(id,owner_tag,scope_tag,status,content_id,idempotency_tag,source_tag,created_at) VALUES (@id,@ownerTag,@scopeTag,@status,@contentId,@idempotencyTag,@sourceTag,@createdAt)').run(record);
      return { record, duplicate: false };
    });
    this.insertAudit = this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (@id,@ts,@actorTag,@action,@outcome,@requestId,@targetId,@scopeTag,@detailsJson)');
    this.insertRawEvent = this.db.transaction((record, raw, auditEvent) => {
      const existing = this.db.prepare('SELECT * FROM raw_events_v1 WHERE event_id=?').get(record.eventId);
      if (existing) {
        this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (?,?,?,?,?,?,?,?,?)').run(auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, 'duplicate', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {}));
        return { record: this.mapRawEvent(existing), duplicate: true };
      }
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(raw);
      this.db.prepare('INSERT OR IGNORE INTO raw_sessions_v1(session_id,runtime,owner_tag,source_tag,first_occurred_at,last_occurred_at,event_count,created_at) VALUES (?,?,?,?,?,?,0,?)').run(record.sessionId, record.projection.runtime, record.ownerTag, record.sourceTag, record.projection.occurredAt, record.projection.occurredAt, record.createdAt);
      const bound = this.db.prepare('SELECT * FROM raw_sessions_v1 WHERE session_id=?').get(record.sessionId);
      if (bound.owner_tag !== record.ownerTag || bound.runtime !== record.projection.runtime || bound.source_tag !== record.sourceTag) throw createError('raw_session_binding_conflict', 409);
      this.db.prepare('INSERT INTO raw_events_v1(event_id,session_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES (?,?,?,?,?,?,?,?)').run(record.eventId, record.sessionId, record.contentId, record.payloadDigest, JSON.stringify(record.projection), record.ownerTag, record.sourceTag, record.createdAt);
      this.db.prepare("UPDATE raw_sessions_v1 SET event_count=event_count+1,first_occurred_at=CASE WHEN ? IS NULL THEN first_occurred_at WHEN first_occurred_at IS NULL OR julianday(?)<julianday(first_occurred_at) THEN ? ELSE first_occurred_at END,last_occurred_at=CASE WHEN ? IS NULL THEN last_occurred_at WHEN last_occurred_at IS NULL OR julianday(?)>julianday(last_occurred_at) THEN ? ELSE last_occurred_at END WHERE session_id=?").run(record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.sessionId);
      this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (?,?,?,?,?,?,?,?,?)').run(auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, 'stored', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {}));
      return { record, duplicate: false };
    });
  }
  mapProposal(row) {
    return row ? { id: row.id, ownerTag: row.owner_tag, scopeTag: row.scope_tag, status: row.status, contentId: row.content_id, idempotencyTag: row.idempotency_tag, sourceTag: row.source_tag, createdAt: row.created_at } : null;
  }
  findProposal(ownerTags, idempotencyTags) {
    for (const ownerTag of ownerTags) for (const idempotencyTag of idempotencyTags) {
      const found = this.selectProposalByTags.get(ownerTag, idempotencyTag);
      if (found) return this.mapProposal(found);
    }
    return null;
  }
  enqueueProposalWithRaw(record, rawRecord) {
    return this.insertBoth(record, rawRecord);
  }
  getProposal(id) { return this.mapProposal(this.selectProposal.get(id)); }
  appendAudit(event) {
    this.insertAudit.run({ id: event.id, ts: event.ts, actorTag: event.actorTag, action: event.action, outcome: event.outcome, requestId: event.requestId || null, targetId: event.targetId || null, scopeTag: event.scopeTag || null, detailsJson: JSON.stringify(event.details || {}) });
  }
  mapRawEvent(row) { return row ? { eventId: row.event_id, sessionId: row.session_id, contentId: row.content_id, payloadDigest: row.payload_digest, projection: JSON.parse(row.projection_json), ownerTag: row.owner_tag, sourceTag: row.source_tag, createdAt: row.created_at } : null; }
  ingestRawEvent(record, rawRecord, auditEvent) { return this.insertRawEvent(record, rawRecord, auditEvent); }
  getRawEvent(id) { return this.mapRawEvent(this.db.prepare('SELECT * FROM raw_events_v1 WHERE event_id=?').get(id)); }
  mapSession(row) { return row ? { id: row.session_id, runtime: row.runtime, ownerTag: row.owner_tag, sourceTag: row.source_tag, firstOccurredAt: row.first_occurred_at, lastOccurredAt: row.last_occurred_at, eventCount: row.event_count, createdAt: row.created_at } : null; }
  searchSessions({ ownerTags = [], query = '', limit = 20 }) {
    if (!ownerTags.length) return [];
    const pattern = escapedLike(query);
    const placeholders = ownerTags.map(() => '?').join(',');
    return this.db.prepare(`SELECT * FROM raw_sessions_v1 WHERE owner_tag IN (${placeholders}) AND (lower(session_id) LIKE lower(?) ESCAPE '\\' OR lower(runtime) LIKE lower(?) ESCAPE '\\') ORDER BY CASE WHEN last_occurred_at IS NULL THEN 1 ELSE 0 END,last_occurred_at DESC,created_at DESC,session_id ASC LIMIT ?`).all(...ownerTags, pattern, pattern, limit).map(row => this.mapSession(row));
  }
  getSession(id) { return this.mapSession(this.db.prepare('SELECT * FROM raw_sessions_v1 WHERE session_id=?').get(id)); }
  listSessionEvents(id) { return this.db.prepare('SELECT * FROM raw_events_v1 WHERE session_id=? ORDER BY created_at,event_id').all(id).map(row => this.mapRawEvent(row)); }
  status() {
    return { backend: 'sqlite', rawObjects: this.db.prepare('SELECT count(*) AS count FROM raw_objects_v2').get().count, queuedProposals: this.db.prepare("SELECT count(*) AS count FROM fabric_proposals WHERE status='queued'").get().count, auditEvents: this.db.prepare('SELECT count(*) AS count FROM audit_events_v2').get().count };
  }
  close() { this.db.close(); }
}

const POSTGRES_SCHEMA = 'agent_memory_fabric';
const POSTGRES_SCHEMA_VERSION = 3;
const POSTGRES_SCHEMA_SQL = [
  `CREATE SCHEMA IF NOT EXISTS ${POSTGRES_SCHEMA}`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_objects_v2 (
    content_id TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    byte_length BIGINT NOT NULL CHECK (byte_length >= 0),
    storage_ref TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.fabric_proposals (
    id TEXT PRIMARY KEY,
    owner_tag TEXT NOT NULL,
    scope_tag TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'review', 'promoted', 'rejected', 'revoked')),
    content_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id),
    idempotency_tag TEXT NOT NULL,
    source_tag TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(owner_tag, idempotency_tag)
  )`,
  `CREATE INDEX IF NOT EXISTS fabric_proposals_status_created_idx
    ON ${POSTGRES_SCHEMA}.fabric_proposals(status, created_at)`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.identity_records (
    id TEXT PRIMARY KEY,
    identity_tag TEXT NOT NULL UNIQUE,
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('agent', 'person', 'relationship', 'room', 'domain', 'shared')),
    status TEXT NOT NULL CHECK (status IN ('active', 'merged', 'split', 'revoked')),
    canonical_identity_id TEXT REFERENCES ${POSTGRES_SCHEMA}.identity_records(id),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    evidence_digest TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.ingest_cursors (
    source_tag TEXT NOT NULL,
    cursor_tag TEXT NOT NULL,
    value_ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(source_tag, cursor_tag)
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_sessions_v1 (
    session_id TEXT PRIMARY KEY, runtime TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL,
    first_occurred_at TIMESTAMPTZ, last_occurred_at TIMESTAMPTZ, event_count BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_events_v1 (
    event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_sessions_v1(session_id),
    content_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id), payload_digest TEXT NOT NULL,
    projection_json JSONB NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS raw_sessions_v1_owner_tag_idx ON ${POSTGRES_SCHEMA}.raw_sessions_v1(owner_tag,last_occurred_at)`,
  `CREATE INDEX IF NOT EXISTS raw_events_v1_session_created_idx ON ${POSTGRES_SCHEMA}.raw_events_v1(session_id,created_at,event_id)`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.audit_events_v2 (
    id TEXT PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    actor_tag TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    request_id TEXT,
    target_id TEXT,
    scope_tag TEXT,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb
  )`,
  `CREATE INDEX IF NOT EXISTS audit_events_v2_ts_idx ON ${POSTGRES_SCHEMA}.audit_events_v2(ts)`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.retention_tombstones (
    id TEXT PRIMARY KEY,
    content_id TEXT NOT NULL,
    content_checksum TEXT NOT NULL,
    source_pointer_tag TEXT,
    reason_code TEXT NOT NULL,
    original_created_at TIMESTAMPTZ NOT NULL,
    expired_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`
];

function postgresSslConfig(env) {
  const mode = String(env.AMF_CATALOG_SSL_MODE || 'verify-full').trim().toLowerCase();
  if (mode === 'disable') return false;
  if (mode === 'require') return { rejectUnauthorized: false };
  if (mode !== 'verify-full') throw createError('catalog_postgres_ssl_mode_invalid', 500);
  const caPath = String(env.AMF_CATALOG_SSL_CA_PATH || '').trim();
  return caPath
    ? { rejectUnauthorized: true, ca: fs.readFileSync(path.resolve(caPath), 'utf8') }
    : { rejectUnauthorized: true };
}

function boundedCatalogInteger(env, name, fallback, { min, max }) {
  const raw = env[name];
  if (raw == null || raw === '') return fallback;
  if (!/^\d+$/.test(String(raw))) throw createError(`invalid_environment:${name}`, 500);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw createError(`invalid_environment:${name}`, 500);
  }
  return value;
}

function catalogError(error) {
  if (error?.message === 'catalog_schema_version_unsupported' || error?.message === 'catalog_postgres_closed') return error;
  if (error?.message === 'catalog_unavailable') return error;
  const wrapped = createError('catalog_unavailable', 503, {
    code: String(error?.code || 'catalog_postgres_operation_failed')
  });
  wrapped.code = String(error?.code || 'catalog_postgres_operation_failed');
  return wrapped;
}

function mapPostgresProposal(row) {
  return row ? {
    id: row.id,
    ownerTag: row.owner_tag,
    scopeTag: row.scope_tag,
    status: row.status,
    contentId: row.content_id,
    idempotencyTag: row.idempotency_tag,
    sourceTag: row.source_tag,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at)
  } : null;
}

function mapPostgresRawEvent(row) {
  return row ? { eventId: row.event_id, sessionId: row.session_id, contentId: row.content_id, payloadDigest: row.payload_digest, projection: typeof row.projection_json === 'string' ? JSON.parse(row.projection_json) : row.projection_json, ownerTag: row.owner_tag, sourceTag: row.source_tag, createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at) } : null;
}

function mapPostgresSession(row) {
  return row ? { id: row.session_id, runtime: row.runtime, ownerTag: row.owner_tag, sourceTag: row.source_tag, firstOccurredAt: row.first_occurred_at ? new Date(row.first_occurred_at).toISOString() : null, lastOccurredAt: row.last_occurred_at ? new Date(row.last_occurred_at).toISOString() : null, eventCount: Number(row.event_count), createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at) } : null;
}

export class PostgresCatalog {
  constructor({
    connectionString,
    ssl,
    pool,
    poolFactory = (config) => new Pool(config),
    max = 10,
    connectTimeoutMs = 5000,
    queryTimeoutMs = 15000,
    statementTimeoutMs = 10000
  } = {}) {
    if (!connectionString && !pool) throw createError('catalog_postgres_url_required', 500);
    for (const [name, value] of Object.entries({ connectTimeoutMs, queryTimeoutMs, statementTimeoutMs })) {
      if (!Number.isSafeInteger(value) || value < 100 || value > 120000) throw createError(`catalog_postgres_${name}_invalid`, 500);
    }
    this.connectTimeoutMs = connectTimeoutMs;
    this.queryTimeoutMs = queryTimeoutMs;
    this.statementTimeoutMs = statementTimeoutMs;
    this.pool = pool || poolFactory({
      connectionString,
      ssl,
      max,
      connectionTimeoutMillis: connectTimeoutMs,
      query_timeout: queryTimeoutMs,
      statement_timeout: statementTimeoutMs
    });
    this._readyPromise = null;
    this._closed = false;
    this._healthy = null;
    this._lastError = null;
    this._counts = { rawObjects: null, queuedProposals: null, auditEvents: null };
    this.pool.on?.('error', (error) => {
      this._healthy = false;
      this._lastError = String(error?.code || 'catalog_postgres_pool_error');
    });
  }

  async _connect() {
    let timer;
    let timedOut = false;
    const pending = Promise.resolve().then(() => this.pool.connect());
    pending.then((client) => {
      if (timedOut) client.release?.(new Error('catalog_late_client_discarded'));
    }, () => {});
    try {
      return await Promise.race([
        pending,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            timedOut = true;
            const error = createError('catalog_unavailable', 503, { code: 'catalog_postgres_connect_timeout' });
            error.code = 'catalog_postgres_connect_timeout';
            reject(error);
          }, this.connectTimeoutMs);
        })
      ]);
    } catch (error) {
      throw catalogError(error);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async _query(target, text, values = []) {
    const controller = new AbortController();
    let timer;
    try {
      return await Promise.race([
        target.query({ text, values, query_timeout: this.queryTimeoutMs, signal: controller.signal }),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            const error = createError('catalog_unavailable', 503, { code: 'catalog_postgres_query_timeout' });
            error.code = 'catalog_postgres_query_timeout';
            reject(error);
          }, this.queryTimeoutMs);
        })
      ]);
    } catch (error) {
      throw catalogError(error);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async _begin(client) {
    await this._query(client, 'BEGIN');
    await this._query(client, `SELECT set_config('statement_timeout', $1, true)`, [String(this.statementTimeoutMs)]);
  }

  ready() {
    if (this._closed) return Promise.reject(createError('catalog_postgres_closed', 500));
    if (!this._readyPromise) {
      const current = this._initialize();
      this._readyPromise = current;
      current.catch((error) => {
        this._healthy = false;
        this._lastError = String(error?.code || 'catalog_postgres_initialization_failed');
        if (this._readyPromise === current) this._readyPromise = null;
      });
    }
    return this._readyPromise;
  }

  async _initialize() {
    const client = await this._connect();
    let destroyClient = false;
    try {
      await this._begin(client);
      await this._query(client, 'SELECT pg_advisory_xact_lock($1)', [824602001]);
      for (const statement of POSTGRES_SCHEMA_SQL) await this._query(client, statement);
      const schemaState = await this._query(client, `SELECT max(version) AS current_version FROM ${POSTGRES_SCHEMA}.schema_migrations`);
      const currentVersion = schemaState.rows[0]?.current_version == null ? 0 : Number(schemaState.rows[0].current_version);
      if (!Number.isInteger(currentVersion) || currentVersion > POSTGRES_SCHEMA_VERSION) {
        throw createError('catalog_schema_version_unsupported', 500);
      }
      await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.schema_migrations(version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
        [POSTGRES_SCHEMA_VERSION]
      );
      await this._query(client, 'COMMIT');
      this._healthy = true;
      this._lastError = null;
    } catch (error) {
      destroyClient = error?.code === 'catalog_postgres_query_timeout';
      if (!destroyClient) try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      throw error;
    } finally {
      client.release(destroyClient ? new Error('catalog_client_discarded') : undefined);
    }
  }

  async findProposal(ownerTags, idempotencyTags) {
    await this.ready();
    const result = await this._query(this.pool,
      `SELECT * FROM ${POSTGRES_SCHEMA}.fabric_proposals
       WHERE owner_tag = ANY($1::text[]) AND idempotency_tag = ANY($2::text[])
       ORDER BY created_at ASC LIMIT 1`,
      [ownerTags, idempotencyTags]
    );
    return mapPostgresProposal(result.rows[0]);
  }

  async enqueueProposalWithRaw(record, rawRecord) {
    await this.ready();
    const client = await this._connect();
    let destroyClient = false;
    let commitAttempted = false;
    try {
      await this._begin(client);
      await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (content_id) DO NOTHING`,
        [rawRecord.contentId, rawRecord.mediaType, rawRecord.byteLength, rawRecord.storageRef, rawRecord.createdAt]
      );
      const inserted = await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.fabric_proposals
          (id,owner_tag,scope_tag,status,content_id,idempotency_tag,source_tag,created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (owner_tag,idempotency_tag) DO NOTHING RETURNING *`,
        [record.id, record.ownerTag, record.scopeTag, record.status, record.contentId, record.idempotencyTag, record.sourceTag, record.createdAt]
      );
      if (inserted.rows[0]) {
        commitAttempted = true;
        await this._query(client, 'COMMIT');
        return { record: mapPostgresProposal(inserted.rows[0]), duplicate: false };
      }
      const existing = await this._query(client,
        `SELECT * FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE owner_tag=$1 AND idempotency_tag=$2`,
        [record.ownerTag, record.idempotencyTag]
      );
      if (!existing.rows[0]) throw createError('catalog_idempotency_resolution_failed', 500);
      await this._query(client,
        `DELETE FROM ${POSTGRES_SCHEMA}.raw_objects_v2 raw
         WHERE raw.content_id=$1 AND NOT EXISTS (
           SELECT 1 FROM ${POSTGRES_SCHEMA}.fabric_proposals proposal WHERE proposal.content_id=raw.content_id
         )`,
        [rawRecord.contentId]
      );
      commitAttempted = true;
      await this._query(client, 'COMMIT');
      return { record: mapPostgresProposal(existing.rows[0]), duplicate: true };
    } catch (error) {
      if (commitAttempted) {
        // Once COMMIT was sent, a lost acknowledgement cannot prove rollback.
        // Discard the connection and let the caller reconcile by idempotency key.
        destroyClient = true;
        error.catalogTransactionOutcome = 'ambiguous_commit';
        error.retainRaw = true;
      } else {
        destroyClient = error?.code === 'catalog_postgres_query_timeout';
        if (!destroyClient) try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
        error.catalogTransactionOutcome = 'not_committed';
        error.retainRaw = false;
      }
      throw error;
    } finally {
      client.release(destroyClient ? new Error('catalog_client_discarded') : undefined);
    }
  }

  async getProposal(id) {
    await this.ready();
    const result = await this._query(this.pool,
      `SELECT * FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE id=$1`,
      [id]
    );
    return mapPostgresProposal(result.rows[0]);
  }

  async ingestRawEvent(record, rawRecord, auditEvent) {
    await this.ready();
    const client = await this._connect();
    let destroyClient = false;
    let commitAttempted = false;
    let ambiguousError = null;
    let expectedDuplicate = false;
    try {
      await this._begin(client);
      const existing = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE event_id=$1`, [record.eventId]);
      if (existing.rows[0]) {
        expectedDuplicate = true;
        await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, [auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, 'duplicate', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {})]);
        commitAttempted = true;
        await this._query(client, 'COMMIT'); return { record: mapPostgresRawEvent(existing.rows[0]), duplicate: true };
      }
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (content_id) DO NOTHING`, [rawRecord.contentId, rawRecord.mediaType, rawRecord.byteLength, rawRecord.storageRef, rawRecord.createdAt]);
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_sessions_v1(session_id,runtime,owner_tag,source_tag,first_occurred_at,last_occurred_at,event_count,created_at) VALUES ($1,$2,$3,$4,$5,$5,0,$6) ON CONFLICT (session_id) DO NOTHING`, [record.sessionId, record.projection.runtime, record.ownerTag, record.sourceTag, record.projection.occurredAt, record.createdAt]);
      const boundSession = (await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 WHERE session_id=$1`, [record.sessionId])).rows[0];
      if (!boundSession || boundSession.owner_tag !== record.ownerTag || boundSession.runtime !== record.projection.runtime || boundSession.source_tag !== record.sourceTag) throw createError('raw_session_binding_conflict', 409);
      const inserted = await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_events_v1(event_id,session_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8) ON CONFLICT (event_id) DO NOTHING RETURNING *`, [record.eventId, record.sessionId, record.contentId, record.payloadDigest, JSON.stringify(record.projection), record.ownerTag, record.sourceTag, record.createdAt]);
      const resolved = inserted.rows[0] || (await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE event_id=$1`, [record.eventId])).rows[0];
      if (inserted.rows[0]) await this._query(client, `UPDATE ${POSTGRES_SCHEMA}.raw_sessions_v1 SET event_count=event_count+1,first_occurred_at=CASE WHEN $1::timestamptz IS NULL THEN first_occurred_at ELSE least(coalesce(first_occurred_at,$1::timestamptz),$1::timestamptz) END,last_occurred_at=CASE WHEN $1::timestamptz IS NULL THEN last_occurred_at ELSE greatest(coalesce(last_occurred_at,$1::timestamptz),$1::timestamptz) END WHERE session_id=$2`, [record.projection.occurredAt, record.sessionId]);
      expectedDuplicate = !inserted.rows[0];
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, [auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, inserted.rows[0] ? 'stored' : 'duplicate', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {})]);
      commitAttempted = true;
      await this._query(client, 'COMMIT');
      return { record: mapPostgresRawEvent(resolved), duplicate: !inserted.rows[0] };
    } catch (error) {
      if (commitAttempted) {
        destroyClient = true;
        error.catalogTransactionOutcome = 'ambiguous_commit';
        error.retainRaw = true;
        ambiguousError = error;
      } else {
        destroyClient = error?.code === 'catalog_postgres_query_timeout';
        if (!destroyClient) try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
        error.catalogTransactionOutcome = 'not_committed';
        error.retainRaw = false;
        throw error;
      }
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
    if (ambiguousError) {
      const reconciled = await this.getRawEvent(record.eventId);
      if (reconciled && reconciled.sessionId === record.sessionId && reconciled.ownerTag === record.ownerTag
        && reconciled.sourceTag === record.sourceTag && reconciled.payloadDigest === record.payloadDigest
        && reconciled.projection.runtime === record.projection.runtime) {
        return { record: reconciled, duplicate: expectedDuplicate };
      }
      throw ambiguousError;
    }
  }
  async getRawEvent(id) { await this.ready(); return mapPostgresRawEvent((await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE event_id=$1`, [id])).rows[0]); }
  async searchSessions({ ownerTags = [], query = '', limit = 20 }) { if (!ownerTags.length) return []; await this.ready(); return (await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 WHERE owner_tag=ANY($1::text[]) AND (session_id ILIKE $2 ESCAPE '\\' OR runtime ILIKE $2 ESCAPE '\\') ORDER BY last_occurred_at DESC NULLS LAST,created_at DESC,session_id ASC LIMIT $3`, [ownerTags, escapedLike(query), limit])).rows.map(mapPostgresSession); }
  async getSession(id) { await this.ready(); return mapPostgresSession((await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 WHERE session_id=$1`, [id])).rows[0]); }
  async listSessionEvents(id) { await this.ready(); return (await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE session_id=$1 ORDER BY created_at,event_id`, [id])).rows.map(mapPostgresRawEvent); }

  async appendAudit(event) {
    await this.ready();
    await this._query(this.pool,
      `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2
        (id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
      [event.id, event.ts, event.actorTag, event.action, event.outcome, event.requestId || null, event.targetId || null, event.scopeTag || null, JSON.stringify(event.details || {})]
    );
  }

  async health() {
    await this.ready();
    try {
      const result = await this._query(this.pool, `SELECT
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.raw_objects_v2) AS raw_objects,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE status='queued') AS queued_proposals,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.audit_events_v2) AS audit_events`);
      const row = result.rows[0] || {};
      this._counts = {
        rawObjects: Number(row.raw_objects || 0),
        queuedProposals: Number(row.queued_proposals || 0),
        auditEvents: Number(row.audit_events || 0)
      };
      this._healthy = true;
      this._lastError = null;
      return this.status();
    } catch (error) {
      this._healthy = false;
      this._lastError = String(error?.code || 'catalog_postgres_health_failed');
      throw error;
    }
  }

  status() {
    return {
      backend: 'postgres',
      schemaVersion: POSTGRES_SCHEMA_VERSION,
      healthy: this._healthy,
      closed: this._closed,
      ...this._counts,
      ...(this._lastError ? { lastError: this._lastError } : {})
    };
  }

  async close() {
    if (this._closed) return;
    this._closed = true;
    await this.pool.end();
  }
}

const SAFE_AUDIT_DETAIL_KEYS = new Set(['code', 'contentId', 'duplicate', 'resultCount', 'total', 'view', 'purpose', 'transport']);

export class FabricStore {
  constructor({ rawStore, catalog, ingestKeyRing = null, clock = () => new Date(), idFactory = () => crypto.randomUUID() }) {
    this.rawStore = rawStore;
    this.catalog = catalog;
    this.clock = clock;
    this.idFactory = idFactory;
    this.configured = true;
    this._proposalMutation = Promise.resolve();
    this.ingestKeys = ingestKeyRing ? normalizeIngestKeyRing(ingestKeyRing) : null;
  }

  async _catalogOperation(operation) {
    try {
      return await operation();
    } catch (error) {
      if (error?.message === 'catalog_unavailable' || error?.message === 'catalog_schema_version_unsupported' || (Number(error?.status) >= 400 && Number(error?.status) < 500)) throw error;
      const wrapped = createError('catalog_unavailable', 503, { code: String(error?.code || 'catalog_operation_failed') });
      wrapped.code = String(error?.code || 'catalog_operation_failed');
      throw wrapped;
    }
  }

  propose(input) {
    const run = this._proposalMutation.catch(() => {}).then(() => this._propose(input));
    this._proposalMutation = run.then(() => undefined, () => undefined);
    return run;
  }

  async _propose({ actor, scope, text, metadata = {}, infer = false, record = null, rationale = null, expectedRevision = null, source = 'v2-rest', idempotencyKey }) {
    const payload = record
      ? { type: 'canonical-memory-proposal', actor, scope, record, rationale, expectedRevision }
      : { type: 'memory-proposal', actor, scope, text, metadata, infer };
    const prepared = this.rawStore.prepare(payload);
    const ownerTags = this.rawStore.opaqueTags('owner', actor);
    const idempotencyTags = this.rawStore.opaqueTags('idempotency', idempotencyKey);
    const existing = await this._catalogOperation(() => this.catalog.findProposal(ownerTags, idempotencyTags));
    if (existing) {
      const existingPayload = await this.rawStore.get(existing.contentId);
      if (canonicalJson(existingPayload) !== canonicalJson(payload)) throw createError('idempotency_key_conflict', 409);
      return { id: existing.id, status: existing.status, contentId: existing.contentId, scope, createdAt: existing.createdAt, duplicate: true };
    }
    const createdAt = this.clock().toISOString();
    const raw = await this.rawStore.commit(prepared);
    const catalogRecord = {
      id: this.idFactory(), ownerTag: this.rawStore.opaqueTag('owner', actor), scopeTag: this.rawStore.opaqueTag('scope', scope), status: 'queued', contentId: raw.contentId,
      idempotencyTag: this.rawStore.opaqueTag('idempotency', idempotencyKey), sourceTag: this.rawStore.opaqueTag('source', source), createdAt
    };
    try {
      const queued = await this._catalogOperation(() => this.catalog.enqueueProposalWithRaw(
        catalogRecord,
        { contentId: raw.contentId, mediaType: 'application/vnd.agent-memory-fabric.proposal+json', byteLength: raw.byteLength, storageRef: raw.storageRef, createdAt }
      ));
      if (queued.duplicate) {
        const existingPayload = await this.rawStore.get(queued.record.contentId);
        if (canonicalJson(existingPayload) !== canonicalJson(payload)) {
          throw createError('idempotency_key_conflict', 409);
        }
        return { id: queued.record.id, status: queued.record.status, contentId: queued.record.contentId, scope, createdAt: queued.record.createdAt, duplicate: true };
      }
      return { id: queued.record.id, status: 'queued', contentId: raw.contentId, scope, createdAt, duplicate: false };
    } catch (error) {
      if (error?.catalogTransactionOutcome === 'ambiguous_commit' || error?.retainRaw === true) {
        try {
          const reconciled = await this._catalogOperation(() => this.catalog.findProposal(ownerTags, idempotencyTags));
          if (reconciled) {
            const existingPayload = await this.rawStore.get(reconciled.contentId);
            if (canonicalJson(existingPayload) === canonicalJson(payload)) {
              return {
                id: reconciled.id,
                status: reconciled.status,
                contentId: reconciled.contentId,
                scope,
                createdAt: reconciled.createdAt,
                duplicate: reconciled.id !== catalogRecord.id
              };
            }
            throw createError('idempotency_key_conflict', 409);
          }
        } catch (reconcileError) {
          if (reconcileError?.message === 'idempotency_key_conflict') throw reconcileError;
          // Reconciliation itself is unavailable: retain the encrypted orphan.
        }
        throw error;
      }
      // Content addressing is shared across owners, keys and Fabric processes.
      // Local `created` is not proof that no catalog row references this RAW.
      // Retain the encrypted orphan; only coordinated reference-aware GC may delete it.
      throw error;
    }
  }

  async readProposalAuthorized(id, { actor, allowedScopes = [], allowAll = false }) {
    const record = await this._catalogOperation(() => this.catalog.getProposal(id));
    const scopeTags = new Set(allowedScopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope)));
    if (!record || (!allowAll && !scopeTags.has(record.scopeTag))) {
      throw createError('memory_not_found', 404);
    }
    const payload = await this.rawStore.get(record.contentId);
    if (this.rawStore.opaqueTag('owner', payload.actor, record.ownerTag.split(':', 1)[0]) !== record.ownerTag || this.rawStore.opaqueTag('scope', payload.scope, record.scopeTag.split(':', 1)[0]) !== record.scopeTag) {
      throw createError('catalog_binding_mismatch', 500);
    }
    return { id: record.id, status: record.status, contentId: record.contentId, scope: payload.scope, createdAt: record.createdAt, payload };
  }

  async getProposalStatusAuthorized(id, { actor, allowedScopes = [], allowAll = false }) {
    const record = await this._catalogOperation(() => this.catalog.getProposal(id));
    const scopeTags = new Set(allowedScopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope)));
    if (!record || (!allowAll && !scopeTags.has(record.scopeTag))) {
      throw createError('memory_not_found', 404);
    }
    return { id: record.id, status: record.status, contentId: record.contentId, createdAt: record.createdAt };
  }

  async readProposal(id) { return this.readProposalAuthorized(id, { actor: '', allowAll: true }); }

  async ingestRawEvent(input, { requestId = null } = {}) {
    if (!this.ingestKeys) throw createError('raw_ingest_unconfigured', 503);
    validateClientCiphertext({ ...input, actorId: input.actor }, { allowedKeyIds: new Set(this.ingestKeys.keys.keys()), authorizations: this.ingestKeys.authorizations });
    const { projection, envelope, sourceInstanceId, actor } = input;
    const contentId = ciphertextContentId(envelope);
    const payloadDigest = ciphertextPayloadDigest(envelope);
    decryptClientCiphertext({ actorId: actor, sourceInstanceId, projection, envelope }, this.ingestKeys);
    const ownerTags = new Set(this.rawStore.opaqueTags('raw-owner', actor));
    const sourceTags = new Set(this.rawStore.opaqueTags('raw-source', sourceInstanceId));
    const existing = await this._catalogOperation(() => this.catalog.getRawEvent(projection.eventId));
    const auditEvent = { id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action: 'raw_event_ingest', outcome: 'stored', requestId, targetId: projection.eventId, scopeTag: null, details: { contentId, duplicate: Boolean(existing) } };
    if (existing) {
      if (!ownerTags.has(existing.ownerTag) || !sourceTags.has(existing.sourceTag) || existing.sessionId !== projection.sessionId || existing.projection.runtime !== projection.runtime) throw createError('raw_session_binding_conflict', 409);
      if (existing.payloadDigest !== payloadDigest) throw createError('raw_event_conflict', 409);
      await this._catalogOperation(() => this.catalog.ingestRawEvent(existing, null, auditEvent));
      return { status: 'duplicate', duplicate: true, eventId: projection.eventId, sessionId: projection.sessionId, contentId: existing.contentId };
    }
    const createdAt = this.clock().toISOString();
    const boundSession = await this._catalogOperation(() => this.catalog.getSession(projection.sessionId));
    if (boundSession && (!ownerTags.has(boundSession.ownerTag) || !sourceTags.has(boundSession.sourceTag) || boundSession.runtime !== projection.runtime)) throw createError('raw_session_binding_conflict', 409);
    // Reject a known binding conflict before creating an unreferenced ciphertext
    // object. A concurrent binding race is still resolved atomically by the
    // catalog; its ciphertext is retained for reference-aware reconciliation/GC.
    const raw = await this.rawStore.commitClientCiphertext(contentId, envelope);
    const record = {
      eventId: projection.eventId, sessionId: projection.sessionId, contentId, payloadDigest, projection,
      ownerTag: boundSession?.ownerTag || this.rawStore.opaqueTag('raw-owner', actor),
      sourceTag: boundSession?.sourceTag || this.rawStore.opaqueTag('raw-source', sourceInstanceId), createdAt
    };
    const stored = await this._catalogOperation(() => this.catalog.ingestRawEvent(record, { contentId, mediaType: 'application/vnd.agent-memory-fabric.raw-event-ciphertext+json', byteLength: raw.byteLength, storageRef: raw.storageRef, createdAt }, auditEvent));
    if (stored.record.payloadDigest !== payloadDigest) throw createError('raw_event_conflict', 409);
    return { status: stored.duplicate ? 'duplicate' : 'stored', duplicate: stored.duplicate, eventId: projection.eventId, sessionId: projection.sessionId, contentId: stored.record.contentId };
  }

  createSessionReader() {
    if (!this.ingestKeys || !this.catalog.searchSessions) return null;
    const store = this;
    const publicSession = session => ({
      id: session.id, runtime: session.runtime, firstOccurredAt: session.firstOccurredAt,
      lastOccurredAt: session.lastOccurredAt, eventCount: session.eventCount, createdAt: session.createdAt,
      title: `${session.runtime} session`, scope: '', ownerSelf: true
    });
    const ownedSession = async (actor, id) => {
      const session = await store._catalogOperation(() => store.catalog.getSession(id));
      const ownerTags = new Set(store.rawStore.opaqueTags('raw-owner', actor));
      if (!session || !ownerTags.has(session.ownerTag)) throw createError('session_not_found', 404);
      return session;
    };
    return {
      configured: true,
      kind: 'fabric-ciphertext-catalog',
      async search({ actor, query, limit }) {
        const sessions = await store._catalogOperation(() => store.catalog.searchSessions({ ownerTags: store.rawStore.opaqueTags('raw-owner', actor), query, limit }));
        return { items: sessions.map(publicSession), total: sessions.length };
      },
      async get({ actor, id }) {
        return publicSession(await ownedSession(actor, id));
      },
      async transcript({ actor, id, view }) {
        await ownedSession(actor, id);
        const events = await store._catalogOperation(() => store.catalog.listSessionEvents(id));
        if (view !== 'original') return { id, view: 'redacted', messages: events.map(event => ({ eventId: event.eventId, occurredAt: event.projection.occurredAt, role: event.projection.role, content: { redacted: true, contentType: event.projection.contentType, parts: event.projection.contentParts } })) };
        const messages = [];
        for (const event of events) {
          const envelope = await store.rawStore.getClientCiphertext(event.contentId);
          if (envelope.actorId !== actor || !store.rawStore.opaqueTags('raw-owner', actor).includes(event.ownerTag)
            || !store.rawStore.opaqueTags('raw-source', envelope.sourceInstanceId).includes(event.sourceTag)) throw createError('catalog_binding_mismatch', 500);
          const item = decryptClientCiphertext({ actorId: actor, sourceInstanceId: envelope.sourceInstanceId, projection: event.projection, envelope }, store.ingestKeys);
          messages.push({ eventId: event.eventId, occurredAt: event.projection.occurredAt, role: event.projection.role, raw: item.event.raw });
        }
        return { id, view: 'original', messages };
      }
    };
  }

  async audit({ actor = 'anonymous', action, outcome, requestId = null, targetId = null, scope = null, details = {} }) {
    const safeDetails = Object.fromEntries(Object.entries(details).filter(([key]) => SAFE_AUDIT_DETAIL_KEYS.has(key)));
    await this._catalogOperation(() => this.catalog.appendAudit({ id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action, outcome, requestId, targetId, scopeTag: scope ? this.rawStore.opaqueTag('audit-scope', scope) : null, details: safeDetails }));
  }
  async ready() { await this._catalogOperation(() => this.catalog.ready?.()); }
  async health() { return this._catalogOperation(() => this.catalog.health ? this.catalog.health() : this.status()); }
  async close() { await this.catalog.close?.(); }
  status() { return { configured: true, rawIngestConfigured: Boolean(this.ingestKeys), ...this.catalog.status() }; }
}

export function createUnconfiguredFabricStore(reason = 'raw_encryption_key_required') {
  return { configured: false, reason, async propose() { throw createError('fabric_store_unconfigured', 503); }, async ingestRawEvent() { throw createError('raw_ingest_unconfigured', 503); }, async readProposalAuthorized() { throw createError('fabric_store_unconfigured', 503); }, async getProposalStatusAuthorized() { throw createError('fabric_store_unconfigured', 503); }, async readProposal() { throw createError('fabric_store_unconfigured', 503); }, createSessionReader() { return null; }, async audit() {}, async ready() {}, async close() {}, status() { return { configured: false }; } };
}

export function createFabricStoreFromEnv({ rootPath = process.cwd(), env = process.env, postgresPoolFactory } = {}) {
  let keyRing;
  if (env.AMF_RAW_KEY_RING_PATH) {
    try { keyRing = JSON.parse(fs.readFileSync(path.resolve(env.AMF_RAW_KEY_RING_PATH), 'utf8')); } catch { throw createError('raw_key_ring_file_invalid', 500); }
  } else if (env.AMF_RAW_KEY_RING_JSON) {
    try { keyRing = JSON.parse(env.AMF_RAW_KEY_RING_JSON); } catch { throw createError('raw_key_ring_invalid_json', 500); }
  }
  const encryptionKey = env.AMF_RAW_ENCRYPTION_KEY;
  if (!keyRing && !encryptionKey) return createUnconfiguredFabricStore();
  const dataRoot = path.resolve(rootPath, env.AMF_DATA_PATH || 'var/agent-memory-fabric');
  const catalogKind = String(env.AMF_CATALOG_KIND || 'sqlite').trim().toLowerCase();
  let catalog;
  if (catalogKind === 'sqlite') {
    catalog = new SqliteCatalog({ databasePath: env.AMF_CATALOG_PATH || path.join(dataRoot, 'catalog.sqlite') });
  } else if (catalogKind === 'postgres') {
    const connectionString = String(env.AMF_CATALOG_DATABASE_URL || '').trim();
    if (!connectionString) throw createError('catalog_postgres_url_required', 500);
    const max = Number(env.AMF_CATALOG_POOL_MAX || '10');
    if (!Number.isInteger(max) || max < 1 || max > 100) throw createError('catalog_postgres_pool_max_invalid', 500);
    const connectTimeoutMs = boundedCatalogInteger(env, 'AMF_CATALOG_CONNECT_TIMEOUT_MS', 5000, { min: 100, max: 120000 });
    const queryTimeoutMs = boundedCatalogInteger(env, 'AMF_CATALOG_QUERY_TIMEOUT_MS', 15000, { min: 100, max: 120000 });
    const statementTimeoutMs = boundedCatalogInteger(env, 'AMF_CATALOG_STATEMENT_TIMEOUT_MS', 10000, { min: 100, max: 120000 });
    catalog = new PostgresCatalog({ connectionString, ssl: postgresSslConfig(env), max, connectTimeoutMs, queryTimeoutMs, statementTimeoutMs, ...(postgresPoolFactory ? { poolFactory: postgresPoolFactory } : {}) });
  } else {
    throw createError('catalog_kind_invalid', 500);
  }
  const rawStore = new FileRawStore({ rootPath: path.join(dataRoot, 'raw'), encryptionKey, keyId: env.AMF_RAW_ENCRYPTION_KEY_ID || 'default', keyRing });
  let ingestKeyRing = null;
  if (env.AMF_INGEST_KEY_RING_PATH) {
    try { ingestKeyRing = JSON.parse(fs.readFileSync(path.resolve(env.AMF_INGEST_KEY_RING_PATH), 'utf8')); } catch { throw createError('raw_ingest_key_ring_file_invalid', 500); }
  } else if (env.AMF_INGEST_KEY_RING_JSON) {
    try { ingestKeyRing = JSON.parse(env.AMF_INGEST_KEY_RING_JSON); } catch { throw createError('raw_ingest_key_ring_invalid', 500); }
  }
  return new FabricStore({ rawStore, catalog, ingestKeyRing });
}

export { POSTGRES_SCHEMA, POSTGRES_SCHEMA_VERSION };
