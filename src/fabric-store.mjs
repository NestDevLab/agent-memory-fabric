import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import pg from 'pg';
import { ciphertextContentId, ciphertextPayloadDigest, decryptClientCiphertext, normalizeIngestKeyRing, validateClientCiphertext } from './ingest/raw-event-contract.mjs';
import { normalizeSessionContextBinding, selectLogicalMessage, sessionBindingMatches, sessionContextBinding, validateProjectionV2 } from './ingest/raw-projection-v2.mjs';
import {
  retentionDeadline,
  retentionTombstone,
  validateIdentityCreate,
  validateIdentityMutation,
  validateRetentionAction
} from './identity-retention.mjs';

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

function recallRefs(item) {
  const metadata = item?.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata) ? item.metadata : {};
  return {
    proposalId: typeof item?.proposalId === 'string' ? item.proposalId : (typeof metadata.proposalId === 'string' ? metadata.proposalId : null),
    contentId: typeof item?.contentId === 'string' ? item.contentId : (typeof metadata.contentId === 'string' ? metadata.contentId : null),
    identityId: typeof item?.identityId === 'string' ? item.identityId : (typeof metadata.identityId === 'string' ? metadata.identityId : null)
  };
}

export function identityPairLockKey(first, second) {
  const ordered = [String(first), String(second)].sort();
  return crypto.createHash('sha256').update(canonicalJson(['identity-pair', ...ordered]), 'utf8').digest('hex');
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
    this.rawEventsV2 = new Map();
    this.logicalMessages = new Map();
    this.logicalAliases = new Map();
    this.rawSessions = new Map();
    this.identities = new Map();
    this.identitiesByTag = new Map();
    this.identityEvents = [];
    this.identityIdempotency = new Map();
    this.retention = new Map();
    this.retentionTombstones = new Map();
    this.retentionOperations = new Map();
    this.curatorReceipts = new Map();
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
    if (rawRecord.retention) this.retention.set(rawRecord.contentId, { ...rawRecord.retention });
    this.proposals.set(record.id, { ...record });
    this.idempotency.set(`${record.ownerTag}\u0000${record.idempotencyTag}`, record.id);
    return { record: this.proposals.get(record.id), duplicate: false };
  }
  getProposal(id) { return this.proposals.get(id) || null; }
  recallItemActive(refs, scopeTags) {
    const allowed = new Set(scopeTags);
    if (refs.proposalId) {
      const row = this.proposals.get(refs.proposalId);
      if (!row || !allowed.has(row.scopeTag) || ['revoked', 'rejected'].includes(row.status)) return false;
    }
    if (refs.contentId) {
      const row = this.retention.get(refs.contentId);
      if (!row || !allowed.has(row.scopeTag) || row.lifecycle !== 'active') return false;
    }
    if (refs.identityId) {
      const row = this.identities.get(refs.identityId);
      if (!row || !allowed.has(row.scopeTag) || row.status !== 'active') return false;
    }
    return true;
  }
  appendAudit(event) { this.auditEvents.push({ ...event }); }
  recordCuratorReceipt(receipt, auditEvent) {
    const current = this.curatorReceipts.get(receipt.proposalId);
    const proposal = this.proposals.get(receipt.proposalId);
    if (!proposal) throw createError('receipt_proposal_unverified', 409);
    if (receipt.kind === 'decision') {
      if (current?.decision) {
        if (canonicalJson(current.decision) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
        this.auditEvents.push({ ...auditEvent, outcome: 'duplicate' });
        return { ...structuredClone(current), duplicate: true };
      }
      const row = { proposalId: receipt.proposalId, status: receipt.status, decision: structuredClone(receipt), apply: null };
      this.curatorReceipts.set(receipt.proposalId, row);
      proposal.status = receipt.status === 'rejected' ? 'rejected' : 'review';
      this.auditEvents.push({ ...auditEvent, outcome: 'recorded' });
      return { ...structuredClone(row), duplicate: false };
    }
    if (!current?.decision || current.decision.status !== 'approved_pending_apply') throw createError('receipt_transition_invalid', 409);
    if (current.apply) {
      if (canonicalJson(current.apply) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
      this.auditEvents.push({ ...auditEvent, outcome: 'duplicate' });
      return { ...structuredClone(current), duplicate: true };
    }
    current.status = 'promoted'; current.apply = structuredClone(receipt); proposal.status = 'promoted';
    this.auditEvents.push({ ...auditEvent, outcome: 'recorded' });
    return { ...structuredClone(current), duplicate: false };
  }
  getCuratorReceipt(proposalId) { const row = this.curatorReceipts.get(proposalId); return row ? structuredClone(row) : null; }
  listCuratorReceipts() { return [...this.curatorReceipts.values()].map(row => structuredClone(row)); }
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
  findLogicalMessage(ids) {
    for (const id of ids) {
      const canonical = this.logicalAliases.get(id) || (this.logicalMessages.has(id) ? id : null);
      if (canonical) return structuredClone(this.logicalMessages.get(canonical));
    }
    return null;
  }
  ingestRawEventV2(record, rawRecord, auditEvent) {
    const existing = this.rawEventsV2.get(record.eventId) || this.rawEvents.get(record.eventId);
    if (existing) { this.auditEvents.push({ ...auditEvent, outcome: 'duplicate' }); return { record: structuredClone(existing), duplicate: true, logical: this.findLogicalMessage([record.logicalMessageId]) }; }
    const session = this.rawSessions.get(record.sessionId) || { id: record.sessionId, runtime: record.projection.sourceKind, ownerTag: record.ownerTag, sourceTag: record.sourceTag, conversationKind: record.projection.conversationKind, contextTags: sessionContextBinding(record.projection.contextTags), firstOccurredAt: record.projection.occurredAt, lastOccurredAt: record.projection.occurredAt, eventCount: 0, createdAt: record.createdAt };
    if (session.runtime !== record.projection.sourceKind || !sessionBindingMatches(session.contextTags, record.projection)
      || session.conversationKind !== record.projection.conversationKind) throw createError('raw_session_binding_conflict', 409);
    const ids = [record.logicalMessageId, ...(record.projection.logicalMessageAliases || []).map(item => item.logicalMessageId)];
    const matched = this.findLogicalMessage(ids);
    const canonicalId = matched?.logicalMessageId || record.logicalMessageId;
    this.rawObjects.set(rawRecord.contentId, { ...rawRecord });
    const stored = structuredClone({ ...record, logicalMessageId: canonicalId });
    this.rawEventsV2.set(record.eventId, stored);
    const eventIds = [...new Set([...(matched?.eventIds || []), record.eventId])];
    const observations = eventIds.map(eventId => this.rawEventsV2.get(eventId)).filter(Boolean).map(item => ({ ...item, projection: { ...item.projection, logicalMessageId: canonicalId } }));
    const selection = selectLogicalMessage(observations);
    const logical = { ...selection, logicalMessageId: canonicalId, eventIds, updatedAt: record.createdAt };
    this.logicalMessages.set(canonicalId, logical);
    for (const id of ids) this.logicalAliases.set(id, canonicalId);
    session.eventCount += 1;
    session.firstOccurredAt = earlierTimestamp(session.firstOccurredAt, record.projection.occurredAt);
    session.lastOccurredAt = laterTimestamp(session.lastOccurredAt, record.projection.occurredAt);
    this.rawSessions.set(record.sessionId, session);
    this.auditEvents.push({ ...auditEvent, outcome: 'stored' });
    return { record: stored, duplicate: false, logical: structuredClone(logical) };
  }
  getRawEvent(id) { return this.rawEventsV2.get(id) || this.rawEvents.get(id) || null; }
  searchSessions({ ownerTags = [], query = '', limit = 20 }) {
    const needle = query.toLowerCase();
    const allowed = new Set(ownerTags);
    const participantSessions = new Set(
      [...this.rawEvents.values(), ...this.rawEventsV2.values()]
        .filter(event => allowed.has(event.ownerTag))
        .map(event => event.sessionId)
    );
    return [...this.rawSessions.values()].filter(item => participantSessions.has(item.id) && (!needle || `${item.id} ${item.runtime}`.toLowerCase().includes(needle))).sort(compareSessions).slice(0, limit);
  }
  getSession(id) { return this.rawSessions.get(id) || null; }
  listSessionEvents(id) { return [...this.rawEvents.values(), ...this.rawEventsV2.values()].filter(item => item.sessionId === id).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.eventId.localeCompare(b.eventId)); }
  rawV2Readiness() {
    try { for (const item of this.rawEventsV2.values()) validateProjectionV2(item.projection); }
    catch { return { safe: false, reason: 'literal_routing_scan_failed' }; }
    return { safe: false, reason: 'production_postgres_required', evidence: { persisted: false, v1Count: this.rawEvents.size, v2Count: this.rawEventsV2.size, aliasCount: this.logicalAliases.size } };
  }
  createIdentity(record, event, rawRecord) {
    const replay = this.identityIdempotency.get(event.idempotencyTag);
    if (replay) return { record: { ...this.identities.get(replay.identityId) }, event: { ...replay }, duplicate: true };
    const existingId = this.identitiesByTag.get(record.identityTag);
    if (existingId) return { record: { ...this.identities.get(existingId) }, event: null, duplicate: true };
    this.rawObjects.set(rawRecord.contentId, { ...rawRecord });
    this.identities.set(record.id, { ...record });
    this.identitiesByTag.set(record.identityTag, record.id);
    this.identityEvents.push({ ...event });
    this.identityIdempotency.set(event.idempotencyTag, { ...event });
    return { record: { ...record }, event: { ...event }, duplicate: false };
  }
  findIdentityOperation(idempotencyTags) {
    for (const tag of idempotencyTags) {
      const event = this.identityIdempotency.get(tag);
      if (event) return { event: { ...event }, record: { ...this.identities.get(event.identityId) } };
    }
    return null;
  }
  getIdentity(id) { const row = this.identities.get(id); return row ? { ...row } : null; }
  mutateIdentity({ sourceId, targetId = null, expectedRevision, operation, event, rawRecord }) {
    const replay = this.identityIdempotency.get(event.idempotencyTag);
    if (replay) return { record: { ...this.identities.get(replay.identityId) }, event: { ...replay }, duplicate: true };
    const source = this.identities.get(sourceId);
    if (!source) throw createError('identity_not_found', 404);
    if (source.revision !== expectedRevision) throw createError('revision_conflict', 409);
    if (operation === 'merge') {
      const target = this.identities.get(targetId);
      if (!target || target.status !== 'active' || target.scopeTag !== source.scopeTag || target.identityKind !== source.identityKind || target.id === source.id) throw createError('identity_not_found', 404);
      if (source.status !== 'active') throw createError('identity_state_conflict', 409);
      source.status = 'merged';
      source.canonicalIdentityId = target.id;
    } else if (operation === 'split') {
      if (source.status !== 'merged' || !source.canonicalIdentityId) throw createError('identity_state_conflict', 409);
      source.status = 'active';
      source.canonicalIdentityId = null;
    } else throw createError('identity_operation_invalid', 400);
    this.rawObjects.set(rawRecord.contentId, { ...rawRecord });
    source.revision += 1;
    source.updatedAt = event.createdAt;
    const storedEvent = { ...event, revision: source.revision, targetIdentityId: targetId };
    this.identityEvents.push(storedEvent);
    this.identityIdempotency.set(event.idempotencyTag, storedEvent);
    return { record: { ...source }, event: { ...storedEvent }, duplicate: false };
  }
  planRetention({ asOf, scopeTags, limit }) {
    const allowed = scopeTags ? new Set(scopeTags) : null;
    return [...this.retention.values()]
      .filter(row => row.lifecycle === 'active' && row.expiresAt <= asOf && (!allowed || allowed.has(row.scopeTag)))
      .sort((a, b) => a.expiresAt.localeCompare(b.expiresAt) || a.contentId.localeCompare(b.contentId))
      .slice(0, limit).map(row => ({ ...row }));
  }
  findRetentionOperation(idempotencyTags) {
    for (const tag of idempotencyTags) if (this.retentionOperations.has(tag)) return { ...this.retentionOperations.get(tag) };
    return null;
  }
  applyRetention({ contentIds, expectedPlanAsOf, reason, createdAt, idFactory, allowedScopeTags = null, operation }) {
    const replay = this.retentionOperations.get(operation.idempotencyTag);
    if (replay) return { response: structuredClone(replay.response), requestDigest: replay.requestDigest, duplicate: true };
    const results = [];
    const allowed = allowedScopeTags ? new Set(allowedScopeTags) : null;
    for (const contentId of contentIds) {
      const row = this.retention.get(contentId);
      if (!row || (allowed && !allowed.has(row.scopeTag)) || row.lifecycle !== 'active' || (reason === 'retention_expired' && row.expiresAt > expectedPlanAsOf)) continue;
      row.lifecycle = reason === 'retention_expired' ? 'expired' : reason;
      row.revision += 1;
      row.updatedAt = createdAt;
      const tombstone = retentionTombstone({ id: idFactory(), row, reason, createdAt });
      this.retentionTombstones.set(tombstone.id, tombstone);
      for (const proposal of this.proposals.values()) {
        if (proposal.contentId === contentId && proposal.scopeTag === row.scopeTag && !['revoked', 'rejected'].includes(proposal.status)) proposal.status = 'revoked';
      }
      const referenced = [...this.proposals.values()].some(proposal => proposal.contentId === contentId && !['revoked', 'rejected'].includes(proposal.status));
      results.push({ contentId, lifecycle: row.lifecycle, tombstoneId: tombstone.id, gcCandidate: !referenced });
    }
    const response = { appliedAt: createdAt, physicalDeletionPerformed: false, results };
    this.retentionOperations.set(operation.idempotencyTag, { ...operation, response: structuredClone(response) });
    return { response, requestDigest: operation.requestDigest, duplicate: false };
  }
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

function pageBinding(value) { return crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex'); }
function decodePageCursor(cursor, binding) {
  if (!cursor) return 0;
  let value;
  try { value = JSON.parse(Buffer.from(String(cursor), 'base64url').toString('utf8')); } catch { throw createError('invalid_request', 400); }
  if (!value || Object.keys(value).sort().join('\0') !== 'binding\0offset' || value.binding !== binding || !Number.isSafeInteger(value.offset) || value.offset < 0 || value.offset > 10000) throw createError('invalid_request', 400);
  return value.offset;
}
function encodePageCursor(offset, binding) { return Buffer.from(JSON.stringify({ binding, offset }), 'utf8').toString('base64url'); }
function inTimeWindow(timestamp, from, to) {
  if (!timestamp) return !from && !to;
  const value = Date.parse(timestamp);
  return (!from || value >= Date.parse(from)) && (!to || value <= Date.parse(to));
}

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
      CREATE TABLE IF NOT EXISTS raw_sessions_v1 (session_id TEXT PRIMARY KEY, runtime TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, conversation_kind TEXT, context_tags_json TEXT, session_binding_json TEXT, first_occurred_at TEXT, last_occurred_at TEXT, event_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS raw_events_v1 (event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES raw_sessions_v1(session_id), content_id TEXT NOT NULL REFERENCES raw_objects_v2(content_id), payload_digest TEXT NOT NULL, projection_json TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS raw_events_v2 (event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES raw_sessions_v1(session_id), logical_message_id TEXT NOT NULL, content_id TEXT NOT NULL REFERENCES raw_objects_v2(content_id), payload_digest TEXT NOT NULL, projection_json TEXT NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS raw_events_v2_session_created_idx ON raw_events_v2(session_id,created_at,event_id);
      CREATE INDEX IF NOT EXISTS raw_events_v2_owner_session_idx ON raw_events_v2(owner_tag,session_id);
      CREATE TABLE IF NOT EXISTS logical_messages_v2 (logical_message_id TEXT PRIMARY KEY, preferred_observation_id TEXT NOT NULL, payload_conflict INTEGER NOT NULL, tombstoned INTEGER NOT NULL, selection_version TEXT NOT NULL, event_ids_json TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS logical_message_aliases_v2 (alias_id TEXT PRIMARY KEY, logical_message_id TEXT NOT NULL REFERENCES logical_messages_v2(logical_message_id));
      CREATE INDEX IF NOT EXISTS raw_sessions_v1_owner_tag_idx ON raw_sessions_v1(owner_tag,last_occurred_at);
      CREATE INDEX IF NOT EXISTS raw_events_v1_session_created_idx ON raw_events_v1(session_id,created_at,event_id);
      CREATE INDEX IF NOT EXISTS raw_events_v1_owner_session_idx ON raw_events_v1(owner_tag,session_id);
      CREATE TABLE IF NOT EXISTS audit_events_v2 (id TEXT PRIMARY KEY, ts TEXT NOT NULL, actor_tag TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, request_id TEXT, target_id TEXT, scope_tag TEXT, details_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS identity_records_v2 (id TEXT PRIMARY KEY, identity_tag TEXT NOT NULL UNIQUE, identity_kind TEXT NOT NULL CHECK(identity_kind IN ('agent','person','relationship','room','domain','shared')), scope_tag TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','merged','split','revoked')), canonical_identity_id TEXT REFERENCES identity_records_v2(id), revision INTEGER NOT NULL CHECK(revision >= 1), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS identity_events_v2 (id TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES identity_records_v2(id), revision INTEGER NOT NULL CHECK(revision >= 1), operation TEXT NOT NULL CHECK(operation IN ('create','merge','split','revoke')), target_identity_id TEXT REFERENCES identity_records_v2(id), evidence_content_id TEXT NOT NULL REFERENCES raw_objects_v2(content_id), evidence_strength TEXT NOT NULL CHECK(evidence_strength IN ('strong','weak')), automatic INTEGER NOT NULL CHECK(automatic IN (0,1)), actor_tag TEXT NOT NULL, idempotency_tag TEXT NOT NULL UNIQUE, response_json TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(identity_id,revision));
      CREATE TABLE IF NOT EXISTS raw_retention_v2 (content_id TEXT PRIMARY KEY REFERENCES raw_objects_v2(content_id), content_checksum TEXT NOT NULL, scope_tag TEXT NOT NULL, source_pointer_tag TEXT, original_created_at TEXT NOT NULL, expires_at TEXT NOT NULL, lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','revoked','forgotten','expired')), revision INTEGER NOT NULL CHECK(revision >= 1), updated_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS raw_retention_v2_expiry_idx ON raw_retention_v2(lifecycle, expires_at);
      CREATE TABLE IF NOT EXISTS retention_tombstones_v2 (id TEXT PRIMARY KEY, content_id TEXT NOT NULL, content_checksum TEXT NOT NULL, source_pointer_tag TEXT, reason_code TEXT NOT NULL CHECK(reason_code IN ('retention_expired','revoked','forgotten')), original_created_at TEXT NOT NULL, expired_at TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS retention_operations_v2 (id TEXT PRIMARY KEY, idempotency_tag TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL, response_json TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS raw_projection_v2_migration_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, verified_at TEXT NOT NULL, v1_count INTEGER NOT NULL, v2_count INTEGER NOT NULL, alias_count INTEGER NOT NULL, alias_orphan_count INTEGER NOT NULL, legacy_field_count INTEGER NOT NULL, literal_scan_count INTEGER NOT NULL, backend TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS curator_receipt_state_v1 (proposal_id TEXT PRIMARY KEY REFERENCES fabric_proposals(id), status TEXT NOT NULL, decision_json TEXT NOT NULL, apply_json TEXT);
    `);
    const sessionColumns = new Set(this.db.prepare('PRAGMA table_info(raw_sessions_v1)').all().map(row => row.name));
    if (!sessionColumns.has('conversation_kind')) this.db.exec('ALTER TABLE raw_sessions_v1 ADD COLUMN conversation_kind TEXT');
    if (!sessionColumns.has('context_tags_json')) this.db.exec('ALTER TABLE raw_sessions_v1 ADD COLUMN context_tags_json TEXT');
    if (!sessionColumns.has('session_binding_json')) this.db.exec('ALTER TABLE raw_sessions_v1 ADD COLUMN session_binding_json TEXT');
    const migrateSessionBindings = this.db.transaction(() => {
      const rows = this.db.prepare('SELECT session_id,context_tags_json FROM raw_sessions_v1 WHERE context_tags_json IS NOT NULL AND session_binding_json IS NULL').all();
      const update = this.db.prepare('UPDATE raw_sessions_v1 SET session_binding_json=? WHERE session_id=? AND session_binding_json IS NULL');
      for (const row of rows) {
        let binding;
        try { binding = sessionContextBinding(JSON.parse(row.context_tags_json)); }
        catch { throw createError('raw_session_binding_migration_invalid', 500); }
        update.run(JSON.stringify(binding), row.session_id);
      }
    });
    migrateSessionBindings();
    this.selectProposal = this.db.prepare('SELECT * FROM fabric_proposals WHERE id = ?');
    this.selectProposalByTags = this.db.prepare('SELECT * FROM fabric_proposals WHERE owner_tag = ? AND idempotency_tag = ?');
    this.insertBoth = this.db.transaction((record, raw) => {
      const existing = this.selectProposalByTags.get(record.ownerTag, record.idempotencyTag);
      if (existing) return { record: this.mapProposal(existing), duplicate: true };
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(raw);
      if (raw.retention) this.db.prepare('INSERT OR IGNORE INTO raw_retention_v2(content_id,content_checksum,scope_tag,source_pointer_tag,original_created_at,expires_at,lifecycle,revision,updated_at) VALUES (@contentId,@contentChecksum,@scopeTag,@sourcePointerTag,@originalCreatedAt,@expiresAt,@lifecycle,@revision,@updatedAt)').run(raw.retention);
      this.db.prepare('INSERT INTO fabric_proposals(id,owner_tag,scope_tag,status,content_id,idempotency_tag,source_tag,created_at) VALUES (@id,@ownerTag,@scopeTag,@status,@contentId,@idempotencyTag,@sourceTag,@createdAt)').run(record);
      return { record, duplicate: false };
    });
    this.insertAudit = this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (@id,@ts,@actorTag,@action,@outcome,@requestId,@targetId,@scopeTag,@detailsJson)');
    this.recordCuratorReceiptTransaction = this.db.transaction((receipt, auditEvent) => {
      const proposal = this.db.prepare('SELECT * FROM fabric_proposals WHERE id=?').get(receipt.proposalId);
      if (!proposal) throw createError('receipt_proposal_unverified', 409);
      const current = this.getCuratorReceipt(receipt.proposalId);
      let duplicate = false;
      if (receipt.kind === 'decision') {
        if (current) {
          if (canonicalJson(current.decision) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
          duplicate = true;
        } else {
          this.db.prepare('INSERT INTO curator_receipt_state_v1(proposal_id,status,decision_json,apply_json) VALUES (?,?,?,NULL)').run(receipt.proposalId, receipt.status, JSON.stringify(receipt));
          this.db.prepare('UPDATE fabric_proposals SET status=? WHERE id=?').run(receipt.status === 'rejected' ? 'rejected' : 'review', receipt.proposalId);
        }
      } else {
        if (!current?.decision || current.decision.status !== 'approved_pending_apply') throw createError('receipt_transition_invalid', 409);
        if (current.apply) {
          if (canonicalJson(current.apply) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
          duplicate = true;
        } else {
          this.db.prepare("UPDATE curator_receipt_state_v1 SET status='promoted',apply_json=? WHERE proposal_id=? AND apply_json IS NULL").run(JSON.stringify(receipt), receipt.proposalId);
          this.db.prepare("UPDATE fabric_proposals SET status='promoted' WHERE id=?").run(receipt.proposalId);
        }
      }
      this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (?,?,?,?,?,?,?,?,?)').run(auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, duplicate ? 'duplicate' : 'recorded', auditEvent.requestId || null, receipt.proposalId, null, JSON.stringify(auditEvent.details || {}));
      return { ...this.getCuratorReceipt(receipt.proposalId), duplicate };
    });
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
    this.insertRawEventV2 = this.db.transaction((record, raw, auditEvent) => {
      const existing = this.db.prepare('SELECT * FROM raw_events_v2 WHERE event_id=?').get(record.eventId) || this.db.prepare('SELECT * FROM raw_events_v1 WHERE event_id=?').get(record.eventId);
      if (existing) {
        this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (?,?,?,?,?,?,?,?,?)').run(auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, 'duplicate', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {}));
        return { record: this.mapRawEvent(existing), duplicate: true, logical: this.findLogicalMessage([record.logicalMessageId]) };
      }
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(raw);
      const sessionBinding = sessionContextBinding(record.projection.contextTags);
      this.db.prepare('INSERT OR IGNORE INTO raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,context_tags_json,session_binding_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES (?,?,?,?,?,?,?,?,?,0,?)').run(record.sessionId, record.projection.sourceKind, record.ownerTag, record.sourceTag, record.projection.conversationKind, JSON.stringify(record.projection.contextTags), JSON.stringify(sessionBinding), record.projection.occurredAt, record.projection.occurredAt, record.createdAt);
      const bound = this.db.prepare('SELECT * FROM raw_sessions_v1 WHERE session_id=?').get(record.sessionId);
      const boundBinding = bound.session_binding_json ? JSON.parse(bound.session_binding_json) : null;
      if (bound.runtime !== record.projection.sourceKind || bound.conversation_kind !== record.projection.conversationKind
        || !sessionBindingMatches(boundBinding, record.projection)) throw createError('raw_session_binding_conflict', 409);
      const ids = [record.logicalMessageId, ...record.projection.logicalMessageAliases.map(item => item.logicalMessageId)];
      const matched = this.findLogicalMessage(ids);
      const canonicalId = matched?.logicalMessageId || record.logicalMessageId;
      this.db.prepare('INSERT INTO raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(record.eventId, record.sessionId, canonicalId, record.contentId, record.payloadDigest, JSON.stringify(record.projection), record.ownerTag, record.sourceTag, record.createdAt);
      const eventIds = [...new Set([...(matched?.eventIds || []), record.eventId])];
      const observations = eventIds.map(id => this.mapRawEvent(this.db.prepare('SELECT * FROM raw_events_v2 WHERE event_id=?').get(id))).filter(Boolean).map(item => ({ ...item, projection: { ...item.projection, logicalMessageId: canonicalId } }));
      const selection = selectLogicalMessage(observations);
      const logical = { ...selection, logicalMessageId: canonicalId, eventIds, updatedAt: record.createdAt };
      this.db.prepare('INSERT INTO logical_messages_v2(logical_message_id,preferred_observation_id,payload_conflict,tombstoned,selection_version,event_ids_json,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(logical_message_id) DO UPDATE SET preferred_observation_id=excluded.preferred_observation_id,payload_conflict=excluded.payload_conflict,tombstoned=excluded.tombstoned,selection_version=excluded.selection_version,event_ids_json=excluded.event_ids_json,updated_at=excluded.updated_at').run(canonicalId, logical.preferredObservationId, logical.payloadConflict ? 1 : 0, logical.tombstoned ? 1 : 0, logical.selectionVersion, JSON.stringify(eventIds), record.createdAt);
      for (const id of ids) this.db.prepare('INSERT INTO logical_message_aliases_v2(alias_id,logical_message_id) VALUES (?,?) ON CONFLICT(alias_id) DO UPDATE SET logical_message_id=excluded.logical_message_id').run(id, canonicalId);
      this.db.prepare("UPDATE raw_sessions_v1 SET event_count=event_count+1,first_occurred_at=CASE WHEN ? IS NULL THEN first_occurred_at WHEN first_occurred_at IS NULL OR julianday(?)<julianday(first_occurred_at) THEN ? ELSE first_occurred_at END,last_occurred_at=CASE WHEN ? IS NULL THEN last_occurred_at WHEN last_occurred_at IS NULL OR julianday(?)>julianday(last_occurred_at) THEN ? ELSE last_occurred_at END WHERE session_id=?").run(record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.projection.occurredAt, record.sessionId);
      this.db.prepare('INSERT INTO audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES (?,?,?,?,?,?,?,?,?)').run(auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, 'stored', auditEvent.requestId || null, auditEvent.targetId, null, JSON.stringify(auditEvent.details || {}));
      return { record: { ...record, logicalMessageId: canonicalId }, duplicate: false, logical };
    });
    this.selectIdentity = this.db.prepare('SELECT * FROM identity_records_v2 WHERE id = ?');
    this.selectIdentityEventByIdempotency = this.db.prepare('SELECT * FROM identity_events_v2 WHERE idempotency_tag = ?');
    this.createIdentityTransaction = this.db.transaction((record, event, raw) => {
      const replay = this.selectIdentityEventByIdempotency.get(event.idempotencyTag);
      if (replay) return { record: this.mapIdentity(this.selectIdentity.get(replay.identity_id)), event: this.mapIdentityEvent(replay), duplicate: true };
      const existing = this.db.prepare('SELECT * FROM identity_records_v2 WHERE identity_tag=?').get(record.identityTag);
      if (existing) return { record: this.mapIdentity(existing), event: null, duplicate: true };
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(raw);
      this.db.prepare('INSERT INTO identity_records_v2(id,identity_tag,identity_kind,scope_tag,status,canonical_identity_id,revision,created_at,updated_at) VALUES (@id,@identityTag,@identityKind,@scopeTag,@status,@canonicalIdentityId,@revision,@createdAt,@updatedAt)').run(record);
      this.db.prepare('INSERT INTO identity_events_v2(id,identity_id,revision,operation,target_identity_id,evidence_content_id,evidence_strength,automatic,actor_tag,idempotency_tag,response_json,created_at) VALUES (@id,@identityId,@revision,@operation,@targetIdentityId,@evidenceContentId,@evidenceStrength,@automatic,@actorTag,@idempotencyTag,@responseJson,@createdAt)').run({ ...event, automatic: event.automatic ? 1 : 0, responseJson: JSON.stringify(event.response) });
      return { record, event, duplicate: false };
    });
    this.mutateIdentityTransaction = this.db.transaction(({ sourceId, targetId, expectedRevision, operation, event, rawRecord }) => {
      const replay = this.selectIdentityEventByIdempotency.get(event.idempotencyTag);
      if (replay) return { record: this.mapIdentity(this.selectIdentity.get(replay.identity_id)), event: this.mapIdentityEvent(replay), duplicate: true };
      const sourceRow = this.selectIdentity.get(sourceId);
      if (!sourceRow) throw createError('identity_not_found', 404);
      const source = this.mapIdentity(sourceRow);
      if (source.revision !== expectedRevision) throw createError('revision_conflict', 409);
      let status;
      let canonicalIdentityId;
      if (operation === 'merge') {
        const target = this.mapIdentity(this.selectIdentity.get(targetId));
        if (!target || target.status !== 'active' || target.scopeTag !== source.scopeTag || target.identityKind !== source.identityKind || target.id === source.id) throw createError('identity_not_found', 404);
        if (source.status !== 'active') throw createError('identity_state_conflict', 409);
        status = 'merged'; canonicalIdentityId = target.id;
      } else if (operation === 'split') {
        if (source.status !== 'merged' || !source.canonicalIdentityId) throw createError('identity_state_conflict', 409);
        status = 'active'; canonicalIdentityId = null;
      } else throw createError('identity_operation_invalid', 400);
      this.db.prepare('INSERT OR IGNORE INTO raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES (@contentId,@mediaType,@byteLength,@storageRef,@createdAt)').run(rawRecord);
      const revision = source.revision + 1;
      const changed = this.db.prepare('UPDATE identity_records_v2 SET status=?, canonical_identity_id=?, revision=?, updated_at=? WHERE id=? AND revision=?').run(status, canonicalIdentityId, revision, event.createdAt, sourceId, expectedRevision);
      if (changed.changes !== 1) throw createError('revision_conflict', 409);
      const storedEvent = { ...event, revision, targetIdentityId: targetId, automatic: event.automatic ? 1 : 0 };
      this.db.prepare('INSERT INTO identity_events_v2(id,identity_id,revision,operation,target_identity_id,evidence_content_id,evidence_strength,automatic,actor_tag,idempotency_tag,response_json,created_at) VALUES (@id,@identityId,@revision,@operation,@targetIdentityId,@evidenceContentId,@evidenceStrength,@automatic,@actorTag,@idempotencyTag,@responseJson,@createdAt)').run({ ...storedEvent, responseJson: JSON.stringify(storedEvent.response) });
      return { record: this.mapIdentity(this.selectIdentity.get(sourceId)), event: storedEvent, duplicate: false };
    });
    this.selectRetentionOperation = this.db.prepare('SELECT * FROM retention_operations_v2 WHERE idempotency_tag=?');
    this.applyRetentionTransaction = this.db.transaction(({ contentIds, expectedPlanAsOf, reason, createdAt, idFactory, allowedScopeTags = null, operation }) => {
      const replay = this.selectRetentionOperation.get(operation.idempotencyTag);
      if (replay) return { response: JSON.parse(replay.response_json), requestDigest: replay.request_digest, duplicate: true };
      const results = [];
      for (const contentId of contentIds) {
        const row = this.db.prepare('SELECT * FROM raw_retention_v2 WHERE content_id=?').get(contentId);
        if (!row || (allowedScopeTags && !allowedScopeTags.includes(row.scope_tag)) || row.lifecycle !== 'active' || (reason === 'retention_expired' && row.expires_at > expectedPlanAsOf)) continue;
        const lifecycle = reason === 'retention_expired' ? 'expired' : reason;
        const revision = row.revision + 1;
        const changed = this.db.prepare("UPDATE raw_retention_v2 SET lifecycle=?, revision=?, updated_at=? WHERE content_id=? AND revision=? AND lifecycle='active'").run(lifecycle, revision, createdAt, contentId, row.revision);
        if (changed.changes !== 1) throw createError('revision_conflict', 409);
        const tombstone = retentionTombstone({ id: idFactory(), row: this.mapRetention({ ...row, lifecycle, revision, updated_at: createdAt }), reason, createdAt });
        this.db.prepare('INSERT INTO retention_tombstones_v2(id,content_id,content_checksum,source_pointer_tag,reason_code,original_created_at,expired_at,created_at) VALUES (@id,@contentId,@contentChecksum,@sourcePointerTag,@reasonCode,@originalCreatedAt,@expiredAt,@createdAt)').run(tombstone);
        this.db.prepare("UPDATE fabric_proposals SET status='revoked' WHERE content_id=? AND scope_tag=? AND status NOT IN ('revoked','rejected')").run(contentId, row.scope_tag);
        const referenced = this.db.prepare("SELECT 1 FROM fabric_proposals WHERE content_id=? AND status NOT IN ('revoked','rejected') LIMIT 1").get(contentId);
        results.push({ contentId, lifecycle, tombstoneId: tombstone.id, gcCandidate: !referenced });
      }
      const response = { appliedAt: createdAt, physicalDeletionPerformed: false, results };
      this.db.prepare('INSERT INTO retention_operations_v2(id,idempotency_tag,request_digest,response_json,created_at) VALUES (?,?,?,?,?)').run(operation.id, operation.idempotencyTag, operation.requestDigest, JSON.stringify(response), createdAt);
      return { response, requestDigest: operation.requestDigest, duplicate: false };
    });
  }
  mapIdentity(row) { return row ? { id: row.id, identityTag: row.identity_tag, identityKind: row.identity_kind, scopeTag: row.scope_tag, status: row.status, canonicalIdentityId: row.canonical_identity_id, revision: row.revision, createdAt: row.created_at, updatedAt: row.updated_at } : null; }
  mapIdentityEvent(row) { return row ? { ...row, evidenceContentId: row.evidence_content_id, response: JSON.parse(row.response_json) } : null; }
  mapRetention(row) { return row ? { contentId: row.content_id, contentChecksum: row.content_checksum, scopeTag: row.scope_tag, sourcePointerTag: row.source_pointer_tag, originalCreatedAt: row.original_created_at, expiresAt: row.expires_at, lifecycle: row.lifecycle, revision: row.revision, updatedAt: row.updated_at } : null; }
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
  recallItemActive(refs, scopeTags) {
    if (refs.proposalId) {
      const row = this.selectProposal.get(refs.proposalId);
      if (!row || !scopeTags.includes(row.scope_tag) || ['revoked', 'rejected'].includes(row.status)) return false;
    }
    if (refs.contentId) {
      const row = this.db.prepare('SELECT * FROM raw_retention_v2 WHERE content_id=?').get(refs.contentId);
      if (!row || !scopeTags.includes(row.scope_tag) || row.lifecycle !== 'active') return false;
    }
    if (refs.identityId) {
      const row = this.selectIdentity.get(refs.identityId);
      if (!row || !scopeTags.includes(row.scope_tag) || row.status !== 'active') return false;
    }
    return true;
  }
  appendAudit(event) {
    this.insertAudit.run({ id: event.id, ts: event.ts, actorTag: event.actorTag, action: event.action, outcome: event.outcome, requestId: event.requestId || null, targetId: event.targetId || null, scopeTag: event.scopeTag || null, detailsJson: JSON.stringify(event.details || {}) });
  }
  recordCuratorReceipt(receipt, auditEvent) { return this.recordCuratorReceiptTransaction(receipt, auditEvent); }
  getCuratorReceipt(proposalId) { const row = this.db.prepare('SELECT * FROM curator_receipt_state_v1 WHERE proposal_id=?').get(proposalId); return row ? { proposalId: row.proposal_id, status: row.status, decision: JSON.parse(row.decision_json), apply: row.apply_json ? JSON.parse(row.apply_json) : null } : null; }
  listCuratorReceipts() { return this.db.prepare('SELECT * FROM curator_receipt_state_v1 ORDER BY proposal_id').all().map(row => ({ proposalId: row.proposal_id, status: row.status, decision: JSON.parse(row.decision_json), apply: row.apply_json ? JSON.parse(row.apply_json) : null })); }
  mapRawEvent(row) { return row ? { eventId: row.event_id, sessionId: row.session_id, logicalMessageId: row.logical_message_id || null, contentId: row.content_id, payloadDigest: row.payload_digest, projection: JSON.parse(row.projection_json), ownerTag: row.owner_tag, sourceTag: row.source_tag, createdAt: row.created_at } : null; }
  ingestRawEvent(record, rawRecord, auditEvent) { return this.insertRawEvent(record, rawRecord, auditEvent); }
  ingestRawEventV2(record, rawRecord, auditEvent) { return this.insertRawEventV2(record, rawRecord, auditEvent); }
  findLogicalMessage(ids) {
    for (const id of ids) {
      const alias = this.db.prepare('SELECT logical_message_id FROM logical_message_aliases_v2 WHERE alias_id=?').get(id);
      const row = this.db.prepare('SELECT * FROM logical_messages_v2 WHERE logical_message_id=?').get(alias?.logical_message_id || id);
      if (row) return { logicalMessageId: row.logical_message_id, preferredObservationId: row.preferred_observation_id, payloadConflict: Boolean(row.payload_conflict), tombstoned: Boolean(row.tombstoned), selectionVersion: row.selection_version, eventIds: JSON.parse(row.event_ids_json), updatedAt: row.updated_at };
    }
    return null;
  }
  getRawEvent(id) { return this.mapRawEvent(this.db.prepare('SELECT * FROM raw_events_v2 WHERE event_id=?').get(id) || this.db.prepare('SELECT * FROM raw_events_v1 WHERE event_id=?').get(id)); }
  mapSession(row) { return row ? { id: row.session_id, runtime: row.runtime, ownerTag: row.owner_tag, sourceTag: row.source_tag, conversationKind: row.conversation_kind || null, contextTags: row.session_binding_json ? JSON.parse(row.session_binding_json) : null, firstOccurredAt: row.first_occurred_at, lastOccurredAt: row.last_occurred_at, eventCount: row.event_count, createdAt: row.created_at } : null; }
  searchSessions({ ownerTags = [], query = '', limit = 20 }) {
    if (!ownerTags.length) return [];
    const pattern = escapedLike(query);
    const placeholders = ownerTags.map(() => '?').join(',');
    return this.db.prepare(`SELECT s.* FROM raw_sessions_v1 s WHERE (EXISTS (SELECT 1 FROM raw_events_v1 e WHERE e.session_id=s.session_id AND e.owner_tag IN (${placeholders})) OR EXISTS (SELECT 1 FROM raw_events_v2 e WHERE e.session_id=s.session_id AND e.owner_tag IN (${placeholders}))) AND (lower(s.session_id) LIKE lower(?) ESCAPE '\\' OR lower(s.runtime) LIKE lower(?) ESCAPE '\\') ORDER BY CASE WHEN s.last_occurred_at IS NULL THEN 1 ELSE 0 END,s.last_occurred_at DESC,s.created_at DESC,s.session_id ASC LIMIT ?`).all(...ownerTags, ...ownerTags, pattern, pattern, limit).map(row => this.mapSession(row));
  }
  getSession(id) { return this.mapSession(this.db.prepare('SELECT * FROM raw_sessions_v1 WHERE session_id=?').get(id)); }
  listSessionEvents(id) { return [...this.db.prepare('SELECT * FROM raw_events_v1 WHERE session_id=?').all(id), ...this.db.prepare('SELECT * FROM raw_events_v2 WHERE session_id=?').all(id)].map(row => this.mapRawEvent(row)).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.eventId.localeCompare(b.eventId)); }
  rawV2Readiness() {
    let counts;
    try {
      const rows = this.db.prepare('SELECT projection_json FROM raw_events_v2').all();
      for (const row of rows) validateProjectionV2(JSON.parse(row.projection_json));
      counts = {
        v1Count: this.db.prepare('SELECT count(*) AS n FROM raw_events_v1').get().n,
        v2Count: rows.length,
        aliasCount: this.db.prepare('SELECT count(*) AS n FROM logical_message_aliases_v2').get().n,
        aliasOrphanCount: this.db.prepare('SELECT count(*) AS n FROM logical_message_aliases_v2 a LEFT JOIN logical_messages_v2 l ON l.logical_message_id=a.logical_message_id WHERE l.logical_message_id IS NULL').get().n,
        legacyFieldCount: rows.filter(row => /\"(?:nativeRoomId|nativePersonId|roomId|personId)\"\s*:/.test(row.projection_json)).length,
        literalScanCount: rows.filter(row => !validateProjectionV2(JSON.parse(row.projection_json))).length
      };
      this.db.prepare('INSERT INTO raw_projection_v2_migration_state(singleton,schema_version,verified_at,v1_count,v2_count,alias_count,alias_orphan_count,legacy_field_count,literal_scan_count,backend) VALUES (1,5,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,verified_at=excluded.verified_at,v1_count=excluded.v1_count,v2_count=excluded.v2_count,alias_count=excluded.alias_count,alias_orphan_count=excluded.alias_orphan_count,legacy_field_count=excluded.legacy_field_count,literal_scan_count=excluded.literal_scan_count,backend=excluded.backend').run(new Date().toISOString(), counts.v1Count, counts.v2Count, counts.aliasCount, counts.aliasOrphanCount, counts.legacyFieldCount, counts.literalScanCount, 'sqlite');
    }
    catch { return { safe: false, reason: 'literal_routing_scan_failed' }; }
    return { safe: false, reason: 'production_postgres_required', evidence: { persisted: true, ...counts } };
  }
  createIdentity(record, event, rawRecord) { return this.createIdentityTransaction(record, event, rawRecord); }
  findIdentityOperation(idempotencyTags) {
    for (const tag of idempotencyTags) {
      const event = this.selectIdentityEventByIdempotency.get(tag);
      if (event) return { event: this.mapIdentityEvent(event), record: this.mapIdentity(this.selectIdentity.get(event.identity_id)) };
    }
    return null;
  }
  getIdentity(id) { return this.mapIdentity(this.selectIdentity.get(id)); }
  mutateIdentity(input) { return this.mutateIdentityTransaction(input); }
  planRetention({ asOf, scopeTags, limit }) {
    const rows = scopeTags
      ? this.db.prepare(`SELECT * FROM raw_retention_v2 WHERE lifecycle='active' AND expires_at<=? AND scope_tag IN (${scopeTags.map(() => '?').join(',')}) ORDER BY expires_at,content_id LIMIT ?`).all(asOf, ...scopeTags, limit)
      : this.db.prepare("SELECT * FROM raw_retention_v2 WHERE lifecycle='active' AND expires_at<=? ORDER BY expires_at,content_id LIMIT ?").all(asOf, limit);
    return rows.map(row => this.mapRetention(row));
  }
  findRetentionOperation(idempotencyTags) {
    for (const tag of idempotencyTags) {
      const row = this.selectRetentionOperation.get(tag);
      if (row) return { response: JSON.parse(row.response_json), requestDigest: row.request_digest, idempotencyTag: row.idempotency_tag };
    }
    return null;
  }
  applyRetention(input) { return this.applyRetentionTransaction(input); }
  status() {
    return { backend: 'sqlite', rawObjects: this.db.prepare('SELECT count(*) AS count FROM raw_objects_v2').get().count, queuedProposals: this.db.prepare("SELECT count(*) AS count FROM fabric_proposals WHERE status='queued'").get().count, auditEvents: this.db.prepare('SELECT count(*) AS count FROM audit_events_v2').get().count };
  }
  close() { this.db.close(); }
}

const POSTGRES_SCHEMA = 'agent_memory_fabric';
const POSTGRES_SCHEMA_VERSION = 7;
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
    conversation_kind TEXT, context_tags_json JSONB, session_binding_json JSONB, first_occurred_at TIMESTAMPTZ, last_occurred_at TIMESTAMPTZ, event_count BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL
  )`,
  `ALTER TABLE ${POSTGRES_SCHEMA}.raw_sessions_v1 ADD COLUMN IF NOT EXISTS conversation_kind TEXT`,
  `ALTER TABLE ${POSTGRES_SCHEMA}.raw_sessions_v1 ADD COLUMN IF NOT EXISTS context_tags_json JSONB`,
  `ALTER TABLE ${POSTGRES_SCHEMA}.raw_sessions_v1 ADD COLUMN IF NOT EXISTS session_binding_json JSONB`,
  `UPDATE ${POSTGRES_SCHEMA}.raw_sessions_v1
    SET session_binding_json=jsonb_strip_nulls(jsonb_build_object(
      'conversation',context_tags_json->'conversation',
      'room',context_tags_json->'room',
      'thread',context_tags_json->'thread'))
    WHERE session_binding_json IS NULL AND context_tags_json IS NOT NULL`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_events_v1 (
    event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_sessions_v1(session_id),
    content_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id), payload_digest TEXT NOT NULL,
    projection_json JSONB NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_events_v2 (
    event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_sessions_v1(session_id),
    logical_message_id TEXT NOT NULL, content_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id),
    payload_digest TEXT NOT NULL, projection_json JSONB NOT NULL, owner_tag TEXT NOT NULL, source_tag TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS raw_events_v2_session_created_idx ON ${POSTGRES_SCHEMA}.raw_events_v2(session_id,created_at,event_id)`,
  `CREATE INDEX IF NOT EXISTS raw_events_v2_owner_session_idx ON ${POSTGRES_SCHEMA}.raw_events_v2(owner_tag,session_id)`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.logical_messages_v2 (
    logical_message_id TEXT PRIMARY KEY, preferred_observation_id TEXT NOT NULL, payload_conflict BOOLEAN NOT NULL,
    tombstoned BOOLEAN NOT NULL, selection_version TEXT NOT NULL, event_ids JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.logical_message_aliases_v2 (
    alias_id TEXT PRIMARY KEY, logical_message_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.logical_messages_v2(logical_message_id)
  )`,
  `CREATE INDEX IF NOT EXISTS raw_sessions_v1_owner_tag_idx ON ${POSTGRES_SCHEMA}.raw_sessions_v1(owner_tag,last_occurred_at)`,
  `CREATE INDEX IF NOT EXISTS raw_events_v1_session_created_idx ON ${POSTGRES_SCHEMA}.raw_events_v1(session_id,created_at,event_id)`,
  `CREATE INDEX IF NOT EXISTS raw_events_v1_owner_session_idx ON ${POSTGRES_SCHEMA}.raw_events_v1(owner_tag,session_id)`,
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
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.identity_records_v2 (
    id TEXT PRIMARY KEY,
    identity_tag TEXT NOT NULL UNIQUE,
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('agent','person','relationship','room','domain','shared')),
    scope_tag TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','merged','split','revoked')),
    canonical_identity_id TEXT REFERENCES ${POSTGRES_SCHEMA}.identity_records_v2(id),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.identity_events_v2 (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.identity_records_v2(id),
    revision BIGINT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('create','merge','split','revoke')),
    target_identity_id TEXT REFERENCES ${POSTGRES_SCHEMA}.identity_records_v2(id),
    evidence_content_id TEXT NOT NULL REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id),
    evidence_strength TEXT NOT NULL CHECK (evidence_strength IN ('strong','weak')),
    automatic BOOLEAN NOT NULL,
    actor_tag TEXT NOT NULL,
    idempotency_tag TEXT NOT NULL UNIQUE,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(identity_id, revision)
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_retention_v2 (
    content_id TEXT PRIMARY KEY REFERENCES ${POSTGRES_SCHEMA}.raw_objects_v2(content_id),
    content_checksum TEXT NOT NULL,
    scope_tag TEXT NOT NULL,
    source_pointer_tag TEXT,
    original_created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active','revoked','forgotten','expired')),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    updated_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS raw_retention_v2_expiry_idx ON ${POSTGRES_SCHEMA}.raw_retention_v2(lifecycle, expires_at)`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.retention_tombstones_v2 (
    id TEXT PRIMARY KEY,
    content_id TEXT NOT NULL,
    content_checksum TEXT NOT NULL,
    source_pointer_tag TEXT,
    reason_code TEXT NOT NULL,
    original_created_at TIMESTAMPTZ NOT NULL,
    expired_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.retention_operations_v2 (
    id TEXT PRIMARY KEY,
    idempotency_tag TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    response_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.raw_projection_v2_migration_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, verified_at TIMESTAMPTZ NOT NULL,
    v1_count BIGINT NOT NULL, v2_count BIGINT NOT NULL, alias_count BIGINT NOT NULL, alias_orphan_count BIGINT NOT NULL,
    legacy_field_count BIGINT NOT NULL, literal_scan_count BIGINT NOT NULL, backend TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ${POSTGRES_SCHEMA}.curator_receipt_state_v1 (
    proposal_id TEXT PRIMARY KEY REFERENCES ${POSTGRES_SCHEMA}.fabric_proposals(id), status TEXT NOT NULL,
    decision_json JSONB NOT NULL, apply_json JSONB
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
  return row ? { eventId: row.event_id, sessionId: row.session_id, logicalMessageId: row.logical_message_id || null, contentId: row.content_id, payloadDigest: row.payload_digest, projection: typeof row.projection_json === 'string' ? JSON.parse(row.projection_json) : row.projection_json, ownerTag: row.owner_tag, sourceTag: row.source_tag, createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at) } : null;
}

function mapPostgresSession(row) {
  return row ? { id: row.session_id, runtime: row.runtime, ownerTag: row.owner_tag, sourceTag: row.source_tag, conversationKind: row.conversation_kind || null, contextTags: row.session_binding_json ? (typeof row.session_binding_json === 'string' ? JSON.parse(row.session_binding_json) : row.session_binding_json) : null, firstOccurredAt: row.first_occurred_at ? new Date(row.first_occurred_at).toISOString() : null, lastOccurredAt: row.last_occurred_at ? new Date(row.last_occurred_at).toISOString() : null, eventCount: Number(row.event_count), createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at) } : null;
}

function mapPostgresIdentity(row) {
  return row ? {
    id: row.id,
    identityTag: row.identity_tag,
    identityKind: row.identity_kind,
    scopeTag: row.scope_tag,
    status: row.status,
    canonicalIdentityId: row.canonical_identity_id,
    revision: Number(row.revision),
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at)
  } : null;
}

function mapPostgresIdentityEvent(row) {
  return row ? {
    ...row,
    evidenceContentId: row.evidence_content_id,
    response: typeof row.response_json === 'string' ? JSON.parse(row.response_json) : row.response_json
  } : null;
}

function mapPostgresRetention(row) {
  return row ? {
    contentId: row.content_id,
    contentChecksum: row.content_checksum,
    scopeTag: row.scope_tag,
    sourcePointerTag: row.source_pointer_tag,
    originalCreatedAt: row.original_created_at instanceof Date ? row.original_created_at.toISOString() : String(row.original_created_at),
    expiresAt: row.expires_at instanceof Date ? row.expires_at.toISOString() : String(row.expires_at),
    lifecycle: row.lifecycle,
    revision: Number(row.revision),
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at)
  } : null;
}

async function insertPostgresIdentityEvent(catalog, client, event) {
  await catalog._query(client,
    `INSERT INTO ${POSTGRES_SCHEMA}.identity_events_v2
      (id,identity_id,revision,operation,target_identity_id,evidence_content_id,evidence_strength,automatic,actor_tag,idempotency_tag,response_json,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`,
    [event.id, event.identityId, event.revision, event.operation, event.targetIdentityId, event.evidenceContentId, event.evidenceStrength, Boolean(event.automatic), event.actorTag, event.idempotencyTag, JSON.stringify(event.response), event.createdAt]
  );
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
      if (rawRecord.retention) {
        const retention = rawRecord.retention;
        await this._query(client,
          `INSERT INTO ${POSTGRES_SCHEMA}.raw_retention_v2
            (content_id,content_checksum,scope_tag,source_pointer_tag,original_created_at,expires_at,lifecycle,revision,updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (content_id) DO NOTHING`,
          [retention.contentId, retention.contentChecksum, retention.scopeTag, retention.sourcePointerTag, retention.originalCreatedAt, retention.expiresAt, retention.lifecycle, retention.revision, retention.updatedAt]
        );
      }
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
  async findLogicalMessage(ids, queryable = this.pool) {
    await this.ready();
    const alias = await this._query(queryable, `SELECT logical_message_id FROM ${POSTGRES_SCHEMA}.logical_message_aliases_v2 WHERE alias_id=ANY($1::text[]) LIMIT 1`, [ids]);
    const canonical = alias.rows[0]?.logical_message_id || ids[0];
    const result = await this._query(queryable, `SELECT * FROM ${POSTGRES_SCHEMA}.logical_messages_v2 WHERE logical_message_id=$1`, [canonical]);
    const row = result.rows[0];
    return row ? { logicalMessageId: row.logical_message_id, preferredObservationId: row.preferred_observation_id, payloadConflict: row.payload_conflict, tombstoned: row.tombstoned, selectionVersion: row.selection_version, eventIds: typeof row.event_ids === 'string' ? JSON.parse(row.event_ids) : row.event_ids, updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at) } : null;
  }
  async ingestRawEventV2(record, rawRecord, auditEvent) {
    await this.ready();
    const client = await this._connect();
    let destroyClient = false;
    try {
      await this._begin(client);
      const existingV2 = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v2 WHERE event_id=$1`, [record.eventId]);
      const existingV1 = existingV2.rows[0] ? { rows: [] } : await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE event_id=$1`, [record.eventId]);
      const existing = existingV2.rows[0] || existingV1.rows[0];
      if (existing) {
        await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,$4,'duplicate',$5,$6,NULL,$7::jsonb)`, [auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, auditEvent.requestId || null, auditEvent.targetId, JSON.stringify(auditEvent.details || {})]);
        await this._query(client, 'COMMIT');
        return { record: mapPostgresRawEvent(existing), duplicate: true, logical: await this.findLogicalMessage([record.logicalMessageId]) };
      }
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(content_id) DO NOTHING`, [rawRecord.contentId, rawRecord.mediaType, rawRecord.byteLength, rawRecord.storageRef, rawRecord.createdAt]);
      const sessionBinding = sessionContextBinding(record.projection.contextTags);
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,context_tags_json,session_binding_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$8,0,$9) ON CONFLICT(session_id) DO NOTHING`, [record.sessionId, record.projection.sourceKind, record.ownerTag, record.sourceTag, record.projection.conversationKind, JSON.stringify(record.projection.contextTags), JSON.stringify(sessionBinding), record.projection.occurredAt, record.createdAt]);
      const bound = (await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 WHERE session_id=$1`, [record.sessionId])).rows[0];
      const boundBinding = bound?.session_binding_json && (typeof bound.session_binding_json === 'string' ? JSON.parse(bound.session_binding_json) : bound.session_binding_json);
      if (!bound || bound.runtime !== record.projection.sourceKind || bound.conversation_kind !== record.projection.conversationKind
        || !sessionBindingMatches(boundBinding, record.projection)) throw createError('raw_session_binding_conflict', 409);
      const ids = [record.logicalMessageId, ...record.projection.logicalMessageAliases.map(item => item.logicalMessageId)];
      const matched = await this.findLogicalMessage(ids, client);
      const canonicalId = matched?.logicalMessageId || record.logicalMessageId;
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, [record.eventId, record.sessionId, canonicalId, record.contentId, record.payloadDigest, JSON.stringify(record.projection), record.ownerTag, record.sourceTag, record.createdAt]);
      const eventIds = [...new Set([...(matched?.eventIds || []), record.eventId])];
      const observations = (await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v2 WHERE event_id=ANY($1::text[])`, [eventIds])).rows.map(mapPostgresRawEvent).map(item => ({ ...item, projection: { ...item.projection, logicalMessageId: canonicalId } }));
      const selection = selectLogicalMessage(observations);
      const logical = { ...selection, logicalMessageId: canonicalId, eventIds, updatedAt: record.createdAt };
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.logical_messages_v2(logical_message_id,preferred_observation_id,payload_conflict,tombstoned,selection_version,event_ids,updated_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT(logical_message_id) DO UPDATE SET preferred_observation_id=EXCLUDED.preferred_observation_id,payload_conflict=EXCLUDED.payload_conflict,tombstoned=EXCLUDED.tombstoned,selection_version=EXCLUDED.selection_version,event_ids=EXCLUDED.event_ids,updated_at=EXCLUDED.updated_at`, [canonicalId, logical.preferredObservationId, logical.payloadConflict, logical.tombstoned, logical.selectionVersion, JSON.stringify(eventIds), record.createdAt]);
      for (const id of ids) await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.logical_message_aliases_v2(alias_id,logical_message_id) VALUES ($1,$2) ON CONFLICT(alias_id) DO UPDATE SET logical_message_id=EXCLUDED.logical_message_id`, [id, canonicalId]);
      await this._query(client, `UPDATE ${POSTGRES_SCHEMA}.raw_sessions_v1 SET event_count=event_count+1,first_occurred_at=CASE WHEN $1::timestamptz IS NULL THEN first_occurred_at ELSE least(coalesce(first_occurred_at,$1::timestamptz),$1::timestamptz) END,last_occurred_at=CASE WHEN $1::timestamptz IS NULL THEN last_occurred_at ELSE greatest(coalesce(last_occurred_at,$1::timestamptz),$1::timestamptz) END WHERE session_id=$2`, [record.projection.occurredAt, record.sessionId]);
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,$4,'stored',$5,$6,NULL,$7::jsonb)`, [auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, auditEvent.requestId || null, auditEvent.targetId, JSON.stringify(auditEvent.details || {})]);
      await this._query(client, 'COMMIT');
      return { record: { ...record, logicalMessageId: canonicalId }, duplicate: false, logical };
    } catch (error) {
      try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      throw error;
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
  }
  async getRawEvent(id) {
    await this.ready();
    const v2 = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v2 WHERE event_id=$1`, [id]);
    return mapPostgresRawEvent(v2.rows[0] || (await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE event_id=$1`, [id])).rows[0]);
  }
  async searchSessions({ ownerTags = [], query = '', limit = 20 }) { if (!ownerTags.length) return []; await this.ready(); return (await this._query(this.pool, `SELECT s.* FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 s WHERE (EXISTS (SELECT 1 FROM ${POSTGRES_SCHEMA}.raw_events_v1 e WHERE e.session_id=s.session_id AND e.owner_tag=ANY($1::text[])) OR EXISTS (SELECT 1 FROM ${POSTGRES_SCHEMA}.raw_events_v2 e WHERE e.session_id=s.session_id AND e.owner_tag=ANY($1::text[]))) AND (s.session_id ILIKE $2 ESCAPE '\\' OR s.runtime ILIKE $2 ESCAPE '\\') ORDER BY s.last_occurred_at DESC NULLS LAST,s.created_at DESC,s.session_id ASC LIMIT $3`, [ownerTags, escapedLike(query), limit])).rows.map(mapPostgresSession); }
  async getSession(id) { await this.ready(); return mapPostgresSession((await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 WHERE session_id=$1`, [id])).rows[0]); }
  async listSessionEvents(id) {
    await this.ready();
    const legacy = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v1 WHERE session_id=$1 ORDER BY created_at,event_id`, [id]);
    const current = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_events_v2 WHERE session_id=$1 ORDER BY created_at,event_id`, [id]);
    return [...(legacy.rows || []), ...(current.rows || [])].map(mapPostgresRawEvent).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.eventId.localeCompare(b.eventId));
  }
  async rawV2Readiness() {
    await this.ready();
    try {
      const rows = await this._query(this.pool, `SELECT projection_json FROM ${POSTGRES_SCHEMA}.raw_events_v2`);
      for (const row of rows.rows) validateProjectionV2(typeof row.projection_json === 'string' ? JSON.parse(row.projection_json) : row.projection_json);
      const bindings = await this._query(this.pool, `SELECT DISTINCT s.session_binding_json
        FROM ${POSTGRES_SCHEMA}.raw_sessions_v1 s
        JOIN ${POSTGRES_SCHEMA}.raw_events_v2 e ON e.session_id=s.session_id`);
      for (const row of bindings.rows) normalizeSessionContextBinding(typeof row.session_binding_json === 'string' ? JSON.parse(row.session_binding_json) : row.session_binding_json);
      const evidenceResult = await this._query(this.pool, `SELECT
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.raw_events_v1) AS v1_count,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.raw_events_v2) AS v2_count,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.logical_message_aliases_v2) AS alias_count,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.logical_message_aliases_v2 a LEFT JOIN ${POSTGRES_SCHEMA}.logical_messages_v2 l ON l.logical_message_id=a.logical_message_id WHERE l.logical_message_id IS NULL) AS alias_orphan_count,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.raw_events_v2 WHERE projection_json ?| ARRAY['nativeRoomId','nativePersonId','roomId','personId']) AS legacy_field_count,
        (SELECT count(*)::bigint FROM ${POSTGRES_SCHEMA}.raw_events_v2 e
          CROSS JOIN LATERAL jsonb_each(e.projection_json->'contextTags') kv
          CROSS JOIN LATERAL jsonb_array_elements_text(kv.value) tag
          WHERE tag !~ '^hmac-sha256:[A-Za-z0-9._-]{1,128}:[a-f0-9]{64}$') AS literal_scan_count`);
      const row = evidenceResult.rows[0];
      const evidence = Object.fromEntries(['v1Count','v2Count','aliasCount','aliasOrphanCount','legacyFieldCount','literalScanCount'].map((key, index) => [key, Number(row[['v1_count','v2_count','alias_count','alias_orphan_count','legacy_field_count','literal_scan_count'][index]] || 0)]));
      if (evidence.aliasOrphanCount || evidence.legacyFieldCount || evidence.literalScanCount) return { safe: false, reason: 'migration_proof_failed', evidence: { persisted: false, ...evidence } };
      await this._query(this.pool, `INSERT INTO ${POSTGRES_SCHEMA}.raw_projection_v2_migration_state(singleton,schema_version,verified_at,v1_count,v2_count,alias_count,alias_orphan_count,legacy_field_count,literal_scan_count,backend) VALUES (1,$1,now(),$2,$3,$4,$5,$6,$7,'postgres') ON CONFLICT(singleton) DO UPDATE SET schema_version=EXCLUDED.schema_version,verified_at=EXCLUDED.verified_at,v1_count=EXCLUDED.v1_count,v2_count=EXCLUDED.v2_count,alias_count=EXCLUDED.alias_count,alias_orphan_count=EXCLUDED.alias_orphan_count,legacy_field_count=EXCLUDED.legacy_field_count,literal_scan_count=EXCLUDED.literal_scan_count,backend=EXCLUDED.backend`, [POSTGRES_SCHEMA_VERSION, evidence.v1Count, evidence.v2Count, evidence.aliasCount, evidence.aliasOrphanCount, evidence.legacyFieldCount, evidence.literalScanCount]);
      const proof = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_projection_v2_migration_state WHERE singleton=1 AND schema_version=$1 AND backend='postgres'`, [POSTGRES_SCHEMA_VERSION]);
      if (!proof.rows[0]) return { safe: false, reason: 'migration_proof_missing', evidence: { persisted: false, ...evidence } };
      return { safe: true, reason: null, evidence: { persisted: true, schemaVersion: POSTGRES_SCHEMA_VERSION, ...evidence } };
    } catch { return { safe: false, reason: 'literal_routing_scan_failed' }; }
  }
  async recallItemActive(refs, scopeTags) {
    await this.ready();
    if (refs.proposalId) {
      const result = await this._query(this.pool, `SELECT status,scope_tag FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE id=$1`, [refs.proposalId]);
      const row = result.rows[0];
      if (!row || !scopeTags.includes(row.scope_tag) || ['revoked', 'rejected'].includes(row.status)) return false;
    }
    if (refs.contentId) {
      const result = await this._query(this.pool, `SELECT lifecycle,scope_tag FROM ${POSTGRES_SCHEMA}.raw_retention_v2 WHERE content_id=$1`, [refs.contentId]);
      const row = result.rows[0];
      if (!row || !scopeTags.includes(row.scope_tag) || row.lifecycle !== 'active') return false;
    }
    if (refs.identityId) {
      const result = await this._query(this.pool, `SELECT status,scope_tag FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1`, [refs.identityId]);
      const row = result.rows[0];
      if (!row || !scopeTags.includes(row.scope_tag) || row.status !== 'active') return false;
    }
    return true;
  }

  async appendAudit(event) {
    await this.ready();
    await this._query(this.pool,
      `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2
        (id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
      [event.id, event.ts, event.actorTag, event.action, event.outcome, event.requestId || null, event.targetId || null, event.scopeTag || null, JSON.stringify(event.details || {})]
    );
  }

  async getCuratorReceipt(proposalId, queryable = this.pool) {
    await this.ready();
    const result = await this._query(queryable, `SELECT * FROM ${POSTGRES_SCHEMA}.curator_receipt_state_v1 WHERE proposal_id=$1`, [proposalId]);
    const row = result.rows[0];
    return row ? { proposalId: row.proposal_id, status: row.status, decision: typeof row.decision_json === 'string' ? JSON.parse(row.decision_json) : row.decision_json, apply: row.apply_json ? (typeof row.apply_json === 'string' ? JSON.parse(row.apply_json) : row.apply_json) : null } : null;
  }

  async listCuratorReceipts() {
    await this.ready();
    const result = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.curator_receipt_state_v1 ORDER BY proposal_id`);
    return Promise.all(result.rows.map(row => this.getCuratorReceipt(row.proposal_id)));
  }

  async recordCuratorReceipt(receipt, auditEvent) {
    await this.ready();
    const client = await this._connect();
    let destroyClient = false;
    try {
      await this._begin(client);
      await this._query(client, 'SELECT pg_advisory_xact_lock(hashtextextended($1, 6))', [receipt.proposalId]);
      const proposal = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE id=$1 FOR UPDATE`, [receipt.proposalId]);
      if (!proposal.rows[0]) throw createError('receipt_proposal_unverified', 409);
      const current = await this.getCuratorReceipt(receipt.proposalId, client);
      let duplicate = false;
      if (receipt.kind === 'decision') {
        if (current) {
          if (canonicalJson(current.decision) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
          duplicate = true;
        } else {
          await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.curator_receipt_state_v1(proposal_id,status,decision_json,apply_json) VALUES ($1,$2,$3::jsonb,NULL)`, [receipt.proposalId, receipt.status, JSON.stringify(receipt)]);
          await this._query(client, `UPDATE ${POSTGRES_SCHEMA}.fabric_proposals SET status=$1 WHERE id=$2`, [receipt.status === 'rejected' ? 'rejected' : 'review', receipt.proposalId]);
        }
      } else {
        if (!current?.decision || current.decision.status !== 'approved_pending_apply') throw createError('receipt_transition_invalid', 409);
        if (current.apply) {
          if (canonicalJson(current.apply) !== canonicalJson(receipt)) throw createError('receipt_conflict', 409);
          duplicate = true;
        } else {
          await this._query(client, `UPDATE ${POSTGRES_SCHEMA}.curator_receipt_state_v1 SET status='promoted',apply_json=$1::jsonb WHERE proposal_id=$2 AND apply_json IS NULL`, [JSON.stringify(receipt), receipt.proposalId]);
          await this._query(client, `UPDATE ${POSTGRES_SCHEMA}.fabric_proposals SET status='promoted' WHERE id=$1`, [receipt.proposalId]);
        }
      }
      await this._query(client, `INSERT INTO ${POSTGRES_SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,$8::jsonb)`, [auditEvent.id, auditEvent.ts, auditEvent.actorTag, auditEvent.action, duplicate ? 'duplicate' : 'recorded', auditEvent.requestId || null, receipt.proposalId, JSON.stringify(auditEvent.details || {})]);
      const result = await this.getCuratorReceipt(receipt.proposalId, client);
      await this._query(client, 'COMMIT');
      return { ...result, duplicate };
    } catch (error) {
      try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      throw error;
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
  }

  async createIdentity(record, event, rawRecord) {
    await this.ready();
    const client = await this._connect();
    let commitAttempted = false;
    let destroyClient = false;
    try {
      await this._begin(client);
      await this._query(client, 'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [event.idempotencyTag]);
      const replay = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_events_v2 WHERE idempotency_tag=$1`, [event.idempotencyTag]);
      if (replay.rows[0]) {
        const row = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1`, [replay.rows[0].identity_id]);
        commitAttempted = true;
        await this._query(client, 'COMMIT');
        return { record: mapPostgresIdentity(row.rows[0]), event: mapPostgresIdentityEvent(replay.rows[0]), duplicate: true };
      }
      await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (content_id) DO NOTHING`,
        [rawRecord.contentId, rawRecord.mediaType, rawRecord.byteLength, rawRecord.storageRef, rawRecord.createdAt]
      );
      const inserted = await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.identity_records_v2(id,identity_tag,identity_kind,scope_tag,status,canonical_identity_id,revision,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (identity_tag) DO NOTHING RETURNING *`,
        [record.id, record.identityTag, record.identityKind, record.scopeTag, record.status, null, record.revision, record.createdAt, record.updatedAt]
      );
      if (!inserted.rows[0]) {
        const existing = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE identity_tag=$1`, [record.identityTag]);
        commitAttempted = true;
        await this._query(client, 'COMMIT');
        return { record: mapPostgresIdentity(existing.rows[0]), event: null, duplicate: true };
      }
      await insertPostgresIdentityEvent(this, client, event);
      commitAttempted = true;
      await this._query(client, 'COMMIT');
      return { record: mapPostgresIdentity(inserted.rows[0]), event, duplicate: false };
    } catch (error) {
      if (commitAttempted) {
        destroyClient = true;
        error.catalogTransactionOutcome = 'ambiguous_commit';
      } else {
        try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      }
      throw error;
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
  }

  async findIdentityOperation(idempotencyTags) {
    await this.ready();
    const result = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_events_v2 WHERE idempotency_tag=ANY($1::text[]) ORDER BY created_at LIMIT 1`, [idempotencyTags]);
    if (!result.rows[0]) return null;
    const record = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1`, [result.rows[0].identity_id]);
    return { event: mapPostgresIdentityEvent(result.rows[0]), record: mapPostgresIdentity(record.rows[0]) };
  }

  async getIdentity(id) {
    await this.ready();
    const result = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1`, [id]);
    return mapPostgresIdentity(result.rows[0]);
  }

  async mutateIdentity({ sourceId, targetId, expectedRevision, operation, event, rawRecord }) {
    await this.ready();
    const client = await this._connect();
    let commitAttempted = false;
    let destroyClient = false;
    try {
      await this._begin(client);
      await this._query(client, 'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [event.idempotencyTag]);
      const replay = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_events_v2 WHERE idempotency_tag=$1`, [event.idempotencyTag]);
      if (replay.rows[0]) {
        const row = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1`, [replay.rows[0].identity_id]);
        commitAttempted = true;
        await this._query(client, 'COMMIT');
        return { record: mapPostgresIdentity(row.rows[0]), event: mapPostgresIdentityEvent(replay.rows[0]), duplicate: true };
      }
      if (operation === 'merge') {
        const pairKey = identityPairLockKey(sourceId, targetId);
        await this._query(client, 'SELECT pg_advisory_xact_lock(hashtextextended($1, 1))', [pairKey]);
      }
      const sourceResult = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1 FOR UPDATE`, [sourceId]);
      const source = mapPostgresIdentity(sourceResult.rows[0]);
      if (!source) throw createError('identity_not_found', 404);
      if (source.revision !== expectedRevision) throw createError('revision_conflict', 409);
      let status;
      let canonicalIdentityId;
      if (operation === 'merge') {
        const targetResult = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.identity_records_v2 WHERE id=$1 FOR SHARE`, [targetId]);
        const target = mapPostgresIdentity(targetResult.rows[0]);
        if (!target || target.status !== 'active' || target.scopeTag !== source.scopeTag || target.identityKind !== source.identityKind || target.id === source.id) throw createError('identity_not_found', 404);
        if (source.status !== 'active') throw createError('identity_state_conflict', 409);
        status = 'merged'; canonicalIdentityId = target.id;
      } else if (operation === 'split') {
        if (source.status !== 'merged' || !source.canonicalIdentityId) throw createError('identity_state_conflict', 409);
        status = 'active'; canonicalIdentityId = null;
      } else throw createError('identity_operation_invalid', 400);
      await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (content_id) DO NOTHING`,
        [rawRecord.contentId, rawRecord.mediaType, rawRecord.byteLength, rawRecord.storageRef, rawRecord.createdAt]
      );
      const revision = source.revision + 1;
      const updated = await this._query(client,
        `UPDATE ${POSTGRES_SCHEMA}.identity_records_v2 SET status=$1,canonical_identity_id=$2,revision=$3,updated_at=$4 WHERE id=$5 AND revision=$6 RETURNING *`,
        [status, canonicalIdentityId, revision, event.createdAt, sourceId, expectedRevision]
      );
      if (!updated.rows[0]) throw createError('revision_conflict', 409);
      const storedEvent = { ...event, revision, targetIdentityId: targetId };
      await insertPostgresIdentityEvent(this, client, storedEvent);
      commitAttempted = true;
      await this._query(client, 'COMMIT');
      return { record: mapPostgresIdentity(updated.rows[0]), event: storedEvent, duplicate: false };
    } catch (error) {
      if (commitAttempted) {
        destroyClient = true;
        error.catalogTransactionOutcome = 'ambiguous_commit';
      } else {
        try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      }
      throw error;
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
  }

  async planRetention({ asOf, scopeTags, limit }) {
    await this.ready();
    const result = scopeTags
      ? await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_retention_v2 WHERE lifecycle='active' AND expires_at<=$1 AND scope_tag=ANY($2::text[]) ORDER BY expires_at,content_id LIMIT $3`, [asOf, scopeTags, limit])
      : await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_retention_v2 WHERE lifecycle='active' AND expires_at<=$1 ORDER BY expires_at,content_id LIMIT $2`, [asOf, limit]);
    return result.rows.map(mapPostgresRetention);
  }

  async findRetentionOperation(idempotencyTags) {
    await this.ready();
    const result = await this._query(this.pool, `SELECT * FROM ${POSTGRES_SCHEMA}.retention_operations_v2 WHERE idempotency_tag=ANY($1::text[]) ORDER BY created_at LIMIT 1`, [idempotencyTags]);
    const row = result.rows[0];
    return row ? { response: typeof row.response_json === 'string' ? JSON.parse(row.response_json) : row.response_json, requestDigest: row.request_digest, idempotencyTag: row.idempotency_tag } : null;
  }

  async applyRetention({ contentIds, expectedPlanAsOf, reason, createdAt, idFactory, allowedScopeTags = null, operation }) {
    await this.ready();
    const client = await this._connect();
    let commitAttempted = false;
    let destroyClient = false;
    try {
      await this._begin(client);
      await this._query(client, 'SELECT pg_advisory_xact_lock(hashtextextended($1, 2))', [operation.idempotencyTag]);
      const replay = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.retention_operations_v2 WHERE idempotency_tag=$1`, [operation.idempotencyTag]);
      if (replay.rows[0]) {
        const row = replay.rows[0];
        commitAttempted = true;
        await this._query(client, 'COMMIT');
        return { response: typeof row.response_json === 'string' ? JSON.parse(row.response_json) : row.response_json, requestDigest: row.request_digest, duplicate: true };
      }
      const results = [];
      for (const contentId of contentIds) {
        const selected = await this._query(client, `SELECT * FROM ${POSTGRES_SCHEMA}.raw_retention_v2 WHERE content_id=$1 FOR UPDATE`, [contentId]);
        const row = mapPostgresRetention(selected.rows[0]);
        if (!row || (allowedScopeTags && !allowedScopeTags.includes(row.scopeTag)) || row.lifecycle !== 'active' || (reason === 'retention_expired' && row.expiresAt > expectedPlanAsOf)) continue;
        const lifecycle = reason === 'retention_expired' ? 'expired' : reason;
        const updated = await this._query(client,
          `UPDATE ${POSTGRES_SCHEMA}.raw_retention_v2 SET lifecycle=$1,revision=revision+1,updated_at=$2 WHERE content_id=$3 AND revision=$4 AND lifecycle='active' RETURNING *`,
          [lifecycle, createdAt, contentId, row.revision]
        );
        if (!updated.rows[0]) throw createError('revision_conflict', 409);
        const tombstone = retentionTombstone({ id: idFactory(), row: mapPostgresRetention(updated.rows[0]), reason, createdAt });
        await this._query(client,
          `INSERT INTO ${POSTGRES_SCHEMA}.retention_tombstones_v2(id,content_id,content_checksum,source_pointer_tag,reason_code,original_created_at,expired_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [tombstone.id, tombstone.contentId, tombstone.contentChecksum, tombstone.sourcePointerTag, tombstone.reasonCode, tombstone.originalCreatedAt, tombstone.expiredAt, tombstone.createdAt]
        );
        await this._query(client,
          `UPDATE ${POSTGRES_SCHEMA}.fabric_proposals SET status='revoked' WHERE content_id=$1 AND scope_tag=$2 AND status NOT IN ('revoked','rejected')`,
          [contentId, row.scopeTag]
        );
        // Reference proof and lifecycle transition share this transaction. We
        // return a GC candidate only; physical deletion is a separate gated job.
        const references = await this._query(client,
          `SELECT 1 FROM ${POSTGRES_SCHEMA}.fabric_proposals WHERE content_id=$1 AND status NOT IN ('revoked','rejected') LIMIT 1 FOR SHARE`,
          [contentId]
        );
        results.push({ contentId, lifecycle, tombstoneId: tombstone.id, gcCandidate: references.rows.length === 0 });
      }
      const response = { appliedAt: createdAt, physicalDeletionPerformed: false, results };
      await this._query(client,
        `INSERT INTO ${POSTGRES_SCHEMA}.retention_operations_v2(id,idempotency_tag,request_digest,response_json,created_at) VALUES ($1,$2,$3,$4::jsonb,$5)`,
        [operation.id, operation.idempotencyTag, operation.requestDigest, JSON.stringify(response), createdAt]
      );
      commitAttempted = true;
      await this._query(client, 'COMMIT');
      return { response, requestDigest: operation.requestDigest, duplicate: false };
    } catch (error) {
      if (commitAttempted) {
        destroyClient = true;
        error.catalogTransactionOutcome = 'ambiguous_commit';
      } else {
        try { await this._query(client, 'ROLLBACK'); } catch { destroyClient = true; }
      }
      throw error;
    } finally { client.release(destroyClient ? new Error('catalog_client_discarded') : undefined); }
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
  constructor({ rawStore, catalog, ingestKeyRing = null, legacyV1Writes = true, clock = () => new Date(), idFactory = () => crypto.randomUUID(), retentionPolicy = {}, identityPolicy = {} }) {
    this.rawStore = rawStore;
    this.catalog = catalog;
    this.clock = clock;
    this.idFactory = idFactory;
    this.retentionPolicy = { defaultYears: 3, scopeDays: {}, ...retentionPolicy };
    this.identityPolicy = { allowAutomaticStrongMerge: false, ...identityPolicy };
    this.physicalRawDeletionEnabled = false;
    this.configured = true;
    this._proposalMutation = Promise.resolve();
    this.ingestKeys = ingestKeyRing ? normalizeIngestKeyRing(ingestKeyRing) : null;
    this.legacyV1Writes = Boolean(legacyV1Writes);
    this._rawV2Scan = { safe: false, reason: this.legacyV1Writes ? 'legacy_v1_writes_enabled' : 'literal_routing_scan_not_run' };
    this._identityMutation = Promise.resolve();
  }

  async _catalogOperation(operation) {
    try {
      return await operation();
    } catch (error) {
      if (error?.message === 'catalog_unavailable' || error?.message === 'catalog_schema_version_unsupported' || (Number.isInteger(error?.status) && error.status >= 400 && error.status < 500)) throw error;
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
    const originalCreatedAt = String(metadata?.originalTimestamp || createdAt);
    const expiresAt = retentionDeadline(originalCreatedAt, scope, this.retentionPolicy);
    const raw = await this.rawStore.commit(prepared);
    const catalogRecord = {
      id: this.idFactory(), ownerTag: this.rawStore.opaqueTag('owner', actor), scopeTag: this.rawStore.opaqueTag('scope', scope), status: 'queued', contentId: raw.contentId,
      idempotencyTag: this.rawStore.opaqueTag('idempotency', idempotencyKey), sourceTag: this.rawStore.opaqueTag('source', source), createdAt
    };
    try {
      const queued = await this._catalogOperation(() => this.catalog.enqueueProposalWithRaw(
        catalogRecord,
        {
          contentId: raw.contentId,
          mediaType: 'application/vnd.agent-memory-fabric.proposal+json',
          byteLength: raw.byteLength,
          storageRef: raw.storageRef,
          createdAt,
          retention: {
            contentId: raw.contentId,
            contentChecksum: raw.contentId,
            scopeTag: this.rawStore.opaqueTag('scope', scope),
            sourcePointerTag: metadata?.nativePointer ? this.rawStore.opaqueTag('native-pointer', metadata.nativePointer) : null,
            originalCreatedAt,
            expiresAt,
            lifecycle: 'active',
            revision: 1,
            updatedAt: createdAt
          }
        }
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
    if (!record || ['revoked', 'rejected'].includes(record.status) || (!allowAll && !scopeTags.has(record.scopeTag))) {
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

  async assertPromotionEligible(proposalId, { actor = 'curator', requestId = null } = {}) {
    const proposal = await this.readProposal(proposalId);
    const eventIds = proposal?.payload?.record?.provenance?.map(item => item.eventId).filter(id => /^evt_[a-f0-9]{64}$/.test(String(id))) || [];
    for (const eventId of eventIds) {
      const event = await this._catalogOperation(() => this.catalog.getRawEvent(eventId));
      if (!event) continue;
      const logical = event.logicalMessageId ? await this._catalogOperation(() => this.catalog.findLogicalMessage([event.logicalMessageId])) : null;
      if (logical?.payloadConflict || logical?.tombstoned) {
        await this.audit({ actor, action: 'raw_reconcile', outcome: 'blocked', requestId, targetId: proposalId, details: { code: logical.tombstoned ? 'logical_message_tombstoned' : 'logical_message_conflict' } });
        throw createError('raw_reconcile_required', 409);
      }
    }
    await this.audit({ actor, action: 'raw_reconcile', outcome: 'eligible', requestId, targetId: proposalId, details: { resultCount: eventIds.length } });
    return true;
  }

  async ingestRawEvent(input, { requestId = null } = {}) {
    if (!this.ingestKeys) throw createError('raw_ingest_unconfigured', 503);
    validateClientCiphertext({ ...input, actorId: input.actor }, { allowedKeyIds: new Set(this.ingestKeys.keys.keys()), authorizations: this.ingestKeys.authorizations });
    const { projection, envelope, sourceInstanceId, actor } = input;
    const projectionV2 = projection.schema === 'amf.raw-event-projection/v2';
    if (!projectionV2 && !this.legacyV1Writes) throw createError('raw_projection_v1_writes_disabled', 409);
    const contentId = ciphertextContentId(envelope);
    const payloadDigest = ciphertextPayloadDigest(envelope);
    await this._catalogOperation(() => this.catalog.appendAudit({ id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action: 'raw_ingest_decrypt_intent', outcome: 'authorized', requestId, targetId: projection.eventId, scopeTag: null, details: { transport: 'raw_ingest' } }));
    decryptClientCiphertext({ actorId: actor, sourceInstanceId, projection, envelope }, this.ingestKeys);
    const ownerTags = new Set(this.rawStore.opaqueTags('raw-owner', actor));
    const sourceTags = new Set(this.rawStore.opaqueTags('raw-source', sourceInstanceId));
    const existing = await this._catalogOperation(() => this.catalog.getRawEvent(projection.eventId));
    const auditEvent = { id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action: 'raw_event_ingest', outcome: 'stored', requestId, targetId: projection.eventId, scopeTag: null, details: { contentId, duplicate: Boolean(existing) } };
    if (existing) {
      const existingRuntime = existing.projection.sourceKind || existing.projection.runtime;
      const requestedRuntime = projection.sourceKind || projection.runtime;
      if (!ownerTags.has(existing.ownerTag) || !sourceTags.has(existing.sourceTag) || existing.sessionId !== projection.sessionId || existingRuntime !== requestedRuntime) throw createError('raw_session_binding_conflict', 409);
      if (projectionV2) {
        let sameBinding = false;
        try { sameBinding = sessionBindingMatches(sessionContextBinding(existing.projection.contextTags), projection); } catch {}
        if (!sameBinding) throw createError('raw_session_binding_conflict', 409);
      }
      if (existing.payloadDigest !== payloadDigest) throw createError('raw_event_conflict', 409);
      if (canonicalJson(existing.projection) !== canonicalJson(projection)) throw createError('raw_event_conflict', 409);
      const duplicateWrite = projectionV2 ? this.catalog.ingestRawEventV2?.bind(this.catalog) : this.catalog.ingestRawEvent.bind(this.catalog);
      if (!duplicateWrite) throw createError('raw_projection_v2_storage_unavailable', 503);
      await this._catalogOperation(() => duplicateWrite(existing, null, auditEvent));
      return { status: 'duplicate', duplicate: true, eventId: projection.eventId, sessionId: projection.sessionId, contentId: existing.contentId };
    }
    const createdAt = this.clock().toISOString();
    const boundSession = await this._catalogOperation(() => this.catalog.getSession(projection.sessionId));
    if (boundSession) {
      const runtimeConflict = boundSession.runtime !== (projection.sourceKind || projection.runtime);
      const bindingConflict = projectionV2 && (!sessionBindingMatches(boundSession.contextTags, projection) || boundSession.conversationKind !== projection.conversationKind);
      const legacyOwnershipConflict = !projectionV2 && (!ownerTags.has(boundSession.ownerTag) || !sourceTags.has(boundSession.sourceTag));
      if (runtimeConflict || bindingConflict || legacyOwnershipConflict) throw createError('raw_session_binding_conflict', 409);
    }
    // Reject a known binding conflict before creating an unreferenced ciphertext
    // object. A concurrent binding race is still resolved atomically by the
    // catalog; its ciphertext is retained for reference-aware reconciliation/GC.
    const raw = await this.rawStore.commitClientCiphertext(contentId, envelope);
    const record = {
      eventId: projection.eventId, sessionId: projection.sessionId, contentId, payloadDigest, projection,
      ownerTag: projectionV2 ? this.rawStore.opaqueTag('raw-owner', actor) : (boundSession?.ownerTag || this.rawStore.opaqueTag('raw-owner', actor)),
      sourceTag: projectionV2 ? this.rawStore.opaqueTag('raw-source', sourceInstanceId) : (boundSession?.sourceTag || this.rawStore.opaqueTag('raw-source', sourceInstanceId)), createdAt
    };
    if (projectionV2) record.logicalMessageId = projection.logicalMessageId;
    const catalogWrite = projectionV2 ? this.catalog.ingestRawEventV2?.bind(this.catalog) : this.catalog.ingestRawEvent.bind(this.catalog);
    if (!catalogWrite) throw createError('raw_projection_v2_storage_unavailable', 503);
    const stored = await this._catalogOperation(() => catalogWrite(record, { contentId, mediaType: 'application/vnd.agent-memory-fabric.raw-event-ciphertext+json', byteLength: raw.byteLength, storageRef: raw.storageRef, createdAt }, auditEvent));
    if (stored.record.payloadDigest !== payloadDigest) throw createError('raw_event_conflict', 409);
    if (projectionV2) await this._refreshRawV2Readiness();
    return { status: stored.duplicate ? 'duplicate' : 'stored', duplicate: stored.duplicate, eventId: projection.eventId, sessionId: projection.sessionId, contentId: stored.record.contentId, ...(projectionV2 ? { logicalMessageId: stored.record.logicalMessageId, preferredObservationId: stored.logical?.preferredObservationId, payloadConflict: stored.logical?.payloadConflict, tombstoned: stored.logical?.tombstoned } : {}) };
  }

  createSessionReader() {
    if (!this.ingestKeys || !this.catalog.searchSessions) return null;
    const store = this;
    const publicSession = session => ({
      id: session.id, runtime: session.runtime, firstOccurredAt: session.firstOccurredAt,
      lastOccurredAt: session.lastOccurredAt, eventCount: session.eventCount, createdAt: session.createdAt,
      title: `${session.runtime} session`, scope: '', ownerSelf: true,
      conversationKind: session.conversationKind || null, contextTags: session.contextTags ? structuredClone(session.contextTags) : null
    });
    const participantSession = async (actor, id) => {
      const session = await store._catalogOperation(() => store.catalog.getSession(id));
      const ownerTags = new Set(store.rawStore.opaqueTags('raw-owner', actor));
      const events = session ? await store._catalogOperation(() => store.catalog.listSessionEvents(id)) : [];
      if (!session || !events.some(event => ownerTags.has(event.ownerTag))) throw createError('session_not_found', 404);
      return session;
    };
    return {
      configured: true,
      kind: 'fabric-ciphertext-catalog',
      async search({ actor, query, cursor = null, limit, from = null, to = null }) {
        const binding = pageBinding({ actor, query, from, to, operation: 'sessions_search' });
        const offset = decodePageCursor(cursor, binding);
        const sessions = await store._catalogOperation(() => store.catalog.searchSessions({ ownerTags: store.rawStore.opaqueTags('raw-owner', actor), query, limit: Math.min(offset + limit + 1, 10001) }));
        const filtered = sessions.filter(session => inTimeWindow(session.lastOccurredAt || session.createdAt, from, to));
        const page = filtered.slice(offset, offset + limit);
        return { items: page.map(publicSession), total: page.length, nextCursor: offset + page.length < filtered.length ? encodePageCursor(offset + page.length, binding) : null };
      },
      async get({ actor, id }) {
        return publicSession(await participantSession(actor, id));
      },
      async transcript({ actor, id, view, cursor = null, limit = 100, from = null, to = null }) {
        await participantSession(actor, id);
        const allEvents = await store._catalogOperation(() => store.catalog.listSessionEvents(id));
        const binding = pageBinding({ actor, id, view, from, to, operation: 'session_transcript' });
        const offset = decodePageCursor(cursor, binding);
        const filtered = allEvents.filter(event => inTimeWindow(event.projection.occurredAt || event.createdAt, from, to));
        const events = filtered.slice(offset, offset + limit);
        const nextCursor = offset + events.length < filtered.length ? encodePageCursor(offset + events.length, binding) : null;
        if (view !== 'original') return { id, view: 'redacted', items: events.map(event => ({ eventId: event.eventId, occurredAt: event.projection.occurredAt, role: event.projection.role, content: { redacted: true, contentType: event.projection.contentType, parts: event.projection.contentParts } })), nextCursor };
        await store._catalogOperation(() => store.catalog.appendAudit({ id: store.idFactory(), ts: store.clock().toISOString(), actorTag: store.rawStore.opaqueTag('audit-actor', actor), action: 'raw_decrypt_intent', outcome: 'authorized', requestId: null, targetId: id, scopeTag: null, details: { view: 'original' } }));
        const items = [];
        for (const event of events) {
          const envelope = await store.rawStore.getClientCiphertext(event.contentId);
          if (!store.rawStore.opaqueTags('raw-owner', envelope.actorId).includes(event.ownerTag)
            || !store.rawStore.opaqueTags('raw-source', envelope.sourceInstanceId).includes(event.sourceTag)) throw createError('catalog_binding_mismatch', 500);
          const item = decryptClientCiphertext({ actorId: envelope.actorId, sourceInstanceId: envelope.sourceInstanceId, projection: event.projection, envelope }, store.ingestKeys);
          items.push({ eventId: event.eventId, occurredAt: event.projection.occurredAt, role: event.projection.role, raw: item.event.raw });
        }
        return { id, view: 'original', items, nextCursor };
      }
    };
  }

  async filterRecallItems(items, { allowedScopes = [] } = {}) {
    const scopeTags = allowedScopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope));
    const visible = [];
    for (const item of Array.isArray(items) ? items : []) {
      const refs = recallRefs(item);
      if (!refs.proposalId && !refs.contentId && !refs.identityId) {
        visible.push(item);
        continue;
      }
      if (await this._catalogOperation(() => this.catalog.recallItemActive(refs, scopeTags))) visible.push(item);
    }
    return visible;
  }

  _queueIdentity(operation) {
    const run = this._identityMutation.catch(() => {}).then(operation);
    this._identityMutation = run.then(() => undefined, () => undefined);
    return run;
  }

  createIdentity(input) {
    return this._queueIdentity(async () => {
      const actor = String(input.actor || '');
      const clean = { ...input }; delete clean.actor;
      const validated = validateIdentityCreate(clean);
      if (!actor) throw createError('identity_actor_required', 400);
      const createdAt = this.clock().toISOString();
      const evidencePayload = { type: 'identity-evidence', operation: 'create', actor, identityKind: validated.kind, externalKey: validated.externalKey, scope: validated.scope, evidence: validated.evidence };
      const replay = await this._catalogOperation(() => this.catalog.findIdentityOperation(this.rawStore.opaqueTags('identity-idempotency', validated.idempotencyKey)));
      if (replay) {
        const previous = await this.rawStore.get(replay.event.evidenceContentId || replay.event.evidence_content_id);
        if (canonicalJson(previous) !== canonicalJson(evidencePayload)) throw createError('idempotency_key_conflict', 409);
        return this._publicIdentityResult({ ...replay, duplicate: true }, validated.scope);
      }
      const prepared = this.rawStore.prepare(evidencePayload);
      const raw = await this.rawStore.commit(prepared);
      const identityId = this.idFactory();
      const record = {
        id: identityId,
        identityTag: this.rawStore.opaqueTag('identity', `${validated.scope}\u0000${validated.kind}\u0000${validated.externalKey}`),
        identityKind: validated.kind,
        scopeTag: this.rawStore.opaqueTag('scope', validated.scope),
        status: 'active', canonicalIdentityId: null, revision: 1, createdAt, updatedAt: createdAt
      };
      const event = {
        id: this.idFactory(), identityId, revision: 1, operation: 'create', targetIdentityId: null,
        evidenceContentId: raw.contentId,
        evidenceStrength: validated.evidence.type === 'weak_observation' ? 'weak' : 'strong',
        automatic: false,
        actorTag: this.rawStore.opaqueTag('audit-actor', actor),
        idempotencyTag: this.rawStore.opaqueTag('identity-idempotency', validated.idempotencyKey),
        response: { id: identityId, kind: validated.kind, status: 'active', canonicalIdentityId: null, revision: 1 },
        createdAt
      };
      let result;
      try {
        result = await this._catalogOperation(() => this.catalog.createIdentity(record, event, {
          contentId: raw.contentId, mediaType: 'application/vnd.agent-memory-fabric.identity-evidence+json', byteLength: raw.byteLength, storageRef: raw.storageRef, createdAt
        }));
      } catch (error) {
        if (error?.catalogTransactionOutcome !== 'ambiguous_commit') throw error;
        const reconciled = await this._catalogOperation(() => this.catalog.findIdentityOperation(this.rawStore.opaqueTags('identity-idempotency', validated.idempotencyKey)));
        if (!reconciled) throw error;
        const previous = await this.rawStore.get(reconciled.event.evidenceContentId);
        if (canonicalJson(previous) !== canonicalJson(evidencePayload)) throw createError('idempotency_key_conflict', 409);
        result = { ...reconciled, duplicate: true };
      }
      if (result.duplicate && !result.event) throw createError('identity_already_exists', 409);
      return this._publicIdentityResult(result, validated.scope);
    });
  }

  mergeIdentity(sourceId, input) {
    return this._identityMutationAction('merge', sourceId, input);
  }

  splitIdentity(sourceId, input) {
    return this._identityMutationAction('split', sourceId, input);
  }

  _identityMutationAction(operation, sourceId, input) {
    return this._queueIdentity(async () => {
      const actor = String(input.actor || '');
      const scope = String(input.scope || '');
      if (!actor) throw createError('identity_actor_required', 400);
      if (!scope) throw createError('identity_scope_invalid', 400);
      const clean = { ...input }; delete clean.actor; delete clean.scope;
      const validated = validateIdentityMutation(clean, operation);
      if (operation === 'merge' && validated.automatic) {
        const evidenceIsStrong = validated.evidence.type !== 'weak_observation';
        if (!this.identityPolicy.allowAutomaticStrongMerge || !evidenceIsStrong) throw createError('identity_auto_merge_forbidden', 403);
      }
      const source = await this._catalogOperation(() => this.catalog.getIdentity(sourceId));
      const scopeTags = new Set(this.rawStore.opaqueTags('scope', scope));
      if (!source || !scopeTags.has(source.scopeTag)) throw createError('identity_not_found', 404);
      const createdAt = this.clock().toISOString();
      const evidencePayload = { type: 'identity-evidence', operation, actor, scope, sourceId, targetId: validated.targetId || null, evidence: validated.evidence };
      const replay = await this._catalogOperation(() => this.catalog.findIdentityOperation(this.rawStore.opaqueTags('identity-idempotency', validated.idempotencyKey)));
      if (replay) {
        const previous = await this.rawStore.get(replay.event.evidenceContentId || replay.event.evidence_content_id);
        if (canonicalJson(previous) !== canonicalJson(evidencePayload)) throw createError('idempotency_key_conflict', 409);
        return this._publicIdentityResult({ ...replay, duplicate: true }, scope);
      }
      const prepared = this.rawStore.prepare(evidencePayload);
      const raw = await this.rawStore.commit(prepared);
      const event = {
        id: this.idFactory(), identityId: sourceId, revision: validated.expectedRevision + 1, operation,
        targetIdentityId: validated.targetId || source.canonicalIdentityId || null,
        evidenceContentId: raw.contentId,
        evidenceStrength: validated.evidence.type === 'weak_observation' ? 'weak' : 'strong',
        automatic: operation === 'merge' ? validated.automatic : false,
        actorTag: this.rawStore.opaqueTag('audit-actor', actor),
        idempotencyTag: this.rawStore.opaqueTag('identity-idempotency', validated.idempotencyKey),
        response: {
          id: sourceId,
          kind: source.identityKind,
          status: operation === 'merge' ? 'merged' : 'active',
          canonicalIdentityId: operation === 'merge' ? validated.targetId : null,
          revision: validated.expectedRevision + 1
        },
        createdAt
      };
      let result;
      try {
        result = await this._catalogOperation(() => this.catalog.mutateIdentity({
          sourceId, targetId: validated.targetId || source.canonicalIdentityId || null, expectedRevision: validated.expectedRevision,
          operation, event,
          rawRecord: { contentId: raw.contentId, mediaType: 'application/vnd.agent-memory-fabric.identity-evidence+json', byteLength: raw.byteLength, storageRef: raw.storageRef, createdAt }
        }));
      } catch (error) {
        if (error?.catalogTransactionOutcome !== 'ambiguous_commit') throw error;
        const reconciled = await this._catalogOperation(() => this.catalog.findIdentityOperation(this.rawStore.opaqueTags('identity-idempotency', validated.idempotencyKey)));
        if (!reconciled) throw error;
        const previous = await this.rawStore.get(reconciled.event.evidenceContentId);
        if (canonicalJson(previous) !== canonicalJson(evidencePayload)) throw createError('idempotency_key_conflict', 409);
        result = { ...reconciled, duplicate: true };
      }
      return this._publicIdentityResult(result, scope);
    });
  }

  _publicIdentityResult(result, scope) {
    const snapshot = result.event?.response;
    if (snapshot) return { ...snapshot, scope, duplicate: result.duplicate, eventId: result.event.id };
    const row = result.record;
    return { id: row.id, kind: row.identityKind, scope, status: row.status, canonicalIdentityId: row.canonicalIdentityId, revision: row.revision, duplicate: result.duplicate, eventId: result.event?.id || null };
  }

  async readIdentityAuthorized(id, { allowedScopes = [], allowAll = false }) {
    const row = await this._catalogOperation(() => this.catalog.getIdentity(id));
    const allowed = new Set(allowedScopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope)));
    if (!row || (!allowAll && !allowed.has(row.scopeTag))) throw createError('identity_not_found', 404);
    return { id: row.id, kind: row.identityKind, status: row.status, canonicalIdentityId: row.canonicalIdentityId, revision: row.revision, createdAt: row.createdAt, updatedAt: row.updatedAt };
  }

  async planRetention(input, { allowedScopes = [], allowAll = false } = {}) {
    const validated = validateRetentionAction(input, 'plan');
    const scopes = validated.scope ? [validated.scope] : allowedScopes;
    if (!allowAll && validated.scope && !allowedScopes.includes(validated.scope)) throw createError('retention_not_found', 404);
    const scopeTags = allowAll && !validated.scope ? null : scopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope));
    const rows = await this._catalogOperation(() => this.catalog.planRetention({ asOf: validated.asOf, scopeTags, limit: validated.limit }));
    return { asOf: validated.asOf, candidates: rows.map(row => ({ contentId: row.contentId, checksum: row.contentChecksum, originalCreatedAt: row.originalCreatedAt, expiresAt: row.expiresAt, lifecycle: row.lifecycle })) };
  }

  async applyRetention(input, { allowedScopes = [], allowAll = false } = {}) {
    const actor = String(input.actor || '');
    if (!actor) throw createError('identity_actor_required', 400);
    const clean = { ...input }; delete clean.actor;
    const validated = validateRetentionAction(clean, 'apply');
    const allowedScopeTags = allowAll ? null : allowedScopes.flatMap(scope => this.rawStore.opaqueTags('scope', scope));
    const createdAt = this.clock().toISOString();
    if (validated.reason === 'retention_expired' && validated.expectedPlanAsOf > createdAt) throw createError('retention_plan_in_future', 409);
    const idempotencyTags = this.rawStore.opaqueTags('retention-idempotency', `${actor}\u0000${validated.idempotencyKey}`);
    const requestDigest = crypto.createHash('sha256').update(canonicalJson({
      candidateIds: validated.candidateIds,
      expectedPlanAsOf: validated.expectedPlanAsOf,
      reason: validated.reason,
      authorization: { allowAll: Boolean(allowAll), allowedScopes: allowAll ? [] : [...allowedScopes].sort() }
    })).digest('hex');
    const existing = await this._catalogOperation(() => this.catalog.findRetentionOperation(idempotencyTags));
    if (existing) {
      if (existing.requestDigest !== requestDigest) throw createError('idempotency_key_conflict', 409);
      return structuredClone(existing.response);
    }
    const operation = { id: this.idFactory(), idempotencyTag: this.rawStore.opaqueTag('retention-idempotency', `${actor}\u0000${validated.idempotencyKey}`), requestDigest };
    let applied;
    try {
      applied = await this._catalogOperation(() => this.catalog.applyRetention({
        contentIds: validated.candidateIds,
        expectedPlanAsOf: validated.expectedPlanAsOf,
        reason: validated.reason,
        createdAt,
        idFactory: this.idFactory,
        allowedScopeTags,
        operation
      }));
    } catch (error) {
      if (error?.catalogTransactionOutcome !== 'ambiguous_commit') throw error;
      const reconciled = await this._catalogOperation(() => this.catalog.findRetentionOperation(idempotencyTags));
      if (!reconciled) throw error;
      if (reconciled.requestDigest !== requestDigest) throw createError('idempotency_key_conflict', 409);
      return structuredClone(reconciled.response);
    }
    if (applied.requestDigest !== requestDigest) throw createError('idempotency_key_conflict', 409);
    return structuredClone(applied.response);
  }

  async audit({ actor = 'anonymous', action, outcome, requestId = null, targetId = null, scope = null, details = {} }) {
    const safeDetails = Object.fromEntries(Object.entries(details).filter(([key]) => SAFE_AUDIT_DETAIL_KEYS.has(key)));
    await this._catalogOperation(() => this.catalog.appendAudit({ id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action, outcome, requestId, targetId, scopeTag: scope ? this.rawStore.opaqueTag('audit-scope', scope) : null, details: safeDetails }));
  }
  async recordCuratorReceiptAtomic(receipt, { actor = 'curator', requestId = null } = {}) {
    const auditEvent = { id: this.idFactory(), ts: this.clock().toISOString(), actorTag: this.rawStore.opaqueTag('audit-actor', actor), action: receipt.kind === 'apply' ? 'curation_apply_receipt' : 'curation_decision_receipt', outcome: 'recorded', requestId, targetId: receipt.proposalId, scopeTag: null, details: { transport: 'internal' } };
    return this._catalogOperation(() => this.catalog.recordCuratorReceipt(receipt, auditEvent));
  }
  async getCuratorReceipt(proposalId) { return this._catalogOperation(() => this.catalog.getCuratorReceipt(proposalId)); }
  async listCuratorReceipts() { return this._catalogOperation(() => this.catalog.listCuratorReceipts()); }
  async _refreshRawV2Readiness() {
    if (this.legacyV1Writes) { this._rawV2Scan = { safe: false, reason: 'legacy_v1_writes_enabled' }; return this._rawV2Scan; }
    this._rawV2Scan = await this._catalogOperation(() => this.catalog.rawV2Readiness?.() || { safe: false, reason: 'literal_routing_scan_unavailable' });
    return this._rawV2Scan;
  }
  async ready() { await this._catalogOperation(() => this.catalog.ready?.()); await this._refreshRawV2Readiness(); }
  async health() { return this._catalogOperation(() => this.catalog.health ? this.catalog.health() : this.status()); }
  async close() { await this.catalog.close?.(); }
  status() { return { configured: true, rawIngestConfigured: Boolean(this.ingestKeys), rawProjectionV2Ready: Boolean(this._rawV2Scan.safe), rawProjectionV2ReadinessReason: this._rawV2Scan.reason, legacyV1WritesEnabled: this.legacyV1Writes, physicalRawDeletionEnabled: false, ...this.catalog.status() }; }
}

export function createUnconfiguredFabricStore(reason = 'raw_encryption_key_required') {
  const unavailable = async () => { throw createError('fabric_store_unconfigured', 503); };
  const rawUnavailable = async () => { throw createError('raw_ingest_unconfigured', 503); };
  return { configured: false, reason, propose: unavailable, ingestRawEvent: rawUnavailable, createIdentity: unavailable, mergeIdentity: unavailable, splitIdentity: unavailable, readIdentityAuthorized: unavailable, planRetention: unavailable, applyRetention: unavailable, readProposalAuthorized: unavailable, getProposalStatusAuthorized: unavailable, readProposal: unavailable, createSessionReader() { return null; }, async filterRecallItems() { return []; }, async audit() {}, async ready() {}, async close() {}, status() { return { configured: false }; } };
}

function loadLifecyclePolicies(env) {
  let retentionPolicy = { defaultYears: 3, scopeDays: {} };
  const policyPath = String(env.AMF_RETENTION_POLICY_PATH || '').trim();
  if (policyPath) {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(path.resolve(policyPath), 'utf8')); } catch { throw createError('retention_policy_invalid', 500); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).some(key => !['defaultYears', 'scopeDays'].includes(key))) throw createError('retention_policy_invalid', 500);
    const defaultYears = parsed.defaultYears ?? 3;
    if (!Number.isSafeInteger(defaultYears) || defaultYears < 1 || defaultYears > 100) throw createError('retention_policy_invalid', 500);
    if (!parsed.scopeDays || typeof parsed.scopeDays !== 'object' || Array.isArray(parsed.scopeDays)) throw createError('retention_policy_invalid', 500);
    for (const [scope, days] of Object.entries(parsed.scopeDays)) if (!scope || scope.length > 1024 || !Number.isSafeInteger(days) || days < 1 || days > 36500) throw createError('retention_policy_invalid', 500);
    retentionPolicy = { defaultYears, scopeDays: { ...parsed.scopeDays } };
  }
  const automaticRaw = String(env.AMF_IDENTITY_AUTO_MERGE_STRONG || 'false').trim().toLowerCase();
  if (!['true', 'false'].includes(automaticRaw)) throw createError('identity_policy_invalid', 500);
  return { retentionPolicy, identityPolicy: { allowAutomaticStrongMerge: automaticRaw === 'true' } };
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
  const lifecyclePolicies = loadLifecyclePolicies(env);
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
  const cutover = String(env.AMF_RAW_V2_CUTOVER || 'false').trim().toLowerCase();
  if (!['true', 'false'].includes(cutover)) throw createError('raw_v2_cutover_invalid', 500);
  return new FabricStore({ rawStore, catalog, ingestKeyRing, legacyV1Writes: cutover !== 'true', ...lifecyclePolicies });
}

export { POSTGRES_SCHEMA, POSTGRES_SCHEMA_VERSION };
