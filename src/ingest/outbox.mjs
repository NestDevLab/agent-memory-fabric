import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson, strictIsoTimestamp } from './transcripts/canonical.mjs';
import { RAW_EVENT_CIPHERTEXT_SCHEMA, RAW_EVENT_CIPHERTEXT_VERSION, projectionDigest, rawEventAad, stablePayloadDigest, validateSafeProjection } from './raw-event-contract.mjs';

const VERSION = RAW_EVENT_CIPHERTEXT_VERSION;
const SAFE_ID = /^evt_[a-f0-9]{64}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HKDF_SALT = Buffer.from('agent-memory-fabric/outbox/v1', 'utf8');

function parseKey(value) {
  const raw = String(value || '');
  if (raw !== raw.trim()) throw new Error('outbox_encryption_key_invalid');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw new Error('outbox_encryption_key_invalid');
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw new Error('outbox_encryption_key_invalid');
  return decoded;
}

function deriveKey(master, purpose) {
  return Buffer.from(crypto.hkdfSync('sha256', master, HKDF_SALT, Buffer.from(purpose, 'utf8'), 32));
}

function normalizeEncryptionKeyRing({ encryptionKey, keyId, keyRing }) {
  if (keyRing) {
    if (!keyRing?.keys || typeof keyRing.keys !== 'object' || Array.isArray(keyRing.keys)) throw new Error('outbox_key_ring_invalid');
    const currentKeyId = String(keyRing.currentKeyId || '');
    if (!SAFE_KEY_ID.test(currentKeyId)) throw new Error('outbox_key_id_invalid');
    const keys = new Map(Object.entries(keyRing.keys).map(([id, value]) => {
      if (!SAFE_KEY_ID.test(String(id))) throw new Error('outbox_key_id_invalid');
      return [String(id), deriveKey(parseKey(value), 'aes-256-gcm')];
    }));
    if (!keys.has(currentKeyId)) throw new Error('outbox_current_key_missing');
    return { currentKeyId, keys, rotated: keys.size > 1 };
  }
  if (!encryptionKey) throw new Error('outbox_encryption_key_required');
  if (!SAFE_KEY_ID.test(String(keyId))) throw new Error('outbox_key_id_invalid');
  return { currentKeyId: String(keyId), keys: new Map([[String(keyId), deriveKey(parseKey(encryptionKey), 'aes-256-gcm')]]), rotated: false };
}

function validateEventId(eventId) {
  if (!SAFE_ID.test(String(eventId))) throw new Error('outbox_event_id_invalid');
  return String(eventId);
}

function assertSafeItem(item) {
  const projection = item?.projection;
  const event = item?.event;
  if (Object.keys(item || {}).sort().join('\0') !== 'event\0projection') throw new Error('outbox_item_fields_invalid');
  const projectionV2 = projection?.schema === 'amf.raw-event-projection/v2';
  if (event?.schema !== (projectionV2 ? 'amf.raw-event/v2' : 'amf.raw-event/v1')) throw new Error('outbox_item_schema_invalid');
  try { validateSafeProjection(projection); } catch { throw new Error('outbox_projection_fields_invalid'); }
  if (projectionV2) {
    if (event.eventId !== projection.eventId || event.sessionId !== projection.sessionId || !event.logical || typeof event.logical !== 'object') throw new Error('outbox_projection_identity_mismatch');
    return item;
  }
  const allowed = ['schema', 'eventId', 'sessionId', 'runtime', 'subtype', 'occurredAt', 'role', 'contentType', 'contentParts', 'hasContent'];
  if (Object.keys(projection).sort().join('\0') !== allowed.sort().join('\0')) throw new Error('outbox_projection_fields_invalid');
  if (event.eventId !== projection.eventId || event.sessionId !== projection.sessionId) throw new Error('outbox_projection_identity_mismatch');
  if (!/^ses_[a-f0-9]{64}$/.test(projection.sessionId)) throw new Error('outbox_projection_session_id_invalid');
  if (!['codex', 'claude'].includes(projection.runtime)) throw new Error('outbox_projection_runtime_invalid');
  if (!/^[a-z][a-z0-9_.:-]{0,63}$/.test(projection.subtype)) throw new Error('outbox_projection_subtype_invalid');
  if (projection.occurredAt !== null && strictIsoTimestamp(projection.occurredAt) !== projection.occurredAt) throw new Error('outbox_projection_timestamp_invalid');
  if (event?.source?.runtime !== projection.runtime || event?.source?.subtype !== projection.subtype || event?.occurredAt !== projection.occurredAt) throw new Error('outbox_projection_source_mismatch');
  if (!['user', 'assistant', 'system', 'tool', 'unknown'].includes(projection.role)) throw new Error('outbox_projection_role_invalid');
  if (!['text', 'structured', 'tool', 'mixed', 'none', 'unknown'].includes(projection.contentType)) throw new Error('outbox_projection_content_type_invalid');
  if (!Number.isSafeInteger(projection.contentParts) || projection.contentParts < 0 || projection.contentParts > 10000 || projection.hasContent !== (projection.contentParts > 0)) throw new Error('outbox_projection_count_invalid');
  return item;
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function writeExclusiveDurable(target, bytes) {
  const directory = path.dirname(target);
  const temp = path.join(directory, `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(temp, target);
    fsyncDirectory(directory);
    return true;
  } catch (error) {
    if (error?.code === 'EEXIST') return false;
    throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
  }
}

export class EncryptedOutbox {
  constructor({ rootPath, encryptionKey, digestKey, checkpointKey = null, keyRing = null, sourceInstanceId, actorId, keyId = 'default' }) {
    if (!rootPath) throw new Error('outbox_root_required');
    if (!encryptionKey && !keyRing) throw new Error('outbox_encryption_key_required');
    if (!digestKey) throw new Error('outbox_digest_key_required');
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(String(sourceInstanceId || ''))) throw new Error('outbox_source_instance_invalid');
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(String(actorId || ''))) throw new Error('outbox_actor_id_invalid');
    const encryption = normalizeEncryptionKeyRing({ encryptionKey, keyId, keyRing });
    if (keyRing && !checkpointKey) throw new Error('outbox_checkpoint_key_required');
    this.rootPath = path.resolve(rootPath);
    this.keyId = encryption.currentKeyId;
    this.keys = encryption.keys;
    this.sourceInstanceId = String(sourceInstanceId);
    this.actorId = String(actorId);
    this.checkpointKey = deriveKey(parseKey(checkpointKey || encryptionKey), 'cursor-checkpoint');
    this.digestKey = deriveKey(parseKey(digestKey), 'stable-event-digest/v1');
    this.pendingPath = path.join(this.rootPath, 'pending');
    this.ackPath = path.join(this.rootPath, 'acks');
    for (const directory of [this.rootPath, this.pendingPath, this.ackPath]) {
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      const stat = fs.lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('outbox_directory_unsafe');
      fs.chmodSync(directory, 0o700);
    }
  }

  pendingFile(eventId) { return path.join(this.pendingPath, `${validateEventId(eventId)}.enc.json`); }
  ackFile(eventId) { return path.join(this.ackPath, `${validateEventId(eventId)}.ack`); }
  itemDigest(item) { return stablePayloadDigest(item, this.digestKey); }
  readAck(eventId) {
    eventId = validateEventId(eventId);
    let ack;
    try { ack = JSON.parse(fs.readFileSync(this.ackFile(eventId), 'utf8')); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw new Error('outbox_ack_invalid'); }
    if (ack?.version !== VERSION || ack?.eventId !== eventId || !/^hmac-sha256:v1:[a-f0-9]{64}$/.test(String(ack?.payloadDigest))) {
      throw new Error('outbox_ack_invalid');
    }
    return ack;
  }
  isAcknowledged(eventId) { return this.readAck(eventId) !== null; }
  checkpoint(bytes) { return crypto.createHmac('sha256', this.checkpointKey).update(bytes).digest('hex'); }
  chainSeed() { return this.checkpoint(Buffer.from('amf-transcript-chain/v1', 'utf8')); }
  chainCheckpoint(previous, bytes) {
    if (!/^[a-f0-9]{64}$/.test(String(previous))) throw new Error('transcript_chain_checkpoint_invalid');
    return crypto.createHmac('sha256', this.checkpointKey)
      .update('amf-transcript-chain-entry/v1\0', 'utf8').update(previous, 'utf8').update('\0', 'utf8').update(bytes).digest('hex');
  }

  encrypt(item) {
    assertSafeItem(item);
    const eventId = validateEventId(item?.event?.eventId);
    const sessionId = item.projection.sessionId;
    const projectionSha256 = projectionDigest(item.projection);
    const payloadDigest = this.itemDigest(item);
    const plaintext = Buffer.from(canonicalJson(item), 'utf8');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.keys.get(this.keyId), iv);
    cipher.setAAD(rawEventAad({ eventId, sessionId, keyId: this.keyId, projectionSha256, payloadDigest, sourceInstanceId: this.sourceInstanceId, actorId: this.actorId }));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      schema: RAW_EVENT_CIPHERTEXT_SCHEMA, version: VERSION, algorithm: 'aes-256-gcm', eventId, sessionId, projectionSha256, payloadDigest, sourceInstanceId: this.sourceInstanceId, actorId: this.actorId, keyId: this.keyId,
      iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64')
    };
  }

  decrypt(envelope) {
    if (envelope?.schema !== RAW_EVENT_CIPHERTEXT_SCHEMA || envelope?.version !== VERSION || envelope?.algorithm !== 'aes-256-gcm') throw new Error('outbox_envelope_unsupported');
    if (!this.keys.has(String(envelope?.keyId || ''))) throw new Error('outbox_key_unavailable');
    const eventId = validateEventId(envelope.eventId);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.keys.get(envelope.keyId), Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(rawEventAad(envelope));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    let plaintext;
    try {
      plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
    } catch {
      throw new Error('outbox_authentication_failed');
    }
    const item = JSON.parse(plaintext.toString('utf8'));
    if (item?.event?.eventId !== eventId || item?.projection?.eventId !== eventId) throw new Error('outbox_event_id_mismatch');
    if (item?.projection?.sessionId !== envelope.sessionId || projectionDigest(item.projection) !== envelope.projectionSha256) throw new Error('outbox_projection_identity_mismatch');
    if (this.itemDigest(item) !== envelope.payloadDigest || envelope.sourceInstanceId !== this.sourceInstanceId || envelope.actorId !== this.actorId) throw new Error('outbox_envelope_binding_mismatch');
    return item;
  }

  read(eventId) {
    const target = this.pendingFile(eventId);
    let envelope;
    try { envelope = JSON.parse(fs.readFileSync(target, 'utf8')); }
    catch (error) {
      if (error?.code === 'ENOENT') return null;
      throw error;
    }
    return this.decrypt(envelope);
  }

  readEnvelope(eventId) {
    try { return JSON.parse(fs.readFileSync(this.pendingFile(eventId), 'utf8')); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  }

  enqueue(item) {
    assertSafeItem(item);
    const eventId = validateEventId(item?.event?.eventId);
    const digest = this.itemDigest(item);
    const acknowledged = this.readAck(eventId);
    if (acknowledged) {
      if (acknowledged.payloadDigest !== digest) throw new Error('outbox_event_id_conflict');
      fs.rmSync(this.pendingFile(eventId), { force: true });
      fsyncDirectory(this.pendingPath);
      return { eventId, state: 'acknowledged', duplicate: true };
    }
    const target = this.pendingFile(eventId);
    const created = writeExclusiveDurable(target, JSON.stringify(this.encrypt(item)));
    if (!created) {
      const existing = this.read(eventId);
      if (canonicalJson(existing) !== canonicalJson(item)) throw new Error('outbox_event_id_conflict');
    }
    const racedAck = this.readAck(eventId);
    if (racedAck) {
      if (racedAck.payloadDigest !== digest) throw new Error('outbox_event_id_conflict');
      fs.rmSync(target, { force: true });
      fsyncDirectory(this.pendingPath);
      return { eventId, state: 'acknowledged', duplicate: true };
    }
    return { eventId, state: 'pending', duplicate: !created };
  }

  acknowledge(eventId, item) {
    eventId = validateEventId(eventId);
    assertSafeItem(item);
    if (item.event.eventId !== eventId) throw new Error('outbox_event_id_mismatch');
    const record = { version: VERSION, eventId, payloadDigest: this.itemDigest(item) };
    const created = writeExclusiveDurable(this.ackFile(eventId), Buffer.from(canonicalJson(record), 'utf8'));
    if (!created && this.readAck(eventId)?.payloadDigest !== record.payloadDigest) throw new Error('outbox_event_id_conflict');
    fs.rmSync(this.pendingFile(eventId), { force: true });
    fsyncDirectory(this.pendingPath);
    return { eventId, state: 'acknowledged' };
  }

  async deliver(eventId, sink) {
    eventId = validateEventId(eventId);
    const existingAck = this.readAck(eventId);
    if (existingAck) {
      const pending = this.read(eventId);
      if (pending && this.itemDigest(pending) !== existingAck.payloadDigest) throw new Error('outbox_event_id_conflict');
      fs.rmSync(this.pendingFile(eventId), { force: true });
      fsyncDirectory(this.pendingPath);
      return { eventId, state: 'acknowledged', duplicate: true };
    }
    if (!sink || (typeof sink.deliver !== 'function' && typeof sink.deliverCiphertext !== 'function')) throw new Error('raw_event_sink_required');
    const item = this.read(eventId);
    if (!item) throw new Error('outbox_event_missing');
    const ack = typeof sink.deliverCiphertext === 'function'
      ? await sink.deliverCiphertext({ projection: item.projection, envelope: this.readEnvelope(eventId) }, { idempotencyKey: eventId })
      : await sink.deliver(item, { idempotencyKey: eventId });
    if (ack?.acknowledged !== true || ack?.eventId !== eventId) throw new Error('raw_event_ack_invalid');
    this.acknowledge(eventId, item);
    return { eventId, state: 'acknowledged', duplicate: Boolean(ack.duplicate) };
  }

  pendingIds() {
    return fs.readdirSync(this.pendingPath)
      .filter(name => /^evt_[a-f0-9]{64}\.enc\.json$/.test(name))
      .map(name => name.slice(0, -'.enc.json'.length)).sort();
  }

  async replay(sink) {
    const results = [];
    for (const eventId of this.pendingIds()) results.push(await this.deliver(eventId, sink));
    return results;
  }
}

export class FakeRawEventSink {
  constructor({ fail = null } = {}) { this.fail = fail; this.deliveries = []; this.ids = new Set(); }
  async deliver(item, { idempotencyKey }) {
    if (this.fail) throw this.fail;
    if (idempotencyKey !== item?.event?.eventId) throw new Error('fake_sink_idempotency_mismatch');
    const duplicate = this.ids.has(idempotencyKey);
    if (!duplicate) this.deliveries.push(item);
    this.ids.add(idempotencyKey);
    return { acknowledged: true, eventId: idempotencyKey, duplicate };
  }
}
