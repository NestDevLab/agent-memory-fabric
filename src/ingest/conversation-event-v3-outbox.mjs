import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  createConversationEvent,
  validateConversationEvent
} from '../conversation-event-v3.mjs';
import { canonicalJson } from './transcripts/canonical.mjs';

const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PENDING_SCHEMA = 'amf.conversation-event-plaintext-outbox/v1';
const ACK_SCHEMA = 'amf.conversation-event-plaintext-ack/v1';
const TEMP_NAME = /^\.amf-[a-f0-9-]{36}\.tmp$/;
const DEFAULT_MAX_EVENT_BYTES = 256 * 1024;
const DEFAULT_MAX_PENDING_COUNT = 1000;
const DEFAULT_MAX_PENDING_BYTES = 64 * 1024 * 1024;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function eventId(value) {
  if (!EVENT_ID.test(String(value))) fail('conversation_outbox_event_id_invalid');
  return String(value);
}

function payloadDigest(value) {
  if (!DIGEST.test(String(value))) fail('conversation_outbox_payload_digest_invalid');
  return String(value);
}

function ownerUid() {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function assertOwner(stat) {
  const uid = ownerUid();
  if (uid !== null && stat.uid !== uid) fail('conversation_outbox_owner_unsafe');
}

function assertDirectory(directory) {
  let stat;
  try { stat = fs.lstatSync(directory); }
  catch { fail('conversation_outbox_directory_unsafe'); }
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('conversation_outbox_directory_unsafe');
  assertOwner(stat);
  if ((stat.mode & 0o777) !== 0o700) fail('conversation_outbox_directory_mode_unsafe');
}

function assertExistingPathComponentsNotSymlinks(target) {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  let current = parsed.root;
  for (const part of resolved.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) fail('conversation_outbox_path_unsafe');
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      if (error?.code === 'conversation_outbox_path_unsafe') throw error;
      fail('conversation_outbox_path_unsafe');
    }
  }
}

function readDirectory(directory) {
  try { return fs.readdirSync(directory); }
  catch { fail('conversation_outbox_directory_read_failed'); }
}

function lstatEntry(file) {
  try { return fs.lstatSync(file); }
  catch { fail('conversation_outbox_file_unsafe'); }
}

function ensurePrivateDirectory(directory) {
  assertExistingPathComponentsNotSymlinks(directory);
  try { fs.mkdirSync(directory, { recursive: true, mode: 0o700 }); }
  catch { fail('conversation_outbox_directory_unsafe'); }
  assertDirectory(directory);
}

function closeDescriptor(fd, code) {
  try { fs.closeSync(fd); }
  catch { fail(code); }
}

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch {
    fail('conversation_outbox_durability_failed');
  } finally {
    if (fd !== undefined) closeDescriptor(fd, 'conversation_outbox_durability_failed');
  }
}

function assertPrivateRegular(stat) {
  if (!stat.isFile() || stat.isSymbolicLink()) fail('conversation_outbox_file_unsafe');
  assertOwner(stat);
  if ((stat.mode & 0o777) !== 0o600) fail('conversation_outbox_file_mode_unsafe');
}

function openPrivateRegular(file) {
  let before;
  try { before = fs.lstatSync(file); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    fail('conversation_outbox_file_unsafe');
  }
  assertPrivateRegular(before);
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const after = fs.fstatSync(fd);
    assertPrivateRegular(after);
    if (after.dev !== before.dev || after.ino !== before.ino) fail('conversation_outbox_file_changed');
    return fd;
  } catch (error) {
    if (fd !== undefined) closeDescriptor(fd, 'conversation_outbox_file_unsafe');
    if (error?.code === 'conversation_outbox_file_changed') throw error;
    fail('conversation_outbox_file_unsafe');
  }
}

function readPrivateBytes(file, maxBytes) {
  const fd = openPrivateRegular(file);
  if (fd === null) return null;
  try {
    let stat;
    try { stat = fs.fstatSync(fd); }
    catch { fail('conversation_outbox_read_failed'); }
    if (stat.size > maxBytes) fail('conversation_outbox_file_too_large');
    try { return fs.readFileSync(fd); }
    catch { fail('conversation_outbox_read_failed'); }
  } finally {
    closeDescriptor(fd, 'conversation_outbox_read_failed');
  }
}

function unlinkPrivateFile(file) {
  const fd = openPrivateRegular(file);
  if (fd === null) return false;
  closeDescriptor(fd, 'conversation_outbox_file_unsafe');
  try { fs.unlinkSync(file); }
  catch { fail('conversation_outbox_file_changed'); }
  fsyncDirectory(path.dirname(file));
  return true;
}

function writeExclusiveDurable(target, bytes) {
  const directory = path.dirname(target);
  const temp = path.join(directory, `.amf-${crypto.randomUUID()}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(temp, target);
    fsyncDirectory(directory);
    return true;
  } catch (error) {
    if (error?.code === 'EEXIST') return false;
    fail('conversation_outbox_write_failed');
  } finally {
    if (fd !== undefined) closeDescriptor(fd, 'conversation_outbox_write_failed');
    try {
      fs.unlinkSync(temp);
      fsyncDirectory(directory);
    } catch (error) {
      if (error?.code !== 'ENOENT') fail('conversation_outbox_durability_failed');
    }
  }
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function assertPositiveLimit(value, maximum, code) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail(code);
  return value;
}

function parseJson(bytes, code) {
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail(code); }
}

export class ConversationEventPlaintextOutbox {
  constructor({
    rootPath,
    resolveIntegrityKey,
    maxEventBytes = DEFAULT_MAX_EVENT_BYTES,
    maxPendingCount = DEFAULT_MAX_PENDING_COUNT,
    maxPendingBytes = DEFAULT_MAX_PENDING_BYTES,
    clock = () => Date.now(),
    nonceFactory = () => crypto.randomBytes(18).toString('base64url')
  } = {}) {
    if (!rootPath) fail('conversation_outbox_root_required');
    if (typeof resolveIntegrityKey !== 'function') fail('conversation_outbox_integrity_key_unavailable');
    if (typeof clock !== 'function' || typeof nonceFactory !== 'function') fail('conversation_outbox_clock_invalid');
    this.maxEventBytes = assertPositiveLimit(maxEventBytes, 16 * 1024 * 1024, 'conversation_outbox_event_limit_invalid');
    this.maxPendingCount = assertPositiveLimit(maxPendingCount, 1_000_000, 'conversation_outbox_count_limit_invalid');
    this.maxPendingBytes = assertPositiveLimit(maxPendingBytes, 1024 * 1024 * 1024, 'conversation_outbox_bytes_limit_invalid');
    if (this.maxPendingBytes < this.maxEventBytes) fail('conversation_outbox_bytes_limit_invalid');
    this.rootPath = path.resolve(rootPath);
    this.pendingPath = path.join(this.rootPath, 'pending');
    this.ackPath = path.join(this.rootPath, 'acks');
    this.conflictPath = path.join(this.rootPath, 'conflicts');
    this.resolveIntegrityKey = resolveIntegrityKey;
    this.clock = clock;
    this.nonceFactory = nonceFactory;
    for (const directory of [this.rootPath, this.pendingPath, this.ackPath, this.conflictPath]) {
      ensurePrivateDirectory(directory);
    }
    this.#recoverTemps();
    this.#assertStorageEntries();
  }

  pendingFile(id) { return path.join(this.pendingPath, `${eventId(id)}.json`); }
  ackFile(id) { return path.join(this.ackPath, `${eventId(id)}.ack.json`); }
  conflictFile(id, digest) {
    return path.join(this.conflictPath, `${eventId(id)}.${payloadDigest(digest).slice(7)}.json`);
  }

  #recoverTemps() {
    for (const directory of [this.pendingPath, this.ackPath, this.conflictPath]) {
      let changed = false;
      for (const name of readDirectory(directory)) {
        if (!TEMP_NAME.test(name)) continue;
        unlinkPrivateFile(path.join(directory, name));
        changed = true;
      }
      if (changed) fsyncDirectory(directory);
    }
  }

  #assertStorageEntries() {
    const rules = [
      [this.pendingPath, /^cevt_[a-z0-9][a-z0-9_-]{7,127}\.json$/],
      [this.ackPath, /^cevt_[a-z0-9][a-z0-9_-]{7,127}\.ack\.json$/],
      [this.conflictPath, /^cevt_[a-z0-9][a-z0-9_-]{7,127}\.[a-f0-9]{64}\.json$/]
    ];
    for (const [directory, rule] of rules) {
      assertDirectory(directory);
      for (const name of readDirectory(directory)) {
        if (!rule.test(name)) fail('conversation_outbox_entry_unsafe');
        const stat = lstatEntry(path.join(directory, name));
        assertPrivateRegular(stat);
      }
    }
  }

  #validateEvent(event) {
    try { return validateConversationEvent(event, { resolveIntegrityKey: this.resolveIntegrityKey }); }
    catch { fail('conversation_outbox_event_invalid'); }
  }

  #recordFor(event) {
    const validated = this.#validateEvent(event);
    const id = eventId(validated.eventId);
    const digest = payloadDigest(validated.integrity.payloadDigest);
    const record = { schema: PENDING_SCHEMA, eventId: id, payloadDigest: digest, event: validated };
    const bytes = Buffer.from(canonicalJson(record), 'utf8');
    if (bytes.length > this.maxEventBytes) fail('conversation_outbox_event_too_large');
    return { record, bytes };
  }

  #readRecord(file, expectedId = null) {
    const bytes = readPrivateBytes(file, this.maxEventBytes);
    if (bytes === null) return null;
    const record = parseJson(bytes, 'conversation_outbox_record_invalid');
    if (!exactKeys(record, ['schema', 'eventId', 'payloadDigest', 'event']) ||
        record.schema !== PENDING_SCHEMA || (expectedId !== null && record.eventId !== expectedId) ||
        record.event?.eventId !== record.eventId || record.event?.integrity?.payloadDigest !== record.payloadDigest) {
      fail('conversation_outbox_record_invalid');
    }
    const validated = this.#validateEvent(record.event);
    return { ...record, event: validated };
  }

  #readAck(id) {
    id = eventId(id);
    const bytes = readPrivateBytes(this.ackFile(id), 4096);
    if (bytes === null) return null;
    const ack = parseJson(bytes, 'conversation_outbox_ack_invalid');
    if (!exactKeys(ack, ['schema', 'eventId', 'payloadDigest']) || ack.schema !== ACK_SCHEMA ||
        ack.eventId !== id || !DIGEST.test(String(ack.payloadDigest))) fail('conversation_outbox_ack_invalid');
    return ack;
  }

  #queueUsage() {
    this.#assertStorageEntries();
    let count = 0;
    let bytes = 0;
    for (const directory of [this.pendingPath, this.conflictPath]) {
      for (const name of readDirectory(directory)) {
        const file = path.join(directory, name);
        const stat = lstatEntry(file);
        assertPrivateRegular(stat);
        count += 1;
        bytes += stat.size;
      }
    }
    return { count, bytes };
  }

  #assertCapacity(addBytes) {
    const usage = this.#queueUsage();
    if (usage.count + 1 > this.maxPendingCount) fail('conversation_outbox_count_limit_exceeded');
    if (usage.bytes + addBytes > this.maxPendingBytes) fail('conversation_outbox_bytes_limit_exceeded');
  }

  stats() { return this.#queueUsage(); }

  read(id) {
    id = eventId(id);
    return this.#readRecord(this.pendingFile(id), id)?.event ?? null;
  }

  readConflict(id, digest) {
    id = eventId(id);
    digest = payloadDigest(digest);
    return this.#readRecord(this.conflictFile(id, digest), id)?.event ?? null;
  }

  #acceptedState(id) {
    const ack = this.#readAck(id);
    const pending = this.#readRecord(this.pendingFile(id), id);
    if (ack && pending && ack.payloadDigest !== pending.payloadDigest) {
      fail('conversation_outbox_event_id_conflict');
    }
    if (ack && pending) unlinkPrivateFile(this.pendingFile(id));
    return { ack, pending, payloadDigest: ack?.payloadDigest ?? pending?.payloadDigest ?? null };
  }

  #preserveConflict(record, bytes) {
    const target = this.conflictFile(record.eventId, record.payloadDigest);
    const prior = this.#readRecord(target, record.eventId);
    let duplicate = Boolean(prior);
    if (prior && prior.payloadDigest !== record.payloadDigest) fail('conversation_outbox_record_invalid');
    if (!prior) {
      this.#assertCapacity(bytes.length);
      if (!writeExclusiveDurable(target, bytes)) {
        const raced = this.#readRecord(target, record.eventId);
        if (raced?.payloadDigest !== record.payloadDigest) fail('conversation_outbox_race_unresolved');
        duplicate = true;
      }
    }
    return {
      eventId: record.eventId,
      payloadDigest: record.payloadDigest,
      state: 'conflict',
      duplicate
    };
  }

  #resolveEnqueue(record, bytes, accepted) {
    if (accepted.payloadDigest === record.payloadDigest) {
      return {
        eventId: record.eventId,
        payloadDigest: record.payloadDigest,
        state: accepted.ack ? 'acknowledged' : 'pending',
        duplicate: true
      };
    }
    return this.#preserveConflict(record, bytes);
  }

  enqueue(event) {
    const { record, bytes } = this.#recordFor(event);
    const id = record.eventId;
    let accepted = this.#acceptedState(id);
    if (accepted.payloadDigest !== null) return this.#resolveEnqueue(record, bytes, accepted);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      this.#assertCapacity(bytes.length);
      if (writeExclusiveDurable(this.pendingFile(id), bytes)) {
        return { eventId: id, payloadDigest: record.payloadDigest, state: 'pending', duplicate: false };
      }
      accepted = this.#acceptedState(id);
      if (accepted.payloadDigest !== null) return this.#resolveEnqueue(record, bytes, accepted);
    }
    fail('conversation_outbox_race_unresolved');
  }

  acknowledge(id, digest) {
    id = eventId(id);
    digest = payloadDigest(digest);
    const pending = this.#readRecord(this.pendingFile(id), id);
    if (!pending || pending.payloadDigest !== digest) fail('conversation_outbox_ack_invalid');
    const record = { schema: ACK_SCHEMA, eventId: id, payloadDigest: digest };
    const bytes = Buffer.from(canonicalJson(record), 'utf8');
    const created = writeExclusiveDurable(this.ackFile(id), bytes);
    if (!created && this.#readAck(id)?.payloadDigest !== digest) fail('conversation_outbox_event_id_conflict');
    unlinkPrivateFile(this.pendingFile(id));
    return { eventId: id, payloadDigest: digest, state: 'acknowledged', duplicate: !created };
  }

  #reconcileAck(id) {
    const ack = this.#readAck(id);
    if (!ack) return null;
    const pending = this.#readRecord(this.pendingFile(id), id);
    if (pending && pending.payloadDigest !== ack.payloadDigest) fail('conversation_outbox_event_id_conflict');
    if (pending) unlinkPrivateFile(this.pendingFile(id));
    return ack;
  }

  async deliver(id, sink) {
    id = eventId(id);
    const priorAck = this.#reconcileAck(id);
    if (priorAck) {
      return {
        eventId: priorAck.eventId,
        payloadDigest: priorAck.payloadDigest,
        state: 'acknowledged',
        duplicate: true
      };
    }
    if (!sink || typeof sink.deliver !== 'function') fail('conversation_outbox_sink_required');
    const record = this.#readRecord(this.pendingFile(id), id);
    if (!record) fail('conversation_outbox_event_missing');
    let key;
    try { key = this.resolveIntegrityKey(record.event.integrity.keyId); }
    catch { fail('conversation_outbox_integrity_key_unavailable'); }
    if (!Buffer.isBuffer(key) || key.length !== 32) fail('conversation_outbox_integrity_key_unavailable');
    let deliveryEvent;
    try {
      deliveryEvent = createConversationEvent(record.event, {
        keyId: record.event.integrity.keyId,
        key,
        sentAt: new Date(this.clock()).toISOString(),
        nonce: this.nonceFactory()
      });
    } catch { fail('conversation_outbox_event_invalid'); }
    let ack;
    try {
      ack = await sink.deliver(deliveryEvent, { idempotencyKey: id, payloadDigest: record.payloadDigest });
    } catch {
      fail('conversation_outbox_delivery_failed');
    }
    if (!exactKeys(ack, ['acknowledged', 'eventId', 'payloadDigest', 'status']) ||
        ack.acknowledged !== true || ack.eventId !== id || ack.payloadDigest !== record.payloadDigest ||
        !['stored', 'duplicate'].includes(ack.status)) fail('conversation_outbox_ack_invalid');
    this.acknowledge(id, record.payloadDigest);
    return { eventId: id, payloadDigest: record.payloadDigest, state: 'acknowledged', duplicate: ack.status === 'duplicate' };
  }

  pendingIds() {
    this.#assertStorageEntries();
    return readDirectory(this.pendingPath).map(name => name.slice(0, -'.json'.length)).sort();
  }

  async replay(sink, { limit = this.maxPendingCount } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > this.maxPendingCount) {
      fail('conversation_outbox_replay_limit_invalid');
    }
    const results = [];
    for (const id of this.pendingIds().slice(0, limit)) {
      try {
        const delivered = await this.deliver(id, sink);
        results.push({ ...delivered, outcome: 'acknowledged' });
      } catch (error) {
        const errorCode = typeof error?.code === 'string' && error.code.startsWith('conversation_outbox_')
          ? error.code
          : 'conversation_outbox_delivery_failed';
        results.push({ eventId: id, state: 'pending', outcome: 'failed', errorCode });
      }
    }
    return results;
  }
}
