import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson, sha256Id } from './canonical.mjs';

const VERSION = 1;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HKDF_SALT = Buffer.from('agent-memory-fabric/cursor/v1', 'utf8');

function parseKey(value) {
  const raw = String(value || '');
  if (!raw) throw new Error('cursor_encryption_key_required');
  if (raw !== raw.trim()) throw new Error('cursor_encryption_key_invalid');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  if (!/^[A-Za-z0-9+/]{43}=$/.test(raw)) throw new Error('cursor_encryption_key_invalid');
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw new Error('cursor_encryption_key_invalid');
  return decoded;
}

function aadFor(cursorKey, keyId) {
  return Buffer.from(canonicalJson({ cursorKey, keyId, version: VERSION }), 'utf8');
}

function normalizeKeyRing({ encryptionKey, keyId, keyRing }) {
  if (keyRing) {
    if (!keyRing?.keys || typeof keyRing.keys !== 'object' || Array.isArray(keyRing.keys)) throw new Error('cursor_key_ring_invalid');
    const currentKeyId = String(keyRing.currentKeyId || '');
    if (!SAFE_KEY_ID.test(currentKeyId)) throw new Error('cursor_key_id_invalid');
    const keys = new Map(Object.entries(keyRing.keys).map(([id, value]) => {
      if (!SAFE_KEY_ID.test(String(id))) throw new Error('cursor_key_id_invalid');
      return [String(id), Buffer.from(crypto.hkdfSync('sha256', parseKey(value), HKDF_SALT, Buffer.from('aes-256-gcm', 'utf8'), 32))];
    }));
    if (!keys.has(currentKeyId)) throw new Error('cursor_current_key_missing');
    return { currentKeyId, keys };
  }
  if (!SAFE_KEY_ID.test(String(keyId))) throw new Error('cursor_key_id_invalid');
  return {
    currentKeyId: String(keyId),
    keys: new Map([[String(keyId), Buffer.from(crypto.hkdfSync('sha256', parseKey(encryptionKey), HKDF_SALT, Buffer.from('aes-256-gcm', 'utf8'), 32))]])
  };
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function writeAtomic(target, value) {
  const temp = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, target);
    fsyncDirectory(path.dirname(target));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
  }
}

export function sourceCursorKey(runtime, logicalSource) {
  return sha256Id('amf-transcript-cursor-v1', runtime, logicalSource);
}

export class CursorStore {
  constructor({ rootPath, encryptionKey, keyId = 'default', keyRing = null }) {
    if (!rootPath) throw new Error('cursor_root_required');
    const normalized = normalizeKeyRing({ encryptionKey, keyId, keyRing });
    this.keys = normalized.keys;
    this.keyId = normalized.currentKeyId;
    this.rootPath = path.resolve(rootPath);
    fs.mkdirSync(this.rootPath, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(this.rootPath);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('cursor_directory_unsafe');
    fs.chmodSync(this.rootPath, 0o700);
  }
  file(key) {
    if (!/^[a-f0-9]{64}$/.test(String(key))) throw new Error('cursor_key_invalid');
    return path.join(this.rootPath, `${key}.enc.json`);
  }
  encrypt(key, cursor) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.keys.get(this.keyId), iv);
    cipher.setAAD(aadFor(key, this.keyId));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(canonicalJson(cursor), 'utf8')), cipher.final()]);
    return {
      version: VERSION, algorithm: 'aes-256-gcm', cursorKey: key, keyId: this.keyId,
      iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64')
    };
  }
  decrypt(key, envelope) {
    if (envelope?.version !== VERSION || envelope?.algorithm !== 'aes-256-gcm') throw new Error('cursor_envelope_unsupported');
    if (envelope?.cursorKey !== key) throw new Error('cursor_key_mismatch');
    if (!this.keys.has(String(envelope?.keyId || ''))) throw new Error('cursor_key_unavailable');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.keys.get(envelope.keyId), Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(aadFor(key, envelope.keyId));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    try {
      return JSON.parse(Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()
      ]).toString('utf8'));
    } catch {
      throw new Error('cursor_authentication_failed');
    }
  }
  read(key) {
    let envelope;
    try { envelope = JSON.parse(fs.readFileSync(this.file(key), 'utf8')); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
    return this.decrypt(key, envelope);
  }
  write(key, cursor) { writeAtomic(this.file(key), this.encrypt(key, cursor)); return cursor; }
}
