import crypto from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';

import { canonicalJson } from './ingest/transcripts/canonical.mjs';

const CONTENT_CLASSES = ['conversation', 'proposal', 'canonical-memory', 'document'];
const CONTENT_CLASS_SET = new Set(CONTENT_CLASSES);
const SOURCE_INSTANCE_ID = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const KEY_REFERENCE = /^key:[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const POLICY_REVISION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const MAX_METADATA_BYTES = 16 * 1024;
const MAX_METADATA_DEPTH = 16;
const MAX_METADATA_NODES = 32 * 1024;
const MAX_CIPHERTEXT_BYTES = MAX_CONTENT_BYTES + 128 * 1024;

const POLICY_KEYS = ['schema', 'revision', 'defaults', 'rules'];
const RULE_REQUIRED_KEYS = ['sourceInstanceId', 'contentClass', 'enabled', 'codec'];
const RULE_OPTIONAL_KEYS = ['writeKeyRef', 'readKeyRefs', 'compression', 'readPlaintext'];
const PLAINTEXT_ENVELOPE_KEYS = ['v', 'codec', 'sourceInstanceId', 'contentClass', 'compression', 'metadata', 'data'];
const AES_ENVELOPE_KEYS = ['v', 'codec', 'sourceInstanceId', 'contentClass', 'keyRef', 'compression', 'metadata', 'iv', 'ciphertext', 'tag'];

export class ContentProtectionError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new ContentProtectionError(code);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value, required, optional = []) {
  if (!isPlainObject(value)) return false;
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every(key => Object.hasOwn(value, key)) && keys.every(key => allowed.has(key));
}

function contentBytes(value, code = 'content_protection_input_invalid') {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail(code);
  const result = Buffer.from(value);
  if (result.length < 1 || result.length > MAX_CONTENT_BYTES) fail(code);
  return result;
}

function normalizeMetadata(value) {
  if (!isPlainObject(value)) fail('content_protection_metadata_invalid');
  const active = new WeakSet();
  let visitedNodes = 0;

  const walk = (item, depth) => {
    visitedNodes += 1;
    if (depth > MAX_METADATA_DEPTH || visitedNodes > MAX_METADATA_NODES) {
      fail('content_protection_metadata_invalid');
    }
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) fail('content_protection_metadata_invalid');
      return item;
    }
    if (typeof item !== 'object') fail('content_protection_metadata_invalid');
    if (active.has(item)) fail('content_protection_metadata_invalid');
    active.add(item);

    try {
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || Reflect.ownKeys(item).some(key =>
          key !== 'length' && (typeof key !== 'string' || !/^\d+$/.test(key)))) {
          fail('content_protection_metadata_invalid');
        }
        const output = [];
        for (let index = 0; index < item.length; index += 1) {
          if (!Object.hasOwn(item, index)) fail('content_protection_metadata_invalid');
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('content_protection_metadata_invalid');
          output.push(walk(descriptor.value, depth + 1));
        }
        return output;
      }

      if (!isPlainObject(item)) fail('content_protection_metadata_invalid');
      const output = {};
      for (const key of Reflect.ownKeys(item).sort()) {
        if (typeof key !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(key)) {
          fail('content_protection_metadata_invalid');
        }
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('content_protection_metadata_invalid');
        output[key] = walk(descriptor.value, depth + 1);
      }
      return output;
    } finally {
      active.delete(item);
    }
  };

  let normalized;
  try {
    normalized = walk(value, 0);
    if (Buffer.byteLength(canonicalJson(normalized), 'utf8') > MAX_METADATA_BYTES) {
      fail('content_protection_metadata_invalid');
    }
  } catch (error) {
    if (error instanceof ContentProtectionError) throw error;
    fail('content_protection_metadata_invalid');
  }
  return normalized;
}

function decodeCanonicalBase64(value, maximumBytes) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximumBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  return decoded.length > 0 && decoded.length <= maximumBytes && decoded.toString('base64') === value
    ? decoded
    : null;
}

function resolveKeyMaterial(resolveKey, keyRef) {
  if (typeof resolveKey !== 'function') fail('content_protection_key_resolver_invalid');
  let material;
  try {
    material = resolveKey(keyRef);
  } catch {
    fail('content_protection_key_unavailable');
  }
  if (!Buffer.isBuffer(material) && !(material instanceof Uint8Array)) {
    fail('content_protection_key_unavailable');
  }
  const result = Buffer.from(material);
  if (result.length !== 32) fail('content_protection_key_unavailable');
  return result;
}

function authenticatedMetadata(envelope, metadata) {
  return Buffer.from(canonicalJson([
    'amf.content-protection/v1/aad',
    envelope.v,
    envelope.codec,
    envelope.sourceInstanceId,
    envelope.contentClass,
    envelope.keyRef,
    envelope.compression,
    metadata
  ]), 'utf8');
}

function selector(sourceInstanceId, contentClass) {
  if (typeof sourceInstanceId !== 'string' || !SOURCE_INSTANCE_ID.test(sourceInstanceId) ||
      !CONTENT_CLASS_SET.has(contentClass)) {
    fail('content_protection_selector_invalid');
  }
  return `${sourceInstanceId}\0${contentClass}`;
}

function validateRule(rule) {
  if (!hasExactKeys(rule, RULE_REQUIRED_KEYS, RULE_OPTIONAL_KEYS) ||
      typeof rule.sourceInstanceId !== 'string' || !SOURCE_INSTANCE_ID.test(rule.sourceInstanceId) ||
      !CONTENT_CLASS_SET.has(rule.contentClass) || typeof rule.enabled !== 'boolean' ||
      !['plaintext', 'aes-256-gcm'].includes(rule.codec)) {
    fail('content_protection_policy_invalid');
  }

  if (!rule.enabled || rule.codec === 'plaintext') {
    if (RULE_OPTIONAL_KEYS.some(key => Object.hasOwn(rule, key))) fail('content_protection_policy_invalid');
    return;
  }

  if (typeof rule.writeKeyRef !== 'string' || !KEY_REFERENCE.test(rule.writeKeyRef) ||
      !Array.isArray(rule.readKeyRefs) || rule.readKeyRefs.length < 1 || rule.readKeyRefs.length > 32 ||
      new Set(rule.readKeyRefs).size !== rule.readKeyRefs.length ||
      rule.readKeyRefs.some(reference => typeof reference !== 'string' || !KEY_REFERENCE.test(reference)) ||
      !rule.readKeyRefs.includes(rule.writeKeyRef) ||
      (Object.hasOwn(rule, 'compression') && rule.compression !== 'deflate-raw') ||
      (Object.hasOwn(rule, 'readPlaintext') && typeof rule.readPlaintext !== 'boolean')) {
    fail('content_protection_policy_invalid');
  }
}

export function resolveContentProtection(policy, sourceInstanceId, contentClass) {
  const selected = selector(sourceInstanceId, contentClass);
  if (!hasExactKeys(policy, POLICY_KEYS) || policy.schema !== 'amf.content-protection-policy/v1' ||
      typeof policy.revision !== 'string' || !POLICY_REVISION.test(policy.revision) ||
      !hasExactKeys(policy.defaults, CONTENT_CLASSES) ||
      CONTENT_CLASSES.some(item => policy.defaults[item] !== 'plaintext') ||
      !Array.isArray(policy.rules) || policy.rules.length > 256) {
    fail('content_protection_policy_invalid');
  }

  const rules = new Map();
  for (const rule of policy.rules) {
    validateRule(rule);
    const identity = selector(rule.sourceInstanceId, rule.contentClass);
    if (rules.has(identity)) fail('content_protection_policy_invalid');
    rules.set(identity, rule);
  }

  const rule = rules.get(selected);
  if (!rule?.enabled || rule.codec === 'plaintext') {
    return { codec: 'plaintext', compression: 'none', sourceInstanceId, contentClass };
  }
  return {
    codec: 'aes-256-gcm',
    compression: rule.compression ?? 'none',
    sourceInstanceId,
    contentClass,
    writeKeyRef: rule.writeKeyRef,
    readKeyRefs: [...rule.readKeyRefs],
    readPlaintext: rule.readPlaintext ?? true
  };
}

export function protectContent({
  policy,
  sourceInstanceId,
  contentClass,
  plaintext,
  metadata,
  resolveKey
}) {
  const resolved = resolveContentProtection(policy, sourceInstanceId, contentClass);
  const clear = contentBytes(plaintext);
  const normalizedMetadata = normalizeMetadata(metadata);

  if (resolved.codec === 'plaintext') {
    return {
      v: 1,
      codec: 'plaintext',
      sourceInstanceId,
      contentClass,
      compression: 'none',
      metadata: normalizedMetadata,
      data: clear.toString('base64')
    };
  }

  const prepared = resolved.compression === 'deflate-raw'
    ? deflateRawSync(clear, { level: 9 })
    : clear;
  if (prepared.length < 1 || prepared.length > MAX_CIPHERTEXT_BYTES) {
    fail('content_protection_input_invalid');
  }

  const iv = crypto.randomBytes(12);
  const envelope = {
    v: 1,
    codec: 'aes-256-gcm',
    sourceInstanceId,
    contentClass,
    keyRef: resolved.writeKeyRef,
    compression: resolved.compression,
    metadata: normalizedMetadata,
    iv: iv.toString('base64'),
    ciphertext: '',
    tag: ''
  };
  const cipher = crypto.createCipheriv('aes-256-gcm', resolveKeyMaterial(resolveKey, resolved.writeKeyRef), iv);
  cipher.setAAD(authenticatedMetadata(envelope, normalizedMetadata));
  envelope.ciphertext = Buffer.concat([cipher.update(prepared), cipher.final()]).toString('base64');
  envelope.tag = cipher.getAuthTag().toString('base64');
  return envelope;
}

export function unprotectContent({ policy, envelope, resolveKey }) {
  if (!isPlainObject(envelope)) fail('content_protection_envelope_invalid');
  const resolved = resolveContentProtection(policy, envelope.sourceInstanceId, envelope.contentClass);
  const normalizedMetadata = normalizeMetadata(envelope.metadata);
  if (envelope.v !== 1) fail('content_protection_envelope_invalid');

  if (envelope.codec === 'plaintext') {
    if (!hasExactKeys(envelope, PLAINTEXT_ENVELOPE_KEYS) || envelope.compression !== 'none') {
      fail('content_protection_envelope_invalid');
    }
    if (resolved.codec === 'aes-256-gcm' && resolved.readPlaintext !== true) {
      fail('content_protection_envelope_invalid');
    }
    const data = decodeCanonicalBase64(envelope.data, MAX_CONTENT_BYTES);
    if (!data) fail('content_protection_envelope_invalid');
    return data;
  }

  if (!hasExactKeys(envelope, AES_ENVELOPE_KEYS) || resolved.codec !== 'aes-256-gcm' ||
      envelope.codec !== 'aes-256-gcm' || !['none', 'deflate-raw'].includes(envelope.compression) ||
      typeof envelope.keyRef !== 'string' || !resolved.readKeyRefs.includes(envelope.keyRef)) {
    fail('content_protection_envelope_invalid');
  }

  const iv = decodeCanonicalBase64(envelope.iv, 12);
  const ciphertext = decodeCanonicalBase64(envelope.ciphertext, MAX_CIPHERTEXT_BYTES);
  const tag = decodeCanonicalBase64(envelope.tag, 16);
  if (!iv || iv.length !== 12 || !ciphertext || !tag || tag.length !== 16) {
    fail('content_protection_envelope_invalid');
  }

  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      resolveKeyMaterial(resolveKey, envelope.keyRef),
      iv
    );
    decipher.setAAD(authenticatedMetadata(envelope, normalizedMetadata));
    decipher.setAuthTag(tag);
    const prepared = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const clear = envelope.compression === 'deflate-raw'
      ? inflateRawSync(prepared, { maxOutputLength: MAX_CONTENT_BYTES })
      : prepared;
    return contentBytes(clear, 'content_protection_envelope_invalid');
  } catch (error) {
    if (error instanceof ContentProtectionError) throw error;
    fail('content_protection_envelope_invalid');
  }
}

export const contentProtectionLimits = Object.freeze({
  maxContentBytes: MAX_CONTENT_BYTES,
  maxMetadataBytes: MAX_METADATA_BYTES,
  maxMetadataNodes: MAX_METADATA_NODES
});
