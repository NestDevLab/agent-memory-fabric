import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { canonicalize, validateAmfMemoryRecord } from '../src/amf-memory-record-validator.mjs';

const policySchema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf.content-protection-policy-v1.schema.json', import.meta.url), 'utf8'));
const memorySchema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf-memory-v2.schema.json', import.meta.url), 'utf8'));
const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/content-protection-v1.conformance.json', import.meta.url), 'utf8'));
const SUPPORTED_KEYWORDS = new Set([
  '$schema', '$id', '$defs', '$ref', 'title', 'description', 'type',
  'additionalProperties', 'required', 'properties', 'const', 'enum', 'pattern',
  'format', 'minLength', 'maxLength', 'minimum', 'maximum', 'minItems',
  'maxItems', 'uniqueItems', 'items', 'allOf', 'if', 'then', 'not', 'anyOf',
  'oneOf'
]);

function assertKeywords(rule) {
  for (const key of Object.keys(rule)) {
    assert.ok(SUPPORTED_KEYWORDS.has(key), `unsupported schema keyword: ${key}`);
  }
  if (rule.format) assert.equal(typeof rule.pattern, 'string');
  for (const child of Object.values(rule.$defs || {})) assertKeywords(child);
  for (const child of Object.values(rule.properties || {})) assertKeywords(child);
  if (rule.items) assertKeywords(rule.items);
  for (const key of ['allOf', 'anyOf', 'oneOf']) {
    for (const child of rule[key] || []) assertKeywords(child);
  }
  for (const key of ['not', 'if', 'then']) {
    if (rule[key]) assertKeywords(rule[key]);
  }
}

function pointer(path, key) {
  return `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`;
}

function matchesType(value, type) {
  return (Array.isArray(type) ? type : [type]).some(item =>
    (item === 'object' && value && typeof value === 'object' && !Array.isArray(value)) ||
    (item === 'array' && Array.isArray(value)) ||
    (item === 'null' && value === null) ||
    (item === 'string' && typeof value === 'string') ||
    (item === 'boolean' && typeof value === 'boolean') ||
    (item === 'integer' && Number.isInteger(value)) ||
    (item === 'number' && typeof value === 'number' && Number.isFinite(value))
  );
}

function isRfc3339Utc(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return false;
  const date = new Date(timestamp);
  return date.getUTCFullYear() === Number(match[1]) &&
    date.getUTCMonth() + 1 === Number(match[2]) &&
    date.getUTCDate() === Number(match[3]) &&
    date.getUTCHours() === Number(match[4]) &&
    date.getUTCMinutes() === Number(match[5]) &&
    date.getUTCSeconds() === Number(match[6]);
}

function validator(root) {
  const resolve = ref => ref.split('/').slice(1).reduce((value, key) => value[key], root);
  const validate = (value, rule = root, path = '') => {
    if (rule.$ref) return validate(value, resolve(rule.$ref), path);
    const errors = [];
    const add = (keyword, at = path) => errors.push({ keyword, instancePath: at });
    if (rule.const !== undefined && value !== rule.const) add('const');
    if (rule.enum && !rule.enum.includes(value)) add('enum');
    if (rule.type && !matchesType(value, rule.type)) {
      add('type');
      return errors;
    }
    if (typeof value === 'string') {
      const length = [...value].length;
      if (rule.minLength !== undefined && length < rule.minLength) add('minLength');
      if (rule.maxLength !== undefined && length > rule.maxLength) add('maxLength');
      if (rule.pattern && !(new RegExp(rule.pattern).test(value))) add('pattern');
      if (rule.format === 'date-time' && !isRfc3339Utc(value)) add('format');
    }
    if (typeof value === 'number') {
      if (rule.minimum !== undefined && value < rule.minimum) add('minimum');
      if (rule.maximum !== undefined && value > rule.maximum) add('maximum');
    }
    if (Array.isArray(value)) {
      if (rule.minItems !== undefined && value.length < rule.minItems) add('minItems');
      if (rule.maxItems !== undefined && value.length > rule.maxItems) add('maxItems');
      if (rule.uniqueItems && new Set(value.map(canonicalize)).size !== value.length) add('uniqueItems');
      if (rule.items) {
        value.forEach((item, index) => errors.push(...validate(item, rule.items, pointer(path, index))));
      }
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const key of rule.required || []) {
        if (!Object.hasOwn(value, key)) add('required');
      }
      if (rule.additionalProperties === false) {
        for (const key of Object.keys(value)) {
          if (!Object.hasOwn(rule.properties || {}, key)) add('additionalProperties');
        }
      }
      for (const [key, child] of Object.entries(rule.properties || {})) {
        if (Object.hasOwn(value, key)) errors.push(...validate(value[key], child, pointer(path, key)));
      }
    }
    for (const branch of rule.allOf || []) {
      if (!validate(value, branch.if, path).length && branch.then) {
        errors.push(...validate(value, branch.then, path));
      }
    }
    if (rule.not && !validate(value, rule.not, path).length) add('not');
    if (rule.anyOf && !rule.anyOf.some(branch => !validate(value, branch, path).length)) add('anyOf');
    if (rule.oneOf) {
      const results = rule.oneOf.map(branch => validate(value, branch, path));
      if (results.filter(result => !result.length).length !== 1) {
        add('oneOf');
        errors.push(...results.flat());
      }
    }
    return errors;
  };
  return validate;
}

const validatePolicy = validator(policySchema);
const validateMemory = validator(memorySchema);

function policySemanticErrors(policy) {
  const seen = new Set();
  const errors = [];
  for (const rule of policy.rules || []) {
    const selector = `${rule.sourceInstanceId}\0${rule.contentClass}`;
    if (seen.has(selector)) errors.push('duplicate_selector');
    seen.add(selector);
    if (rule.enabled && rule.codec === 'aes-256-gcm' &&
        (!Array.isArray(rule.readKeyRefs) || !rule.readKeyRefs.includes(rule.writeKeyRef))) {
      errors.push('write_key_not_readable');
    }
  }
  return errors;
}

function aadFor(record) {
  const claim = record.claim;
  const tuple = [
    'amf-memory/v2/aad', record.schema, record.id, record.revision,
    record.claimType, record.scope, record.visibility, record.subjects,
    record.confidence, record.lifecycle, record.provenance, record.createdAt,
    record.updatedAt, { alg: claim.alg, kekId: claim.kekId, keyRef: claim.keyRef }
  ];
  return crypto.createHash('sha256').update(canonicalize(tuple), 'utf8').digest('hex');
}

function decodeCanonicalBase64(value) {
  if (typeof value !== 'string' || value.length === 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64') === value ? decoded : null;
}

function memorySemanticErrors(record) {
  const errors = [];
  const lifecycle = record.lifecycle;
  const updated = Date.parse(record.updatedAt);
  if (record.claim.encoding === 'plain' && !record.claim.text.trim()) errors.push('plain_text_empty');
  if (updated < Date.parse(record.createdAt) ||
      (record.revision === 1 && record.createdAt !== record.updatedAt)) {
    errors.push('record_timestamp_revision');
  }
  if (lifecycle.validTo && Date.parse(lifecycle.validTo) < Date.parse(lifecycle.validFrom)) {
    errors.push('valid_to_before_valid_from');
  }
  if (lifecycle.status === 'expired' && !lifecycle.validTo) errors.push('expired_missing_valid_to');
  if (lifecycle.status === 'expired' && lifecycle.validTo && Date.parse(lifecycle.validTo) > updated) {
    errors.push('expired_after_updated');
  }
  if (lifecycle.status === 'revoked' && (!lifecycle.revokedAt || !lifecycle.revocationReason)) {
    errors.push('revoked_missing_fields');
  }
  if (lifecycle.status === 'revoked' && lifecycle.revokedAt && Date.parse(lifecycle.revokedAt) > updated) {
    errors.push('revoked_after_updated');
  }
  if (lifecycle.status !== 'revoked' &&
      (lifecycle.revokedAt !== null || lifecycle.revocationReason !== null)) {
    errors.push('non_revoked_has_revocation');
  }
  if (lifecycle.supersedes.includes(record.id)) errors.push('supersedes_self');

  const events = new Set();
  let prior = -Infinity;
  for (const item of record.provenance) {
    if (events.has(item.eventId)) errors.push('duplicate_provenance_event');
    events.add(item.eventId);
    const captured = Date.parse(item.capturedAt);
    if (captured < prior || captured > updated) errors.push('provenance_timestamp_order');
    prior = captured;
  }

  if (record.claim.encoding !== 'sealed') return errors;
  const iv = decodeCanonicalBase64(record.claim.iv);
  const ciphertext = decodeCanonicalBase64(record.claim.ciphertext);
  const tag = decodeCanonicalBase64(record.claim.tag);
  if (!iv) errors.push('iv_base64');
  else if (iv.length !== 12) errors.push('iv_length');
  if (!ciphertext) errors.push('ciphertext_base64');
  else if (!ciphertext.length) errors.push('ciphertext_empty');
  if (!tag) errors.push('tag_base64');
  else if (tag.length !== 16) errors.push('tag_length');
  if (record.claim.aadSha256 !== aadFor(record)) errors.push('aad_mismatch');
  return errors;
}

function merged(base, patch) {
  const value = structuredClone(base);
  for (const [key, item] of Object.entries(patch)) {
    value[key] = item && typeof item === 'object' && !Array.isArray(item) &&
      value[key] && typeof value[key] === 'object' && !Array.isArray(value[key])
      ? { ...value[key], ...item }
      : item;
  }
  return value;
}

test('bounded evaluators cover every behavioral keyword in both published schemas', () => {
  assertKeywords(policySchema);
  assertKeywords(memorySchema);
});

test('policy defaults, exact selectors, enabled encryption, and disabled rules conform', () => {
  assert.deepEqual(validatePolicy(fixtures.policy.valid), []);
  assert.deepEqual(policySemanticErrors(fixtures.policy.valid), []);
});

test('invalid policies fail for their declared structural or deterministic semantic reason', () => {
  for (const entry of fixtures.policy.invalid) {
    const value = merged(fixtures.policy.valid, entry.payload);
    const errors = validatePolicy(value);
    if (entry.expectedSemantic) {
      assert.ok(policySemanticErrors(value).includes(entry.expectedSemantic), entry.name);
    } else {
      assert.ok(errors.some(error => error.keyword === entry.expectedKeyword &&
        error.instancePath === entry.expectedPath), `${entry.name}: ${JSON.stringify(errors)}`);
    }
  }
});

test('v2 permits plain and sealed claims independently from visibility and v1 remains readable', () => {
  for (const record of fixtures.memory.valid) {
    assert.deepEqual(validateMemory(record), [], record.id);
    assert.deepEqual(memorySemanticErrors(record), [], record.id);
  }
  assert.deepEqual(validateAmfMemoryRecord(fixtures.memory.legacyV1), { ok: true, errors: [] });
});

test('sealed v2 AAD, canonical base64, and envelope sizes fail closed', () => {
  const sealed = fixtures.memory.valid[1];
  for (const [name, patch, expected] of [
    ['aad', { aadSha256: '0'.repeat(64) }, 'aad_mismatch'],
    ['iv', { iv: 'AQEBAQEBAQE=' }, 'iv_length'],
    ['tag', { tag: 'AgICAgICAgI=' }, 'tag_length'],
    ['base64', { ciphertext: 'c3ludGhldGljLWNpcGhlcnRleHQ===' }, 'ciphertext_base64']
  ]) {
    assert.ok(memorySemanticErrors(merged(sealed, { claim: patch })).includes(expected), name);
  }
});

test('v2 lifecycle semantics retain v1 transition and ordering guards', () => {
  const record = fixtures.memory.valid[0];
  const duplicateProvenance = [record.provenance[0], record.provenance[0]];
  for (const [name, patch, expected] of [
    ['validity order', { lifecycle: { validTo: '2026-01-02T03:04:04Z' } }, 'valid_to_before_valid_from'],
    ['expired fields', { lifecycle: { status: 'expired', validTo: null } }, 'expired_missing_valid_to'],
    ['revoked fields', { lifecycle: { status: 'revoked', revokedAt: null, revocationReason: null } }, 'revoked_missing_fields'],
    ['non-revoked fields', { lifecycle: { revokedAt: '2026-01-02T03:04:05Z', revocationReason: 'synthetic' } }, 'non_revoked_has_revocation'],
    ['self supersession', { lifecycle: { supersedes: [record.id] } }, 'supersedes_self'],
    ['record order', { updatedAt: '2026-01-02T03:04:04Z' }, 'record_timestamp_revision'],
    ['duplicate provenance', { provenance: duplicateProvenance }, 'duplicate_provenance_event']
  ]) {
    assert.ok(memorySemanticErrors(merged(record, patch)).includes(expected), name);
  }
});

test('invalid v2 fixtures are rejected by the schema evaluator or declared semantic guard', () => {
  for (const entry of fixtures.memory.invalid) {
    const value = merged(fixtures.memory.valid[entry.base ?? 0], entry.payload);
    const errors = validateMemory(value);
    if (entry.expectedSemantic) {
      assert.ok(memorySemanticErrors(value).includes(entry.expectedSemantic), entry.name);
    } else {
      assert.ok(errors.some(error => error.keyword === entry.expectedKeyword &&
        error.instancePath === entry.expectedPath), `${entry.name}: ${JSON.stringify(errors)}`);
    }
  }
});
