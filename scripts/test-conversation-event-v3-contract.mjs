import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';

const schema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf.conversation-event-v3.schema.json', import.meta.url), 'utf8'));
const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/conversation-event-v3.conformance.json', import.meta.url), 'utf8'));
const sourceRules = fs.readFileSync(new URL('../docs/conversation-event-v3-source-rules.md', import.meta.url), 'utf8');
const SUPPORTED_SCHEMA_KEYWORDS = new Set(['$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'additionalProperties', 'required', 'properties', 'const', 'enum', 'pattern', 'format', 'minLength', 'maxLength', 'minimum', 'maximum', 'minItems', 'maxItems', 'uniqueItems', 'items', 'allOf', 'if', 'then', 'not', 'anyOf']);

function assertBoundedSchemaSupport(rule) {
  for (const key of Object.keys(rule)) assert.ok(SUPPORTED_SCHEMA_KEYWORDS.has(key), `unsupported schema keyword: ${key}`);
  if (rule.format !== undefined) assert.equal(typeof rule.pattern, 'string', `format requires a deterministic pattern: ${rule.format}`);
  for (const child of Object.values(rule.$defs || {})) assertBoundedSchemaSupport(child);
  for (const child of Object.values(rule.properties || {})) assertBoundedSchemaSupport(child);
  if (rule.items) assertBoundedSchemaSupport(rule.items);
  for (const branch of rule.allOf || []) assertBoundedSchemaSupport(branch);
  for (const branch of rule.anyOf || []) assertBoundedSchemaSupport(branch);
  if (rule.not) assertBoundedSchemaSupport(rule.not);
  if (rule.if) assertBoundedSchemaSupport(rule.if);
  if (rule.then) assertBoundedSchemaSupport(rule.then);
}

function pointer(path, key) { return `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`; }
function typeMatches(value, expected) {
  const types = Array.isArray(expected) ? expected : [expected];
  return types.some(type => (type === 'array' && Array.isArray(value)) || (type === 'object' && value && typeof value === 'object' && !Array.isArray(value)) || (type === 'null' && value === null) || (type === 'integer' && Number.isInteger(value)) || (type === 'number' && typeof value === 'number' && Number.isFinite(value)) || (type === 'string' && typeof value === 'string') || (type === 'boolean' && typeof value === 'boolean'));
}
function resolve(ref) { return ref.split('/').slice(1).reduce((value, key) => value[key], schema); }
function utcDateTime(value) { if (typeof value !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/.test(value)) return false; const millis = Date.parse(value); if (!Number.isFinite(millis)) return false; const [date, time] = value.split('T'); const iso = new Date(millis).toISOString(); return iso.slice(0, 10) === date && iso.slice(11, 19) === time.slice(0, 8); }
function validate(value, rule = schema, path = '') {
  if (rule.$ref) return validate(value, resolve(rule.$ref), path);
  const errors = [];
  const add = (keyword, at = path) => errors.push({ keyword, instancePath: at });
  if (rule.const !== undefined && value !== rule.const) add('const');
  if (rule.enum && !rule.enum.includes(value)) add('enum');
  if (rule.type && !typeMatches(value, rule.type)) { add('type'); return errors; }
  if (typeof value === 'string') {
    const codePoints = [...value].length;
    if (rule.minLength !== undefined && codePoints < rule.minLength) add('minLength');
    if (rule.maxLength !== undefined && codePoints > rule.maxLength) add('maxLength');
    if (rule.pattern && !(new RegExp(rule.pattern).test(value))) add('pattern');
    if (rule.format === 'date-time' && !utcDateTime(value)) add('format');
  }
  if (typeof value === 'number') {
    if (rule.minimum !== undefined && value < rule.minimum) add('minimum');
    if (rule.maximum !== undefined && value > rule.maximum) add('maximum');
  }
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) add('minItems');
    if (rule.maxItems !== undefined && value.length > rule.maxItems) add('maxItems');
    if (rule.uniqueItems && new Set(value.map(canonicalJson)).size !== value.length) add('uniqueItems');
    if (rule.items) value.forEach((item, index) => errors.push(...validate(item, rule.items, pointer(path, index))));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of rule.required || []) if (!Object.hasOwn(value, key)) add('required');
    if (rule.additionalProperties === false) for (const key of Object.keys(value)) if (!Object.hasOwn(rule.properties || {}, key)) add('additionalProperties');
    for (const [key, propertyRule] of Object.entries(rule.properties || {})) if (Object.hasOwn(value, key)) errors.push(...validate(value[key], propertyRule, pointer(path, key)));
  }
  for (const branch of rule.allOf || []) {
    const matched = !validate(value, branch.if, path).length;
    if (matched && branch.then) errors.push(...validate(value, branch.then, path));
  }
  if (rule.not && !validate(value, rule.not, path).length) add('not');
  if (rule.anyOf && !rule.anyOf.some(option => !validate(value, option, path).length)) add('anyOf');
  return errors;
}
function mergedFixture(entry) {
  const base = structuredClone(fixtures.valid[entry.base ?? 0]);
  for (const [key, value] of Object.entries(entry.payload)) {
    if (value === null) delete base[key];
    else if (key === 'integrity') base.integrity = { ...base.integrity, ...value };
    else base[key] = value;
  }
  return base;
}
function sha256(value) { return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`; }
function logicalDigest(event) {
  return sha256(canonicalJson([
    'amf.conversation-event/v3/logical', event.conversationId, event.threadId ?? null,
    event.role, event.state, event.visibleText ?? null, event.attachments ?? [],
    event.replacesEventId ?? null, event.tombstonesEventId ?? null,
    event.conflictsWithEventIds ?? [], event.revision
  ]));
}
function payloadDigest(event) {
  const { integrity, ...payload } = event;
  return sha256(canonicalJson(payload));
}
function base64url(value) { return value.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function integritySignature(event, key) {
  const integrity = event.integrity;
  const input = canonicalJson(['amf.conversation-event/v3/integrity', integrity.payloadDigest, integrity.keyId, integrity.sentAt, integrity.nonce]);
  return base64url(crypto.createHmac('sha256', key).update(input, 'utf8').digest());
}

test('bounded schema-keyword evaluator covers every behavioral keyword used by the published schema', () => {
  assertBoundedSchemaSupport(schema);
});

test('v3 schema is strict, versioned, and defines only safe attachment and integrity fields', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.properties.schema.const, 'amf.conversation-event/v3');
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.$defs.attachmentReference.additionalProperties, false);
  assert.equal(schema.$defs.integrityEnvelope.additionalProperties, false);
  assert.deepEqual(schema.properties.role.enum, ['user', 'assistant']);
});

test('every synthetic valid v3 fixture satisfies the bounded published-schema evaluator', () => {
  for (const fixture of fixtures.valid) assert.deepEqual(validate(fixture), [], fixture.eventId);
});

test('calendar-invalid timestamps fail the published date-time contract', () => {
  const invalid = structuredClone(fixtures.valid[0]);
  invalid.sourceOccurredAt = '2026-02-30T03:04:05Z';
  assert.ok(validate(invalid).some(error => error.keyword === 'format' && error.instancePath === '/sourceOccurredAt'));
});

test('event cross-references are source- and conversation-bound', () => {
  const normalized = sourceRules.replace(/\s+/g, ' ');
  assert.match(normalized, /same `conversationId` and `sourceInstanceId`/);
  assert.match(normalized, /rejects a cross-conversation or cross-source reference/);
});

test('every valid fixture has deterministic logical, payload, and authenticated integrity digests', () => {
  const testKey = fixtures.integrityTestKey;
  assert.equal(testKey.purpose, 'public synthetic conformance key only');
  assert.equal(testKey.algorithm, 'hmac-sha256');
  const key = Buffer.from(testKey.base64, 'base64');
  assert.equal(key.length, 32);
  assert.equal(key.toString('base64'), testKey.base64);
  for (const fixture of fixtures.valid) {
    assert.equal(fixture.logicalDigest, logicalDigest(fixture), `${fixture.eventId} logicalDigest`);
    assert.equal(fixture.integrity.payloadDigest, payloadDigest(fixture), `${fixture.eventId} payloadDigest`);
    assert.equal(fixture.integrity.keyId, testKey.keyId, `${fixture.eventId} keyId`);
    assert.equal(fixture.integrity.signature, integritySignature(fixture, key), `${fixture.eventId} signature`);
  }
});

test('every synthetic invalid v3 fixture is rejected for its declared schema reason by the bounded evaluator', () => {
  for (const fixture of fixtures.invalid) {
    const errors = validate(mergedFixture(fixture));
    assert.ok(errors.some(error => error.keyword === fixture.expectedKeyword && error.instancePath === fixture.expectedPath), `${fixture.name}: ${JSON.stringify(errors)}`);
  }
});
