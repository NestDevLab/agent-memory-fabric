import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { createM4CleanupInventory, createM4CleanupManifest, verifyM4CleanupManifest } from '../src/migration/m4-cleanup-inventory.mjs';
import { createM4CutoverAuthorization } from '../src/migration/m4-cutover-authorization.mjs';
import { m4CutoverFixture } from './helpers/m4-cutover-fixtures.mjs';

const schema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf.migration-manifest-v1.schema.json', import.meta.url), 'utf8'));
const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/migration-manifest-v1.conformance.json', import.meta.url), 'utf8'));
const docs = Object.fromEntries(['idempotency-conflict-resolution-v1.md', 'v3-migration-safety-v1.md', 'threat-model-v3.md'].map(name => [name, fs.readFileSync(new URL(`../docs/${name}`, import.meta.url), 'utf8')]));
const key = Buffer.from(fixtures.integrityTestKey.base64, 'base64');
const supported = new Set(['$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'additionalProperties', 'required', 'properties', 'const', 'enum', 'pattern', 'minimum', 'maximum', 'minItems', 'maxItems', 'uniqueItems', 'items', 'oneOf', 'anyOf', 'allOf', 'if', 'then', 'not']);

function pointer(path, key) { return `${path}/${String(key).replace(/~/g, '~0').replace(/\//g, '~1')}`; }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`; }
function signature(payloadDigest) { return crypto.createHmac('sha256', key).update(canonicalJson(['amf.migration-manifest/v1/integrity', payloadDigest, fixtures.integrityTestKey.keyId])).digest('base64url'); }
function resolve(ref) { return ref.split('/').slice(1).reduce((value, part) => value[part], schema); }
function typeMatches(value, type) { return ({ object: value && typeof value === 'object' && !Array.isArray(value), array: Array.isArray(value), string: typeof value === 'string', integer: Number.isInteger(value), number: typeof value === 'number' && Number.isFinite(value), boolean: typeof value === 'boolean', null: value === null })[type]; }
function validate(value, rule = schema, path = '') {
  if (rule.$ref) return validate(value, resolve(rule.$ref), path);
  const errors = []; const add = keyword => errors.push({ keyword, instancePath: path });
  if (rule.const !== undefined && !Object.is(value, rule.const)) add('const');
  if (rule.enum && !rule.enum.some(item => Object.is(item, value))) add('enum');
  if (rule.type && !typeMatches(value, rule.type)) { add('type'); return errors; }
  if (typeof value === 'string' && rule.pattern && !(new RegExp(rule.pattern).test(value))) add('pattern');
  if (typeof value === 'number') { if (rule.minimum !== undefined && value < rule.minimum) add('minimum'); if (rule.maximum !== undefined && value > rule.maximum) add('maximum'); }
  if (Array.isArray(value)) { if (rule.minItems !== undefined && value.length < rule.minItems) add('minItems'); if (rule.maxItems !== undefined && value.length > rule.maxItems) add('maxItems'); if (rule.uniqueItems && new Set(value.map(canonicalJson)).size !== value.length) add('uniqueItems'); if (rule.items) value.forEach((item, index) => errors.push(...validate(item, rule.items, pointer(path, index)))); }
  if (value && typeof value === 'object' && !Array.isArray(value)) { for (const name of rule.required || []) if (!Object.hasOwn(value, name)) errors.push({ keyword: 'required', instancePath: path }); if (rule.additionalProperties === false) for (const name of Object.keys(value)) if (!Object.hasOwn(rule.properties || {}, name)) errors.push({ keyword: 'additionalProperties', instancePath: path }); for (const [name, child] of Object.entries(rule.properties || {})) if (Object.hasOwn(value, name)) errors.push(...validate(value[name], child, pointer(path, name))); }
  for (const branch of rule.allOf || []) errors.push(...validate(value, branch, path));
  if (rule.if && !validate(value, rule.if, path).length && rule.then) errors.push(...validate(value, rule.then, path));
  if (rule.not && !validate(value, rule.not, path).length) add('not');
  if (rule.anyOf && !rule.anyOf.some(branch => !validate(value, branch, path).length)) add('anyOf');
  if (rule.oneOf && rule.oneOf.filter(branch => !validate(value, branch, path).length).length !== 1) add('oneOf');
  return errors;
}
function assertSupported(rule) { for (const name of Object.keys(rule)) assert.ok(supported.has(name), `unsupported keyword ${name}`); for (const child of Object.values(rule.$defs || {})) assertSupported(child); for (const child of Object.values(rule.properties || {})) assertSupported(child); if (rule.items) assertSupported(rule.items); for (const key of ['oneOf', 'anyOf', 'allOf']) for (const child of rule[key] || []) assertSupported(child); if (rule.if) assertSupported(rule.if); if (rule.then) assertSupported(rule.then); if (rule.not) assertSupported(rule.not); }
function set(object, dotted, value) { const parts = dotted.split('.'); const leaf = parts.pop(); const holder = parts.reduce((item, part) => item[part], object); holder[leaf] = value; }
function remove(object, dotted) { const parts = dotted.split('.'); const leaf = parts.pop(); delete parts.reduce((item, part) => item[part], object)[leaf]; }
function resign(manifest) { const { integrity, ...payload } = manifest; const payloadDigest = digest(canonicalJson(payload)); manifest.integrity = { algorithm: 'hmac-sha256', keyId: fixtures.integrityTestKey.keyId, payloadDigest, signature: signature(payloadDigest) }; }
function invalidFixture(entry) { const manifest = structuredClone(fixtures.valid.find(item => item.manifestId === entry.base)); if (entry.add) Object.assign(manifest, entry.add); if (entry.remove) remove(manifest, entry.remove); for (const [path, value] of Object.entries(entry.set || {})) if (!path.startsWith('integrity.')) set(manifest, path, value); if (!entry.preserveIntegrity) resign(manifest); if (entry.set?.['integrity.signature'] !== undefined) manifest.integrity.signature = entry.set['integrity.signature']; return manifest; }
function integrityErrors(manifest) { const { integrity, ...payload } = manifest; const errors = []; if (integrity.payloadDigest !== digest(canonicalJson(payload))) errors.push({ keyword: 'payloadDigest', instancePath: '/integrity/payloadDigest' }); if (integrity.signature !== signature(integrity.payloadDigest)) errors.push({ keyword: 'signature', instancePath: '/integrity/signature' }); return errors; }

test('bounded evaluator implements every JSON-Schema keyword used by the published contract', () => { assertSupported(schema); });
test('each valid fixture is independent, phase-exclusive, schema-valid, and cryptographically authentic', () => {
  assert.equal(fixtures.valid.length, 4);
  assert.equal(new Set(fixtures.valid.map(item => item.phase)).size, 4);
  for (const manifest of fixtures.valid) { assert.deepEqual(validate(manifest), [], manifest.manifestId); assert.deepEqual(integrityErrors(manifest), [], manifest.manifestId); assert.deepEqual(Object.keys(manifest).filter(name => ['pause', 'rollback', 'reconciliation', 'cleanup'].includes(name)), [manifest.phase]); }
});
test('phase references bind pause, rollback, complete reconciliation, and cleanup gates in order', () => {
  const byId = new Map(fixtures.valid.map(item => [item.manifestId, item])); const pause = byId.get('pause-manifest-001'); const rollback = byId.get('rollback-manifest-001'); const reconciliation = byId.get('reconciliation-manifest-001'); const cleanup = byId.get('cleanup-manifest-001');
  for (const reference of [rollback.rollback.pauseEvidence, reconciliation.reconciliation.pauseEvidence]) assert.deepEqual(reference, { manifestId: pause.manifestId, digest: pause.integrity.payloadDigest, signature: pause.integrity.signature });
  assert.deepEqual(reconciliation.reconciliation.rollbackEvidence, { manifestId: rollback.manifestId, digest: rollback.integrity.payloadDigest, signature: rollback.integrity.signature });
  assert.deepEqual(cleanup.cleanup.reconciliationEvidence, { manifestId: reconciliation.manifestId, digest: reconciliation.integrity.payloadDigest, signature: reconciliation.integrity.signature, state: 'complete' });
  assert.equal(reconciliation.reconciliation.completeness, 1); assert.equal(reconciliation.reconciliation.unresolvedMismatchCount, 0); assert.equal(reconciliation.reconciliation.dimensions.length, 12); assert.equal(cleanup.cleanup.cutoverCanary.state, 'passed'); assert.equal(cleanup.cleanup.restoreTest, 'passed');
});
test('a pending reconciliation is structurally valid but cannot be presented as complete cutover evidence', () => {
  const pending = structuredClone(fixtures.valid.find(item => item.phase === 'reconciliation'));
  pending.reconciliation.state = 'pending'; pending.reconciliation.completeness = 0.5; resign(pending);
  assert.deepEqual(validate(pending), []); assert.notEqual(pending.reconciliation.state, 'complete');
});
test('declared invalid fixtures fail schema or integrity at their declared safety boundary', () => {
  for (const entry of fixtures.invalid) { const manifest = invalidFixture(entry); const errors = [...validate(manifest), ...integrityErrors(manifest)]; assert.ok(errors.some(error => error.instancePath === entry.expectedPath || error.instancePath.startsWith(entry.expectedPath)), `${entry.name}: ${JSON.stringify(errors)}`); }
});
test('cleanup targets are exact identifiers and manifests exclude paths, globs, commands, and copy instructions', () => {
  const cleanup = fixtures.valid.find(item => item.phase === 'cleanup').cleanup; for (const target of cleanup.targets) assert.match(target.id, /^[a-z][a-z0-9-]{2,79}$/); const published = JSON.stringify(schema); assert.doesNotMatch(published, /(?:filesystem|shell command|data cop(?:y|ies)|glob)/i);
});
test('runtime M4 evidence projects into the existing cleanup phase without widening phase vocabulary', async () => {
  const fixture = await m4CutoverFixture(); const cutover = createM4CutoverAuthorization(fixture.authorizationInput, { selectorScopeKeyDocument: fixture.keys.selectorScope });
  const inventory = createM4CleanupInventory({ manifestId: 'runtime-cleanup-inventory', revision: 1, inventoriedAt: '2026-01-02T01:04:00Z', cutoverManifest: cutover,
    cutoverKeyDocument: fixture.keys.authorization, preservationManifest: fixture.preservation, preservationKeyDocument: fixture.keys.preservation,
    catalogSnapshotManifest: fixture.catalogSnapshot, targets: fixture.catalogSnapshot.eligibleTargets, cleanupKeyDocument: fixture.keys.cleanup },
  { catalogSnapshotKeyDocument: fixture.keys.catalogSnapshot });
  const manifest = createM4CleanupManifest({ manifestId: 'runtime-cleanup-manifest', revision: 1, inventory,
    inventoryKeyDocument: fixture.keys.cleanup, cutoverAuthorization: cutover, cutoverKeyDocument: fixture.keys.authorization,
    migrationKeyDocument: fixture.keys.cleanup });
  assert.deepEqual(validate(manifest), []); assert.equal(manifest.phase, 'cleanup');
  assert.deepEqual(Object.keys(manifest).filter(name => ['pause', 'rollback', 'reconciliation', 'cleanup'].includes(name)), ['cleanup']);
  assert.deepEqual(verifyM4CleanupManifest(manifest, fixture.keys.cleanup), manifest);
});
test('public documents retain conflict controls and cover TLS, replay, and plaintext residual risks', () => {
  const conflict = docs['idempotency-conflict-resolution-v1.md']; for (const phrase of ['same stable ID', 'full payload digest', 'immutable conflict', 'outbox', 'acknowledgement', 'accept_existing', 'accept_received_as_replacement', 'reject_received', 'expected revision', 'append-only', 'fails resolution closed', 'No automatic resolution']) assert.match(conflict, new RegExp(phrase.replace(/ /g, '\\s+'), 'i'));
  const threat = docs['threat-model-v3.md']; for (const phrase of ['authenticated HTTPS/TLS', 'replay-window', 'nonce verification', 'host access', 'recovery copies', 'Plaintext is the default', 'owner', 'backup policy']) assert.match(threat, new RegExp(phrase.replace(/ /g, '\\s+'), 'i'));
  const migration = docs['v3-migration-safety-v1.md'].replace(/\s+/g, ' '); for (const phrase of ['manifest with `integrity` omitted', '["amf.migration-manifest/v1/integrity", payloadDigest, keyId]', 'unpadded base64url', 'reject a digest or signature mismatch']) assert.ok(migration.includes(phrase), phrase);
  for (const text of Object.values(docs)) assert.doesNotMatch(text, /(?:\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\/home\/|\/root\/|https?:\/\/|@)/i);
});
