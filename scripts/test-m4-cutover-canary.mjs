import assert from 'node:assert/strict';
import test from 'node:test';

import { createM4CutoverCanaryManifest, verifyM4CutoverCanaryManifest } from '../src/migration/m4-cutover-canary.mjs';

const digest = value => `sha256:${value.repeat(64)}`;
const key = (keyId = 'canary-key-one', byte = 1) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
const checkpoint = (id, value) => ({ id, digest: digest(value) });
const categories = ['reader', 'config', 'auth', 'integrity', 'identity', 'cursorMigration', 'unexpectedDuplicate'];
function input() {
  return { manifestId: 'canary-manifest-one', revision: 1, keyDocument: key(),
    policy: { start: '2026-01-01T00:00:00.000000000Z', end: '2026-01-01T01:00:00Z', maxSamples: 20,
      queue: { maxDepth: 2, maxOldestAgeMs: 3000 }, latency: { maxP95Ms: 100, maxP99Ms: 200, maxRequestMs: 500 },
      allowed5xx: 0, zeroRequiredCategories: [...categories] },
    observations: { start: '2026-01-01T00:00:00.000000001Z', end: '2026-01-01T00:59:59.999999999Z', sampleCount: 20,
      queue: { maxDepth: 2, maxOldestAgeMs: 3000 }, latency: { p95Ms: 100, p99Ms: 200, maxRequestMs: 500 },
      errors: { http5xx: 0, reader: 0, config: 0, auth: 0, integrity: 0, identity: 0, cursorMigration: 0, unexpectedDuplicate: 0 },
      rollbackDrill: { state: 'passed', configurationRevision: checkpoint('canary-config-revision', 'a'), verification: checkpoint('canary-rollback-verification', 'b') } } };
}

test('signs threshold-equal passed evidence and preserves nanosecond-bounded observation time', () => {
  const value = input(); const before = structuredClone(value); const manifest = createM4CutoverCanaryManifest(value);
  assert.deepEqual(value, before); assert.equal(manifest.schema, 'amf.m4-cutover-canary/v1'); assert.equal(manifest.state, 'passed');
  assert.equal(manifest.observations.start, '2026-01-01T00:00:00.000000001Z');
  assert.deepEqual(verifyM4CutoverCanaryManifest(manifest, key()), manifest);
});

test('derives failed evidence for every threshold and rollback failure', () => {
  const mutations = [
    value => { value.observations.queue.maxDepth = 3; }, value => { value.observations.queue.maxOldestAgeMs = 3001; },
    value => { value.observations.latency.p95Ms = 101; }, value => { value.observations.latency.p99Ms = 201; },
    value => { value.observations.latency.maxRequestMs = 501; }, value => { value.observations.errors.http5xx = 1; },
    ...categories.map(category => value => { value.observations.errors[category] = 1; }),
    value => { value.observations.rollbackDrill.state = 'failed'; },
  ];
  for (const mutate of mutations) { const value = input(); mutate(value); assert.equal(createM4CutoverCanaryManifest(value).state, 'failed'); }
});

test('rejects observation escape, invalid threshold ordering, sample overflow, and category drift', () => {
  for (const mutate of [
    value => { value.observations.start = '2025-12-31T23:59:59.999999999Z'; },
    value => { value.observations.end = '2026-01-01T01:00:00.000000001Z'; },
    value => { value.policy.latency.maxP95Ms = 201; }, value => { value.observations.latency.p95Ms = 201; },
    value => { value.observations.sampleCount = 21; }, value => { value.policy.zeroRequiredCategories.reverse(); },
    value => { value.policy.start = '2026-02-30T00:00:00Z'; },
    value => { value.policy.end = '2026-01-09T00:00:00Z'; },
  ]) { const value = input(); mutate(value); assert.throws(() => createM4CutoverCanaryManifest(value), /m4_cutover_canary_input_invalid/); }
});

test('tamper, wrong key id, wrong key material, and extra fields fail closed', () => {
  const manifest = createM4CutoverCanaryManifest(input()); manifest.observations.sampleCount -= 1;
  assert.throws(() => verifyM4CutoverCanaryManifest(manifest, key()), /m4_cutover_canary_digest_mismatch/);
  assert.throws(() => verifyM4CutoverCanaryManifest(createM4CutoverCanaryManifest(input()), key('other-canary-key', 1)), /m4_cutover_canary_key_id_mismatch/);
  assert.throws(() => verifyM4CutoverCanaryManifest(createM4CutoverCanaryManifest(input()), key('canary-key-one', 2)), /m4_cutover_canary_signature_mismatch/);
  const extra = input(); extra.command = 'never'; assert.throws(() => createM4CutoverCanaryManifest(extra), /m4_cutover_canary_input_invalid/);
});

test('hostile input and malformed verifier values expose fixed errors', () => {
  assert.throws(() => createM4CutoverCanaryManifest(new Proxy({}, { get() { throw new Error('private'); } })), /m4_cutover_canary_input_invalid/);
  assert.throws(() => verifyM4CutoverCanaryManifest({}, key()), /m4_cutover_canary_manifest_invalid/);
  assert.throws(() => verifyM4CutoverCanaryManifest({ uncloneable: () => 'private' }, key()), error => error.code === 'm4_cutover_canary_manifest_invalid');
});
