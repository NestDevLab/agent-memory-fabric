import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { M4_CUTOVER_CANARY_FAILURE_CATEGORIES } from '../src/migration/m4-cutover-canary.mjs';
import { createM4PostRouteObservation, verifyM4PostRouteObservation } from '../src/migration/m4-post-route-observation.mjs';

const sha = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
const key = { schema: 'amf.migration-signing-key/v1', keyId: 'post-route-key', key: Buffer.alloc(32, 33).toString('base64') };
const digest = `sha256:${'a'.repeat(64)}`;
const evidence = { manifestId: 'route-authorization', digest, signature: 'A'.repeat(43) };
const checkpoint = id => ({ id, digest });
function activeResult() { const body = { schema: 'amf.m4-route-execution-result/v1', executionId: 'route-execution-one', revision: 1, state: 'active', planDigest: digest, authorization: evidence, selectorEvidence: { ...evidence, manifestId: 'selector-scope' }, targetRouteRevisions: { publicReader: checkpoint('public-reader'), extractorReader: checkpoint('extractor-reader') }, rollbackRevision: checkpoint('route-rollback'), beforeDigest: digest, afterDigest: `sha256:${'b'.repeat(64)}`, backup: checkpoint('route-backup'), postCommit: { state: 'passed' }, readiness: { state: 'passed' }, rollback: { state: 'not_needed' } }; return { ...body, integrity: { algorithm: 'sha256', payloadDigest: sha(body) } }; }
function reseal(result) { const { integrity, ...body } = result; return { ...body, integrity: { algorithm: 'sha256', payloadDigest: sha(body) } }; }
function input() { return { manifestId: 'post-route-observation', revision: 1, routeExecutionResult: activeResult(), policy: { start: '2026-07-23T00:00:00.000000001Z', end: '2026-07-24T00:00:00.000000001Z', maxSamples: 1, queue: { maxDepth: 0, maxOldestAgeMs: 0 }, latency: { maxP95Ms: 0, maxP99Ms: 0, maxRequestMs: 0 }, allowed5xx: 0, zeroRequiredCategories: [...M4_CUTOVER_CANARY_FAILURE_CATEGORIES] }, observations: { start: '2026-07-23T00:00:00.000000001Z', end: '2026-07-23T00:00:00.000000002Z', sampleCount: 1, queue: { maxDepth: 0, maxOldestAgeMs: 0 }, latency: { p95Ms: 0, p99Ms: 0, maxRequestMs: 0 }, errors: { http5xx: 0, ...Object.fromEntries(M4_CUTOVER_CANARY_FAILURE_CATEGORIES.map(name => [name, 0])) } }, keyDocument: key }; }

test('signs a threshold-equal active route observation and binds R1 digest', () => { const value = input(); const manifest = createM4PostRouteObservation(value); assert.equal(manifest.state, 'passed'); assert.equal(manifest.requiresRollback, false); assert.equal(manifest.routeExecution.resultDigest, value.routeExecutionResult.integrity.payloadDigest); assert.equal(manifest.routeExecution.readinessState, 'passed'); assert.deepEqual(verifyM4PostRouteObservation(manifest, key), manifest); assert.deepEqual(value, input()); });
test('each aggregate bound derives signed failed rollback-required evidence', () => { for (const mutate of [v => { v.observations.queue.maxDepth = 1; }, v => { v.observations.queue.maxOldestAgeMs = 1; }, v => { v.observations.latency = { p95Ms: 1, p99Ms: 1, maxRequestMs: 1 }; }, v => { v.observations.errors.http5xx = 1; }, v => { v.observations.errors.reader = 1; }]) { const value = input(); mutate(value); const manifest = createM4PostRouteObservation(value); assert.equal(manifest.state, 'failed'); assert.equal(manifest.requiresRollback, true); assert.deepEqual(verifyM4PostRouteObservation(manifest, key), manifest); } });
test('route tampering, non-active result, category drift, dates, key and hostile input fail closed', () => { const bad = input(); bad.routeExecutionResult.state = 'rolled_back'; assert.throws(() => createM4PostRouteObservation(bad), /m4_post_route_observation_route_invalid/); const tampered = input(); tampered.routeExecutionResult.afterDigest = digest; assert.throws(() => createM4PostRouteObservation(tampered), /m4_post_route_observation_route_invalid/); const categories = input(); categories.policy.zeroRequiredCategories.reverse(); assert.throws(() => createM4PostRouteObservation(categories), /m4_post_route_observation_input_invalid/); const dates = input(); dates.observations.end = '2026-02-30T00:00:00Z'; assert.throws(() => createM4PostRouteObservation(dates), /m4_post_route_observation_input_invalid/); const manifest = createM4PostRouteObservation(input()); assert.throws(() => verifyM4PostRouteObservation(manifest, { ...key, keyId: 'wrong-post-route-key' }), /m4_post_route_observation_key_id_mismatch/); assert.throws(() => createM4PostRouteObservation(new Proxy({}, { get() { throw new Error('hostile'); } })), /m4_post_route_observation_input_invalid/); });

test('accepts exact time, sample and policy boundaries and rejects their escapes', () => {
  const exact = input(); exact.observations.start = exact.policy.start; exact.observations.end = exact.policy.end; assert.equal(createM4PostRouteObservation(exact).state, 'passed');
  const over = input(); over.policy.end = '2026-07-24T00:00:00.000000002Z'; assert.throws(() => createM4PostRouteObservation(over), /m4_post_route_observation_input_invalid/);
  for (const mutate of [v => { v.observations.start = '2026-07-23T00:00:00.000000000Z'; }, v => { v.observations.end = '2026-07-24T00:00:00.000000002Z'; }, v => { v.observations.end = v.observations.start; }, v => { v.observations.sampleCount = 0; }, v => { v.observations.sampleCount = 2; }]) { const value = input(); mutate(value); assert.throws(() => createM4PostRouteObservation(value), /m4_post_route_observation_input_invalid/); }
  for (const samples of [1, 10_000]) { const value = input(); value.policy.maxSamples = samples; value.observations.sampleCount = samples; assert.equal(createM4PostRouteObservation(value).state, 'passed'); }
  for (const samples of [0, 10_001]) { const value = input(); value.policy.maxSamples = samples; assert.throws(() => createM4PostRouteObservation(value), /m4_post_route_observation_input_invalid/); }
});

test('rejects latency ordering, unsafe integers, and negative zero', () => {
  for (const mutate of [v => { v.policy.latency.maxP95Ms = 2; v.policy.latency.maxP99Ms = 1; }, v => { v.policy.latency.maxP99Ms = 2; v.policy.latency.maxRequestMs = 1; }, v => { v.observations.latency = { p95Ms: 2, p99Ms: 1, maxRequestMs: 2 }; }, v => { v.observations.latency = { p95Ms: 1, p99Ms: 2, maxRequestMs: 1 }; }, v => { v.observations.queue.maxDepth = -0; }, v => { v.policy.allowed5xx = Number.MAX_SAFE_INTEGER + 1; }]) { const value = input(); mutate(value); assert.throws(() => createM4PostRouteObservation(value), /m4_post_route_observation_input_invalid/); }
});

test('all seven zero-required categories independently fail', () => { for (const category of M4_CUTOVER_CANARY_FAILURE_CATEGORIES) { const value = input(); value.observations.errors[category] = 1; const manifest = createM4PostRouteObservation(value); assert.equal(manifest.state, 'failed', category); assert.equal(manifest.requiresRollback, true, category); } });

test('every active R1 hook invariant and R1 integrity tampering is rejected', () => {
  for (const mutate of [r => { r.state = 'rolled_back'; r.rollback.state = 'passed'; }, r => { r.postCommit.state = 'failed'; }, r => { r.readiness.state = 'failed'; }, r => { r.rollback.state = 'passed'; }]) { const value = input(); mutate(value.routeExecutionResult); value.routeExecutionResult = reseal(value.routeExecutionResult); assert.throws(() => createM4PostRouteObservation(value), /m4_post_route_observation_route_invalid/); }
  for (const mutate of [r => { r.afterDigest = digest; }, r => { r.integrity.payloadDigest = digest; }]) { const value = input(); mutate(value.routeExecutionResult); assert.throws(() => createM4PostRouteObservation(value), /m4_post_route_observation_route_invalid/); }
});

test('verification rejects signed body, digest, signature, key and shape tampering', () => {
  const manifest = createM4PostRouteObservation(input());
  for (const mutate of [m => { m.state = 'failed'; }, m => { m.integrity.payloadDigest = digest; }, m => { m.integrity.signature = 'B'.repeat(43); }, m => { m.extra = true; }]) { const altered = structuredClone(manifest); mutate(altered); assert.throws(() => verifyM4PostRouteObservation(altered, key), /m4_post_route_observation_/); }
  const decodedSignature = Buffer.from(manifest.integrity.signature, 'base64url');
  const noncanonicalLast = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_']
    .find(character => character !== manifest.integrity.signature.at(-1)
      && Buffer.from(`${manifest.integrity.signature.slice(0, -1)}${character}`, 'base64url').equals(decodedSignature));
  assert.ok(noncanonicalLast);
  const noncanonical = structuredClone(manifest);
  noncanonical.integrity.signature = `${manifest.integrity.signature.slice(0, -1)}${noncanonicalLast}`;
  assert.throws(() => verifyM4PostRouteObservation(noncanonical, key), /m4_post_route_observation_signature_mismatch/);
  for (const badKey of [{ ...key, key: Buffer.alloc(31, 33).toString('base64') }, { ...key, key: `${key.key}=` }, { ...key, keyId: 'bad' }, { ...key, key: Buffer.alloc(32, 34).toString('base64') }]) assert.throws(() => verifyM4PostRouteObservation(manifest, badKey), /m4_post_route_observation_/);
  const missing = structuredClone(manifest); delete missing.policy; assert.throws(() => verifyM4PostRouteObservation(missing, key), /m4_post_route_observation_manifest_invalid/);
});

test('rejects accessors, symbols, non-enumerables and cycles; verification is detached', () => {
  const accessor = input(); Object.defineProperty(accessor, 'policy', { enumerable: true, get() { return input().policy; } }); assert.throws(() => createM4PostRouteObservation(accessor), /m4_post_route_observation_input_invalid/);
  const symbol = input(); symbol[Symbol('private')] = true; assert.throws(() => createM4PostRouteObservation(symbol), /m4_post_route_observation_input_invalid/);
  const hidden = input(); Object.defineProperty(hidden, 'hidden', { value: true, enumerable: false }); assert.throws(() => createM4PostRouteObservation(hidden), /m4_post_route_observation_input_invalid/);
  const cyclic = input(); cyclic.self = cyclic; assert.throws(() => createM4PostRouteObservation(cyclic), /m4_post_route_observation_input_invalid/);
  const manifest = createM4PostRouteObservation(input()); const verified = verifyM4PostRouteObservation(manifest, key); verified.policy.maxSamples = 9; assert.equal(verifyM4PostRouteObservation(manifest, key).policy.maxSamples, 1);
});
