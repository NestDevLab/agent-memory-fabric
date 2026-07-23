import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { M4_CUTOVER_CANARY_FAILURE_CATEGORIES } from './m4-cutover-canary.mjs';
import { verifyM4RouteExecutionResult } from '../operator/m4-route-executor.mjs';

export const M4_POST_ROUTE_OBSERVATION_SCHEMA = 'amf.m4-post-route-observation/v1';
const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-post-route-observation/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const HMAC_SIGNATURE = /^[A-Za-z0-9_-]{43}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const DAY_NS = 24n * 60n * 60n * 1_000_000_000n;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function safeClone(value, code, seen = new WeakSet(), count = { value: 0 }) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (typeof value !== 'object' || seen.has(value) || ++count.value > 256) fail(code);
  seen.add(value); let descriptors; try { descriptors = Object.getOwnPropertyDescriptors(value); } catch { fail(code); }
  const keys = Reflect.ownKeys(descriptors); if (keys.some(key => typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value'))) fail(code);
  if (Array.isArray(value)) { if (keys.length > 16 || keys.some(key => key !== 'length' && (!/^\d+$/.test(key) || Number(key) >= value.length))) fail(code); return Array.from({ length: value.length }, (_, index) => safeClone(descriptors[String(index)]?.value, code, seen, count)); }
  if (Object.getPrototypeOf(value) !== Object.prototype || keys.length > 32) fail(code);
  return Object.fromEntries(keys.map(key => [key, safeClone(descriptors[key].value, code, seen, count)]));
}
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function snapshot(value, keys, code) { try { if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code); return Object.fromEntries(keys.map(key => [key, value[key]])); } catch (error) { if (error?.code === code) throw error; fail(code); } }
function integer(value, code) { if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) fail(code); return value; }
function utc(value, code) {
  if (typeof value !== 'string') fail(code); const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value); if (!match) fail(code);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number); const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0); const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) fail(code); return value;
}
function nanos(value, code) { const match = /^(.*?)(?:\.(\d{1,9}))?Z$/.exec(utc(value, code)); return BigInt(Date.parse(`${match[1]}Z`)) * 1_000_000n + BigInt((match[2] ?? '').padEnd(9, '0') || '0'); }
function keyDocument(value, code) { const item = snapshot(value, ['schema', 'keyId', 'key'], code); if (item.schema !== KEY_SCHEMA || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code); const key = Buffer.from(item.key, 'base64'); if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) { key.fill(0); fail(code); } return { keyId: item.keyId, key }; }
function sha(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(payloadDigest, loaded) { return crypto.createHmac('sha256', loaded.key).update(canonicalJson([DOMAIN, payloadDigest, loaded.keyId]), 'utf8').digest('base64url'); }
function policy(value, code) {
  const item = snapshot(value, ['start', 'end', 'maxSamples', 'queue', 'latency', 'allowed5xx', 'zeroRequiredCategories'], code); const queue = snapshot(item.queue, ['maxDepth', 'maxOldestAgeMs'], code); const latency = snapshot(item.latency, ['maxP95Ms', 'maxP99Ms', 'maxRequestMs'], code);
  const start = nanos(item.start, code); const end = nanos(item.end, code); if (end <= start || end - start > DAY_NS || !Number.isSafeInteger(item.maxSamples) || item.maxSamples < 1 || item.maxSamples > 10_000 || canonicalJson(item.zeroRequiredCategories) !== canonicalJson(M4_CUTOVER_CANARY_FAILURE_CATEGORIES)) fail(code);
  for (const n of [queue.maxDepth, queue.maxOldestAgeMs, latency.maxP95Ms, latency.maxP99Ms, latency.maxRequestMs, item.allowed5xx]) integer(n, code); if (latency.maxP95Ms > latency.maxP99Ms || latency.maxP99Ms > latency.maxRequestMs) fail(code);
  return { start: item.start, end: item.end, maxSamples: item.maxSamples, queue, latency, allowed5xx: item.allowed5xx, zeroRequiredCategories: [...M4_CUTOVER_CANARY_FAILURE_CATEGORIES] };
}
function observations(value, selected, code) {
  const item = snapshot(value, ['start', 'end', 'sampleCount', 'queue', 'latency', 'errors'], code); const queue = snapshot(item.queue, ['maxDepth', 'maxOldestAgeMs'], code); const latency = snapshot(item.latency, ['p95Ms', 'p99Ms', 'maxRequestMs'], code); const errors = snapshot(item.errors, ['http5xx', ...M4_CUTOVER_CANARY_FAILURE_CATEGORIES], code);
  const start = nanos(item.start, code); const end = nanos(item.end, code); if (start < nanos(selected.start, code) || end > nanos(selected.end, code) || end <= start || !Number.isSafeInteger(item.sampleCount) || item.sampleCount < 1 || item.sampleCount > selected.maxSamples) fail(code);
  for (const n of [queue.maxDepth, queue.maxOldestAgeMs, latency.p95Ms, latency.p99Ms, latency.maxRequestMs, errors.http5xx, ...M4_CUTOVER_CANARY_FAILURE_CATEGORIES.map(category => errors[category])]) integer(n, code); if (latency.p95Ms > latency.p99Ms || latency.p99Ms > latency.maxRequestMs) fail(code);
  return { start: item.start, end: item.end, sampleCount: item.sampleCount, queue, latency, errors };
}
function passed(selected, observed) { return observed.queue.maxDepth <= selected.queue.maxDepth && observed.queue.maxOldestAgeMs <= selected.queue.maxOldestAgeMs && observed.latency.p95Ms <= selected.latency.maxP95Ms && observed.latency.p99Ms <= selected.latency.maxP99Ms && observed.latency.maxRequestMs <= selected.latency.maxRequestMs && observed.errors.http5xx <= selected.allowed5xx && M4_CUTOVER_CANARY_FAILURE_CATEGORIES.every(category => observed.errors[category] === 0); }
function evidence(value, code) { const item = snapshot(value, ['manifestId', 'digest', 'signature'], code); if (!ID.test(item.manifestId) || !DIGEST.test(item.digest) || !SIGNATURE.test(item.signature)) fail(code); return item; }
function checkpoint(value, code) { const item = snapshot(value, ['id', 'digest'], code); if (!ID.test(item.id) || !DIGEST.test(item.digest)) fail(code); return item; }
function routeExecution(value, code) { const item = snapshot(value, ['executionId', 'revision', 'resultDigest', 'authorization', 'targetRouteRevisions', 'afterDigest', 'readinessState'], code); if (!ID.test(item.executionId) || !Number.isSafeInteger(item.revision) || item.revision < 1 || !DIGEST.test(item.resultDigest) || !DIGEST.test(item.afterDigest) || item.readinessState !== 'passed') fail(code); evidence(item.authorization, code); const targetRouteRevisions = snapshot(item.targetRouteRevisions, ['publicReader', 'extractorReader'], code); checkpoint(targetRouteRevisions.publicReader, code); checkpoint(targetRouteRevisions.extractorReader, code); return { ...item, targetRouteRevisions }; }
function fromResult(value, code) { let result; try { result = verifyM4RouteExecutionResult(value); } catch { fail(code); } if (result.state !== 'active' || result.postCommit.state !== 'passed' || result.readiness.state !== 'passed' || result.rollback.state !== 'not_needed') fail(code); return { executionId: result.executionId, revision: result.revision, resultDigest: result.integrity.payloadDigest, authorization: result.authorization, targetRouteRevisions: result.targetRouteRevisions, afterDigest: result.afterDigest, readinessState: 'passed' }; }
function payload(value, code) { const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'requiresRollback', 'routeExecution', 'policy', 'observations'], code); if (item.schema !== M4_POST_ROUTE_OBSERVATION_SCHEMA || !ID.test(item.manifestId) || !Number.isSafeInteger(item.revision) || item.revision < 1) fail(code); const selected = policy(item.policy, code); const observed = observations(item.observations, selected, code); const state = passed(selected, observed) ? 'passed' : 'failed'; if (item.state !== state || item.requiresRollback !== (state === 'failed')) fail(code); return { schema: M4_POST_ROUTE_OBSERVATION_SCHEMA, manifestId: item.manifestId, revision: item.revision, state, requiresRollback: state === 'failed', routeExecution: routeExecution(item.routeExecution, code), policy: selected, observations: observed }; }
function signed(value, code) { const item = snapshot(value, ['schema', 'manifestId', 'revision', 'state', 'requiresRollback', 'routeExecution', 'policy', 'observations', 'integrity'], code); const body = payload({ schema: item.schema, manifestId: item.manifestId, revision: item.revision, state: item.state, requiresRollback: item.requiresRollback, routeExecution: item.routeExecution, policy: item.policy, observations: item.observations }, code); const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code); if (integrity.algorithm !== 'hmac-sha256' || !ID.test(integrity.keyId) || !DIGEST.test(integrity.payloadDigest) || !HMAC_SIGNATURE.test(integrity.signature)) fail(code); return { ...body, integrity }; }

export function createM4PostRouteObservation(value) {
  let input; try { input = safeClone(value, 'm4_post_route_observation_input_invalid'); } catch { fail('m4_post_route_observation_input_invalid'); }
  const item = snapshot(input, ['manifestId', 'revision', 'routeExecutionResult', 'policy', 'observations', 'keyDocument'], 'm4_post_route_observation_input_invalid'); const loaded = keyDocument(item.keyDocument, 'm4_post_route_observation_key_invalid');
  try { const route = fromResult(item.routeExecutionResult, 'm4_post_route_observation_route_invalid'); const selected = policy(item.policy, 'm4_post_route_observation_input_invalid'); const observed = observations(item.observations, selected, 'm4_post_route_observation_input_invalid'); const state = passed(selected, observed) ? 'passed' : 'failed'; const body = payload({ schema: M4_POST_ROUTE_OBSERVATION_SCHEMA, manifestId: item.manifestId, revision: item.revision, state, requiresRollback: state === 'failed', routeExecution: route, policy: selected, observations: observed }, 'm4_post_route_observation_input_invalid'); const payloadDigest = sha(body); return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: signatureFor(payloadDigest, loaded) } }); } finally { loaded.key.fill(0); }
}
export function verifyM4PostRouteObservation(value, keyDocumentValue) {
  let manifest; try { manifest = signed(safeClone(value, 'm4_post_route_observation_manifest_invalid'), 'm4_post_route_observation_manifest_invalid'); } catch (error) { if (error?.code?.startsWith?.('m4_')) throw error; fail('m4_post_route_observation_manifest_invalid'); } const loaded = keyDocument(safeClone(keyDocumentValue, 'm4_post_route_observation_key_invalid'), 'm4_post_route_observation_key_invalid');
  try { if (manifest.integrity.keyId !== loaded.keyId) fail('m4_post_route_observation_key_id_mismatch'); const { integrity, ...body } = manifest; const payloadDigest = sha(body); if (payloadDigest !== integrity.payloadDigest) fail('m4_post_route_observation_digest_mismatch'); const expected = Buffer.from(signatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url'); if (received.toString('base64url') !== integrity.signature || expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_post_route_observation_signature_mismatch'); return safeClone(manifest, 'm4_post_route_observation_manifest_invalid'); } finally { loaded.key.fill(0); }
}
