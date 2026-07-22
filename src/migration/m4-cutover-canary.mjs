import crypto from 'node:crypto';

import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

export const M4_CUTOVER_CANARY_SCHEMA = 'amf.m4-cutover-canary/v1';
export const M4_CUTOVER_CANARY_FAILURE_CATEGORIES = Object.freeze([
  'reader', 'config', 'auth', 'integrity', 'identity', 'cursorMigration', 'unexpectedDuplicate',
]);

const KEY_SCHEMA = 'amf.migration-signing-key/v1';
const DOMAIN = 'amf.m4-cutover-canary/v1/integrity';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43,86}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_SAMPLES = 100_000;
const MAX_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function snapshot(value, keys, code) {
  try {
    if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
    return Object.fromEntries(keys.map(key => [key, value[key]]));
  } catch (error) { if (error?.code === code) throw error; fail(code); }
}
function checkpoint(value, code) {
  const item = snapshot(value, ['id', 'digest'], code);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.digest !== 'string' || !DIGEST.test(item.digest)) fail(code);
  return item;
}
function utc(value, code) {
  if (typeof value !== 'string' || !value.endsWith('Z') || !isConversationEventUtcTimestamp(value)) fail(code);
  return value;
}
function timeKey(value, code) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(utc(value, code));
  if (!match) fail(code);
  return `${match[1]}.${(match[2] || '').padEnd(9, '0')}`;
}
function integer(value, code) { if (!Number.isSafeInteger(value) || value < 0) fail(code); return value; }
function keyDocument(value, code) {
  const item = snapshot(value, ['schema', 'keyId', 'key'], code);
  if (item.schema !== KEY_SCHEMA || typeof item.keyId !== 'string' || !ID.test(item.keyId) || typeof item.key !== 'string' || !BASE64.test(item.key)) fail(code);
  const key = Buffer.from(item.key, 'base64');
  if (key.length < 32 || key.length > 64 || key.toString('base64') !== item.key) { key.fill(0); fail(code); }
  return { keyId: item.keyId, key };
}
function policy(value, code) {
  const item = snapshot(value, ['start', 'end', 'maxSamples', 'queue', 'latency', 'allowed5xx', 'zeroRequiredCategories'], code);
  const queue = snapshot(item.queue, ['maxDepth', 'maxOldestAgeMs'], code);
  const latency = snapshot(item.latency, ['maxP95Ms', 'maxP99Ms', 'maxRequestMs'], code);
  if (timeKey(item.end, code) <= timeKey(item.start, code) || !Number.isSafeInteger(item.maxSamples)
    || item.maxSamples < 1 || item.maxSamples > MAX_SAMPLES
    || Date.parse(item.end) - Date.parse(item.start) > MAX_WINDOW_MS
    || canonicalJson(item.zeroRequiredCategories) !== canonicalJson(M4_CUTOVER_CANARY_FAILURE_CATEGORIES)) fail(code);
  for (const number of [queue.maxDepth, queue.maxOldestAgeMs, latency.maxP95Ms, latency.maxP99Ms, latency.maxRequestMs, item.allowed5xx]) integer(number, code);
  if (latency.maxP95Ms > latency.maxP99Ms || latency.maxP99Ms > latency.maxRequestMs) fail(code);
  return { start: item.start, end: item.end, maxSamples: item.maxSamples, queue, latency, allowed5xx: item.allowed5xx,
    zeroRequiredCategories: [...M4_CUTOVER_CANARY_FAILURE_CATEGORIES] };
}
function observations(value, selectedPolicy, code) {
  const item = snapshot(value, ['start', 'end', 'sampleCount', 'queue', 'latency', 'errors', 'rollbackDrill'], code);
  const queue = snapshot(item.queue, ['maxDepth', 'maxOldestAgeMs'], code);
  const latency = snapshot(item.latency, ['p95Ms', 'p99Ms', 'maxRequestMs'], code);
  const errors = snapshot(item.errors, ['http5xx', ...M4_CUTOVER_CANARY_FAILURE_CATEGORIES], code);
  const rollback = snapshot(item.rollbackDrill, ['state', 'configurationRevision', 'verification'], code);
  if (timeKey(item.start, code) < timeKey(selectedPolicy.start, code) || timeKey(item.end, code) > timeKey(selectedPolicy.end, code)
    || timeKey(item.end, code) <= timeKey(item.start, code) || !Number.isSafeInteger(item.sampleCount)
    || item.sampleCount < 1 || item.sampleCount > selectedPolicy.maxSamples || !['passed', 'failed'].includes(rollback.state)) fail(code);
  for (const number of [queue.maxDepth, queue.maxOldestAgeMs, latency.p95Ms, latency.p99Ms, latency.maxRequestMs,
    errors.http5xx, ...M4_CUTOVER_CANARY_FAILURE_CATEGORIES.map(category => errors[category])]) integer(number, code);
  if (latency.p95Ms > latency.p99Ms || latency.p99Ms > latency.maxRequestMs) fail(code);
  const configurationRevision = checkpoint(rollback.configurationRevision, code); const verification = checkpoint(rollback.verification, code);
  if (configurationRevision.id === verification.id || configurationRevision.digest === verification.digest) fail(code);
  return { start: item.start, end: item.end, sampleCount: item.sampleCount, queue, latency, errors,
    rollbackDrill: { state: rollback.state, configurationRevision, verification } };
}
function passed(selectedPolicy, observed) {
  return observed.queue.maxDepth <= selectedPolicy.queue.maxDepth
    && observed.queue.maxOldestAgeMs <= selectedPolicy.queue.maxOldestAgeMs
    && observed.latency.p95Ms <= selectedPolicy.latency.maxP95Ms
    && observed.latency.p99Ms <= selectedPolicy.latency.maxP99Ms
    && observed.latency.maxRequestMs <= selectedPolicy.latency.maxRequestMs
    && observed.errors.http5xx <= selectedPolicy.allowed5xx
    && M4_CUTOVER_CANARY_FAILURE_CATEGORIES.every(category => observed.errors[category] === 0)
    && observed.rollbackDrill.state === 'passed';
}
function sha(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function signatureFor(payloadDigest, loadedKey) {
  return crypto.createHmac('sha256', loadedKey.key).update(canonicalJson([DOMAIN, payloadDigest, loadedKey.keyId]), 'utf8').digest('base64url');
}
function payload(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'policy', 'observations', 'state'], code);
  if (item.schema !== M4_CUTOVER_CANARY_SCHEMA || typeof item.manifestId !== 'string' || !ID.test(item.manifestId)
    || !Number.isSafeInteger(item.revision) || item.revision < 1) fail(code);
  const selectedPolicy = policy(item.policy, code); const observed = observations(item.observations, selectedPolicy, code);
  const state = passed(selectedPolicy, observed) ? 'passed' : 'failed';
  if (item.state !== state) fail(code);
  return { schema: M4_CUTOVER_CANARY_SCHEMA, manifestId: item.manifestId, revision: item.revision,
    policy: selectedPolicy, observations: observed, state };
}
function signed(value, code) {
  const item = snapshot(value, ['schema', 'manifestId', 'revision', 'policy', 'observations', 'state', 'integrity'], code);
  const body = payload({ schema: item.schema, manifestId: item.manifestId, revision: item.revision,
    policy: item.policy, observations: item.observations, state: item.state }, code);
  const integrity = snapshot(item.integrity, ['algorithm', 'keyId', 'payloadDigest', 'signature'], code);
  if (integrity.algorithm !== 'hmac-sha256' || typeof integrity.keyId !== 'string' || !ID.test(integrity.keyId)
    || typeof integrity.payloadDigest !== 'string' || !DIGEST.test(integrity.payloadDigest)
    || typeof integrity.signature !== 'string' || !SIGNATURE.test(integrity.signature)) fail(code);
  return { ...body, integrity };
}

export function createM4CutoverCanaryManifest(value) {
  let input; try { input = structuredClone(value); } catch { fail('m4_cutover_canary_input_invalid'); }
  const item = snapshot(input, ['manifestId', 'revision', 'policy', 'observations', 'keyDocument'], 'm4_cutover_canary_input_invalid');
  const loaded = keyDocument(item.keyDocument, 'm4_cutover_canary_key_invalid');
  try {
    const selectedPolicy = policy(item.policy, 'm4_cutover_canary_input_invalid');
    const observed = observations(item.observations, selectedPolicy, 'm4_cutover_canary_input_invalid');
    const body = payload({ schema: M4_CUTOVER_CANARY_SCHEMA, manifestId: item.manifestId, revision: item.revision,
      policy: selectedPolicy, observations: observed, state: passed(selectedPolicy, observed) ? 'passed' : 'failed' }, 'm4_cutover_canary_input_invalid');
    const payloadDigest = sha(body);
    return structuredClone({ ...body, integrity: { algorithm: 'hmac-sha256', keyId: loaded.keyId, payloadDigest, signature: signatureFor(payloadDigest, loaded) } });
  } finally { loaded.key.fill(0); }
}

export function verifyM4CutoverCanaryManifest(value, keyDocumentValue) {
  let manifest; try { manifest = signed(structuredClone(value), 'm4_cutover_canary_manifest_invalid'); }
  catch (error) { if (error?.code) throw error; fail('m4_cutover_canary_manifest_invalid'); }
  const loaded = keyDocument(structuredClone(keyDocumentValue), 'm4_cutover_canary_key_invalid');
  try {
    if (manifest.integrity.keyId !== loaded.keyId) fail('m4_cutover_canary_key_id_mismatch');
    const { integrity, ...body } = manifest; const payloadDigest = sha(body);
    if (payloadDigest !== integrity.payloadDigest) fail('m4_cutover_canary_digest_mismatch');
    const expected = Buffer.from(signatureFor(payloadDigest, loaded), 'base64url'); const received = Buffer.from(integrity.signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) fail('m4_cutover_canary_signature_mismatch');
    return structuredClone(manifest);
  } finally { loaded.key.fill(0); }
}
