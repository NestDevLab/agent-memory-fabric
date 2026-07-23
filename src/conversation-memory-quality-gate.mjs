import crypto from 'node:crypto';

import { canonicalJson } from './ingest/transcripts/canonical.mjs';

export const CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA = 'amf.conversation-memory-quality-policy/v1';
export const CONVERSATION_MEMORY_QUALITY_REPORT_SCHEMA = 'amf.conversation-memory-quality-report/v1';
export const CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA = 'amf.conversation-memory-quality-key/v1';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const COUNTERS = ['requested', 'scanned', 'triageRejected', 'modelAttempted', 'modelSucceeded', 'modelFailed', 'modelNoOp', 'candidateClaims', 'duplicateClaims', 'wouldProposeClaims', 'invalidOrUnsafeClaims'];
const RATES = ['promotionBps', 'triageRejectedBps', 'duplicateBps', 'noOpBps', 'modelFailureBps', 'invalidOrUnsafeBps'];
const REASONS = new Set(['quality_threshold_requested', 'quality_threshold_scanned', 'quality_threshold_model_succeeded', 'quality_threshold_promotion', 'quality_threshold_triage_rejected', 'quality_threshold_duplicate', 'quality_threshold_noop', 'quality_threshold_model_failure', 'quality_threshold_invalid_or_unsafe']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function snapshot(value, depth = 0) {
  if (depth > 16) fail('quality_input_invalid');
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 64) fail('quality_input_invalid');
    return value.map((_, index) => { const d = Object.getOwnPropertyDescriptor(value, String(index)); if (!d || !('value' in d)) fail('quality_input_invalid'); return snapshot(d.value, depth + 1); });
  }
  if (!plain(value)) fail('quality_input_invalid');
  const output = {};
  for (const key of Object.keys(value).sort()) {
    const d = Object.getOwnPropertyDescriptor(value, key); if (!d || !('value' in d)) fail('quality_input_invalid');
    Object.defineProperty(output, key, { value: snapshot(d.value, depth + 1), enumerable: true, writable: true, configurable: true });
  }
  return output;
}
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function bps(numerator, denominator) {
  if (!Number.isSafeInteger(denominator) || denominator < 0) fail('quality_counts_invalid');
  return denominator === 0 ? 0 : Math.floor((numerator * 10000) / denominator);
}
function validTime(value) { return typeof value === 'string' && TIME.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z'); }
function validateKey(value) {
  const key = snapshot(value);
  if (!exact(key, ['schema', 'keyId', 'key']) || key.schema !== CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA || !KEY_ID.test(key.keyId) || typeof key.key !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(key.key) || Buffer.from(key.key, 'base64').length !== 32 || Buffer.from(key.key, 'base64').toString('base64') !== key.key) fail('quality_key_invalid');
  return key;
}
function validatePolicy(value) {
  const policy = snapshot(value);
  const thresholdKeys = ['minRequested', 'minScanned', 'minModelSucceeded', 'minPromotionBps', 'minTriageRejectedBps', 'maxTriageRejectedBps', 'maxDuplicateBps', 'maxNoOpBps', 'maxModelFailureBps', 'maxInvalidOrUnsafeBps'];
  if (!exact(policy, ['schema', 'revision', 'maxClaimsPerModel', 'thresholds']) || policy.schema !== CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA || !KEY_ID.test(policy.revision) || !Number.isSafeInteger(policy.maxClaimsPerModel) || policy.maxClaimsPerModel < 1 || policy.maxClaimsPerModel > 3 || !exact(policy.thresholds, thresholdKeys)) fail('quality_policy_invalid');
  for (const key of thresholdKeys) if (!Number.isSafeInteger(policy.thresholds[key]) || policy.thresholds[key] < 0 || (key.endsWith('Bps') && policy.thresholds[key] > 10000)) fail('quality_policy_invalid');
  const t = policy.thresholds;
  if (t.minRequested < 1 || t.minRequested > 20 || t.minScanned < 1 || t.minScanned > t.minRequested || t.minModelSucceeded < 1 || t.minModelSucceeded > t.minScanned || t.minPromotionBps > 10000 || t.minTriageRejectedBps > t.maxTriageRejectedBps) fail('quality_policy_invalid');
  return policy;
}
function validateCounters(value, policy) {
  const counts = snapshot(value);
  if (!exact(counts, COUNTERS) || COUNTERS.some(key => !Number.isSafeInteger(counts[key]) || counts[key] < 0) || counts.requested > 20 || counts.scanned !== counts.requested || counts.scanned !== counts.triageRejected + counts.modelAttempted || counts.modelAttempted !== counts.modelSucceeded + counts.modelFailed || counts.modelNoOp > counts.modelSucceeded || counts.duplicateClaims + counts.wouldProposeClaims + counts.invalidOrUnsafeClaims !== counts.candidateClaims) fail('quality_counts_invalid');
  const nonNoOp = counts.modelSucceeded - counts.modelNoOp;
  if ((counts.candidateClaims === 0 && nonNoOp !== 0) || (counts.candidateClaims > 0 && (nonNoOp < 1 || counts.candidateClaims < nonNoOp || counts.candidateClaims > nonNoOp * policy.maxClaimsPerModel))) fail('quality_counts_invalid');
  return counts;
}
function deriveRates(counts) { return { promotionBps: bps(counts.wouldProposeClaims, counts.candidateClaims), triageRejectedBps: bps(counts.triageRejected, counts.scanned), duplicateBps: bps(counts.duplicateClaims, counts.candidateClaims), noOpBps: bps(counts.modelNoOp, counts.modelSucceeded), modelFailureBps: bps(counts.modelFailed, counts.modelAttempted), invalidOrUnsafeBps: bps(counts.invalidOrUnsafeClaims, counts.candidateClaims) }; }
function assess(counts, rates, policy) {
  const t = policy.thresholds; const reasons = [];
  if (counts.requested < t.minRequested) reasons.push('quality_threshold_requested');
  if (counts.scanned < t.minScanned) reasons.push('quality_threshold_scanned');
  if (counts.modelSucceeded < t.minModelSucceeded) reasons.push('quality_threshold_model_succeeded');
  if (rates.promotionBps < t.minPromotionBps) reasons.push('quality_threshold_promotion');
  if (rates.triageRejectedBps < t.minTriageRejectedBps || rates.triageRejectedBps > t.maxTriageRejectedBps) reasons.push('quality_threshold_triage_rejected');
  if (rates.duplicateBps > t.maxDuplicateBps) reasons.push('quality_threshold_duplicate');
  if (rates.noOpBps > t.maxNoOpBps) reasons.push('quality_threshold_noop');
  if (rates.modelFailureBps > t.maxModelFailureBps) reasons.push('quality_threshold_model_failure');
  if (rates.invalidOrUnsafeBps > t.maxInvalidOrUnsafeBps) reasons.push('quality_threshold_invalid_or_unsafe');
  return { outcome: reasons.length ? 'fail' : 'pass', reasons };
}
function validReasons(value) {
  return Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype && value.length <= REASONS.size
    && value.every(reason => typeof reason === 'string' && REASONS.has(reason)) && new Set(value).size === value.length;
}
function sameArray(left, right) { return left.length === right.length && left.every((value, index) => value === right[index]); }
function payload(report) { return { schema: report.schema, policyDigest: report.policyDigest, releaseDigest: report.releaseDigest, configDigest: report.configDigest, completedAt: report.completedAt, sample: report.sample, rates: report.rates, outcome: report.outcome, reasons: report.reasons, keyId: report.keyId }; }
function sign(payloadValue, key) { return crypto.createHmac('sha256', Buffer.from(key.key, 'base64')).update(canonicalJson(payloadValue), 'utf8').digest('base64'); }

export function createConversationMemoryQualityReport({ policy, key, releaseDigest, configDigest, completedAt, sample }) {
  const normalizedPolicy = validatePolicy(policy); const normalizedKey = validateKey(key); const counts = validateCounters(sample, normalizedPolicy);
  if (!DIGEST.test(releaseDigest) || !DIGEST.test(configDigest) || !validTime(completedAt)) fail('quality_input_invalid');
  const rates = deriveRates(counts); const assessment = assess(counts, rates, normalizedPolicy);
  const report = { schema: CONVERSATION_MEMORY_QUALITY_REPORT_SCHEMA, policyDigest: digest(normalizedPolicy), releaseDigest, configDigest, completedAt, sample: counts, rates, outcome: assessment.outcome, reasons: assessment.reasons, keyId: normalizedKey.keyId };
  return { ...report, payloadDigest: digest(payload(report)), signature: sign(payload(report), normalizedKey) };
}

export function verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest, configDigest, now, maxAgeMs }) {
  try {
    const item = snapshot(report); const normalizedPolicy = validatePolicy(policy); const normalizedKey = validateKey(key);
    const fields = ['schema', 'policyDigest', 'releaseDigest', 'configDigest', 'completedAt', 'sample', 'rates', 'outcome', 'reasons', 'keyId', 'payloadDigest', 'signature'];
    if (!exact(item, fields) || item.schema !== CONVERSATION_MEMORY_QUALITY_REPORT_SCHEMA || !DIGEST.test(item.policyDigest) || !DIGEST.test(item.releaseDigest) || !DIGEST.test(item.configDigest) || !validTime(item.completedAt) || item.keyId !== normalizedKey.keyId || !['pass', 'fail'].includes(item.outcome) || !validReasons(item.reasons) || !DIGEST.test(item.payloadDigest) || typeof item.signature !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(item.signature)) return { ok: false, code: 'quality_report_invalid' };
    if (!DIGEST.test(releaseDigest) || !DIGEST.test(configDigest) || !validTime(now) || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0) return { ok: false, code: 'quality_verification_input_invalid' };
    const body = payload(item); if (item.payloadDigest !== digest(body)) return { ok: false, code: 'quality_payload_digest_mismatch' };
    const expected = Buffer.from(sign(body, normalizedKey), 'utf8'); const actual = Buffer.from(item.signature, 'utf8'); if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return { ok: false, code: 'quality_signature_invalid' };
    if (item.policyDigest !== digest(normalizedPolicy)) return { ok: false, code: 'quality_policy_mismatch' };
    if (item.releaseDigest !== releaseDigest) return { ok: false, code: 'quality_release_mismatch' };
    if (item.configDigest !== configDigest) return { ok: false, code: 'quality_config_mismatch' };
    const counts = validateCounters(item.sample, normalizedPolicy); const rates = deriveRates(counts); const assessment = assess(counts, rates, normalizedPolicy);
    if (!exact(item.rates, RATES) || RATES.some(name => item.rates[name] !== rates[name])) return { ok: false, code: 'quality_rates_invalid' };
    if (item.outcome !== assessment.outcome || !sameArray(item.reasons, assessment.reasons)) return { ok: false, code: 'quality_assessment_invalid' };
    if (item.outcome !== 'pass') return { ok: false, code: 'quality_outcome_not_pass' };
    const age = Date.parse(now) - Date.parse(item.completedAt); if (age < 0) return { ok: false, code: 'quality_report_future' }; if (age > maxAgeMs) return { ok: false, code: 'quality_report_stale' };
    return { ok: true, code: 'quality_gate_pass', outcome: 'pass', completedAt: item.completedAt, sample: { requested: counts.requested, scanned: counts.scanned }, rates };
  } catch (error) { return { ok: false, code: error?.code === 'quality_counts_invalid' ? 'quality_counts_invalid' : 'quality_report_invalid' }; }
}
