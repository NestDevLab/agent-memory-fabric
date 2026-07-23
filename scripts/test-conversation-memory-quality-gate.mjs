import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA, CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA, createConversationMemoryQualityReport, verifyConversationMemoryQualityGate } from '../src/conversation-memory-quality-gate.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';

const key = { schema: CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA, keyId: 'm5-test-key', key: Buffer.alloc(32, 7).toString('base64') };
const digest = character => `sha256:${character.repeat(64)}`;
const policy = { schema: CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA, revision: 'm5-example-policy', maxClaimsPerModel: 2, thresholds: {
  minRequested: 12, minScanned: 12, minModelSucceeded: 3,
  minPromotionBps: 2500, minTriageRejectedBps: 0, maxTriageRejectedBps: 9000,
  maxDuplicateBps: 5000, maxNoOpBps: 5000, maxModelFailureBps: 0, maxInvalidOrUnsafeBps: 0
} };
const sample = { requested: 12, scanned: 12, triageRejected: 6, modelAttempted: 6, modelSucceeded: 6, modelFailed: 0, modelNoOp: 2, candidateClaims: 5, duplicateClaims: 1, wouldProposeClaims: 4, invalidOrUnsafeClaims: 0 };
const input = ({ sample: localSample = sample, policy: localPolicy = policy, key: localKey = key } = {}) => ({ policy: localPolicy, key: localKey, releaseDigest: digest('a'), configDigest: digest('b'), completedAt: '2026-07-23T12:00:00Z', sample: localSample });
const verify = report => verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest: digest('a'), configDigest: digest('b'), now: '2026-07-23T12:05:00Z', maxAgeMs: 600000 });
function resign(report) {
  const payload = { schema: report.schema, policyDigest: report.policyDigest, releaseDigest: report.releaseDigest, configDigest: report.configDigest, completedAt: report.completedAt, sample: report.sample, rates: report.rates, outcome: report.outcome, reasons: report.reasons, keyId: report.keyId };
  report.payloadDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex')}`;
  report.signature = crypto.createHmac('sha256', Buffer.from(key.key, 'base64')).update(canonicalJson(payload), 'utf8').digest('base64');
  return report;
}

test('non-normative example policy produces a signed aggregate-only passing report', () => {
  const report = createConversationMemoryQualityReport(input());
  assert.equal(report.outcome, 'pass'); assert.deepEqual(report.reasons, []); assert.deepEqual(verify(report).ok, true);
  const serialized = JSON.stringify(report);
  for (const forbidden of ['"claim"', 'sessionId', 'conversationId', 'transcript', 'cursor', 'stderr', 'sourceId', 'provider', 'account', 'createdAt']) assert.equal(serialized.includes(forbidden), false, forbidden);
  assert.equal(report.sample.requested, 12); assert.equal(report.rates.promotionBps, 8000);
});

test('threshold boundaries are inclusive and zero denominators produce a signed failing report', () => {
  assert.equal(createConversationMemoryQualityReport(input()).outcome, 'pass');
  const below = { ...sample, wouldProposeClaims: 0, duplicateClaims: 5 };
  assert.deepEqual(createConversationMemoryQualityReport(input({ sample: below })).reasons, ['quality_threshold_promotion', 'quality_threshold_duplicate']);
  const emptyCandidates = { ...sample, modelNoOp: 6, candidateClaims: 0, duplicateClaims: 0, wouldProposeClaims: 0 };
  const emptyReport = createConversationMemoryQualityReport(input({ sample: emptyCandidates }));
  assert.equal(emptyReport.outcome, 'fail'); assert.equal(emptyReport.rates.promotionBps, 0); assert.equal(emptyReport.rates.duplicateBps, 0);
  assert.deepEqual(emptyReport.reasons, ['quality_threshold_promotion', 'quality_threshold_noop']);
  const allRejected = { ...sample, triageRejected: 12, modelAttempted: 0, modelSucceeded: 0, modelNoOp: 0, candidateClaims: 0, duplicateClaims: 0, wouldProposeClaims: 0 };
  assert.equal(createConversationMemoryQualityReport(input({ sample: allRejected })).outcome, 'fail');
  assert.throws(() => createConversationMemoryQualityReport(input({ sample: { ...sample, requested: 12, scanned: 11, triageRejected: 5 } })), /quality_counts_invalid/);
  assert.throws(() => createConversationMemoryQualityReport(input({ sample: { ...sample, requested: 21, scanned: 21 } })), /quality_counts_invalid/);
});

test('signed report verification rejects payload and identity tampering with stable codes', () => {
  const report = createConversationMemoryQualityReport(input());
  for (const [name, mutate, code] of [
    ['payload', value => { value.sample.wouldProposeClaims = 3; value.sample.duplicateClaims = 2; }, 'quality_payload_digest_mismatch'],
    ['outcome', value => { value.outcome = 'fail'; }, 'quality_payload_digest_mismatch'],
    ['reasons', value => { value.reasons = ['quality_threshold_noop']; }, 'quality_payload_digest_mismatch'],
    ['digest', value => { value.payloadDigest = digest('c'); }, 'quality_payload_digest_mismatch'],
    ['signature', value => { value.signature = Buffer.alloc(32, 9).toString('base64'); }, 'quality_signature_invalid'],
    ['key', value => { value.keyId = 'other-key'; }, 'quality_report_invalid']
  ]) {
    const changed = structuredClone(report); mutate(changed); assert.equal(verify(changed).code, code, name);
  }
  const combined = structuredClone(report); combined.releaseDigest = digest('c'); combined.sample.wouldProposeClaims = 3; combined.sample.duplicateClaims = 2;
  assert.equal(verify(combined).code, 'quality_payload_digest_mismatch', 'unauthenticated bindings cannot influence diagnostics');
  assert.equal(verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest: digest('c'), configDigest: digest('b'), now: '2026-07-23T12:05:00Z', maxAgeMs: 600000 }).code, 'quality_release_mismatch');
  assert.equal(verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest: digest('a'), configDigest: digest('c'), now: '2026-07-23T12:05:00Z', maxAgeMs: 600000 }).code, 'quality_config_mismatch');
  assert.equal(verifyConversationMemoryQualityGate({ report, policy: { ...policy, revision: 'changed-policy' }, key, releaseDigest: digest('a'), configDigest: digest('b'), now: '2026-07-23T12:05:00Z', maxAgeMs: 600000 }).code, 'quality_policy_mismatch');
  const wrongKey = { ...key, key: Buffer.alloc(32, 8).toString('base64') };
  assert.equal(verifyConversationMemoryQualityGate({ report, policy, key: wrongKey, releaseDigest: digest('a'), configDigest: digest('b'), now: '2026-07-23T12:05:00Z', maxAgeMs: 600000 }).code, 'quality_signature_invalid');
});

test('verification rejects stale, future, non-pass, malformed counts and hostile getters', () => {
  const report = createConversationMemoryQualityReport(input());
  assert.equal(verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest: digest('a'), configDigest: digest('b'), now: '2026-07-23T12:10:01Z', maxAgeMs: 600000 }).code, 'quality_report_stale');
  assert.equal(verifyConversationMemoryQualityGate({ report, policy, key, releaseDigest: digest('a'), configDigest: digest('b'), now: '2026-07-23T11:59:59Z', maxAgeMs: 600000 }).code, 'quality_report_future');
  const failed = createConversationMemoryQualityReport(input({ sample: { ...sample, modelFailed: 1, modelSucceeded: 5 } }));
  assert.equal(failed.outcome, 'fail'); assert.equal(verify(failed).code, 'quality_outcome_not_pass');
  const malformed = structuredClone(report); malformed.sample.scanned = 11; assert.equal(verify(resign(malformed)).code, 'quality_counts_invalid');
  const inconsistent = structuredClone(report); inconsistent.outcome = 'fail'; inconsistent.reasons = ['quality_threshold_noop'];
  assert.equal(verify(resign(inconsistent)).code, 'quality_assessment_invalid');
  const hostile = {}; Object.defineProperty(hostile, 'schema', { enumerable: true, get() { throw new Error('no getter'); } });
  assert.equal(verify(hostile).code, 'quality_report_invalid');
});

test('policy/key inputs reject getters and non-canonical key material', () => {
  const hostile = { ...policy }; Object.defineProperty(hostile, 'revision', { enumerable: true, get() { throw new Error('no getter'); } });
  assert.throws(() => createConversationMemoryQualityReport(input({ policy: hostile })), /quality_input_invalid/);
  assert.throws(() => createConversationMemoryQualityReport({ ...input(), key: { ...key, key: crypto.randomBytes(31).toString('base64') } }), /quality_key_invalid/);
  const polluted = structuredClone(policy); Object.defineProperty(polluted.thresholds, '__proto__', { value: { minRequested: 0 }, enumerable: true });
  assert.throws(() => createConversationMemoryQualityReport(input({ policy: polluted })), /quality_policy_invalid/);
});
