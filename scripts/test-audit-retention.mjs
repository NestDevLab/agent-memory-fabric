import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AUDIT_RETENTION_CLASSES, AuditSampler, DEFAULT_AUDIT_RETENTION_POLICY,
  auditRetentionActionsByClass, auditRetentionWindowDays, classifyAuditEvent,
  isAuditRetentionExpired, loadAuditRetentionPolicyFromEnv, validateAuditRetentionPolicy
} from '../src/audit-retention.mjs';

const ALL_ACTIONS = [
  'authenticate', 'context_search', 'curation_proposal_decrypt_intent', 'curation_proposal_list',
  'curation_proposal_read', 'curation_receipt', 'curation_reconcile', 'document_read', 'documents_search',
  'identity_create', 'identity_merge', 'identity_read', 'identity_split', 'memory_proposal_status',
  'memory_propose', 'memory_read', 'memory_search', 'memory_status', 'raw_delivery_proof', 'raw_event_ingest',
  'raw_extractor_session_read', 'raw_extractor_sessions_read', 'raw_extractor_transcript_read',
  'retention_apply', 'retention_plan', 'session_get', 'session_transcript', 'sessions_search'
];

test('§2.1 table: every long_retained action keeps that class on every outcome', () => {
  for (const action of auditRetentionActionsByClass('long_retained')) {
    for (const outcome of ['allowed', 'denied', 'failed', 'applied', 'duplicate', 'authorized']) {
      assert.equal(classifyAuditEvent(action, outcome), 'long_retained', `${action}/${outcome}`);
    }
  }
});

test('§2.1 table: memory_status/allowed is ephemeral_status, other outcomes are security_review', () => {
  assert.equal(classifyAuditEvent('memory_status', 'allowed'), 'ephemeral_status');
  assert.equal(classifyAuditEvent('memory_status', 'denied'), 'security_review');
  assert.equal(classifyAuditEvent('memory_status', 'failed'), 'security_review');
});

test('§2.1 table: ephemeral_operational actions on a non-failing outcome, security_review when denied/failed', () => {
  for (const action of auditRetentionActionsByClass('ephemeral_operational')) {
    assert.equal(classifyAuditEvent(action, 'allowed'), 'ephemeral_operational', action);
    assert.equal(classifyAuditEvent(action, 'stored'), 'ephemeral_operational', action);
    assert.equal(classifyAuditEvent(action, 'denied'), 'security_review', action);
    assert.equal(classifyAuditEvent(action, 'failed'), 'security_review', action);
  }
});

test('§2.1 table: authenticate is only ever audited on denial, which is security_review', () => {
  assert.equal(classifyAuditEvent('authenticate', 'denied'), 'security_review');
});

test('§1: the 28 known actions each classify without throwing for their real-world outcomes', () => {
  for (const action of ALL_ACTIONS) {
    const outcome = action === 'authenticate' ? 'denied' : 'allowed';
    assert.doesNotThrow(() => classifyAuditEvent(action, outcome), action);
  }
});

test('classifyAuditEvent rejects an action/outcome pair the table does not cover', () => {
  assert.throws(() => classifyAuditEvent('authenticate', 'allowed'), /audit_retention_class_unmapped/);
  assert.throws(() => classifyAuditEvent('totally_unknown_action', 'allowed'), /audit_retention_class_unmapped/);
});

test('classifyAuditEvent requires non-empty strings', () => {
  assert.throws(() => classifyAuditEvent('', 'allowed'), /audit_retention_action_invalid/);
  assert.throws(() => classifyAuditEvent('memory_status', ''), /audit_retention_outcome_invalid/);
});

test('the four retention classes and default windows match §2.2', () => {
  assert.deepEqual([...AUDIT_RETENTION_CLASSES].sort(), ['ephemeral_operational', 'ephemeral_status', 'long_retained', 'security_review']);
  assert.equal(auditRetentionWindowDays('ephemeral_status'), 2);
  assert.equal(auditRetentionWindowDays('ephemeral_operational'), 10);
  assert.equal(auditRetentionWindowDays('security_review'), 90);
  assert.equal(auditRetentionWindowDays('long_retained'), null);
});

test('validateAuditRetentionPolicy accepts the default policy and rejects malformed entries', () => {
  assert.doesNotThrow(() => validateAuditRetentionPolicy(DEFAULT_AUDIT_RETENTION_POLICY));
  assert.throws(() => validateAuditRetentionPolicy({ ...DEFAULT_AUDIT_RETENTION_POLICY, ephemeral_status: { days: 0 } }), /audit_retention_policy_invalid/);
  assert.throws(() => validateAuditRetentionPolicy({ ...DEFAULT_AUDIT_RETENTION_POLICY, long_retained: { days: 5, externalArchive: false } }), /audit_retention_policy_invalid/);
});

test('loadAuditRetentionPolicyFromEnv applies documented bounds and defaults', () => {
  assert.deepEqual(loadAuditRetentionPolicyFromEnv({}), DEFAULT_AUDIT_RETENTION_POLICY);
  assert.equal(loadAuditRetentionPolicyFromEnv({ AMF_AUDIT_RETENTION_EPHEMERAL_STATUS_DAYS: '1' }).ephemeral_status.days, 1);
  assert.throws(() => loadAuditRetentionPolicyFromEnv({ AMF_AUDIT_RETENTION_EPHEMERAL_STATUS_DAYS: '4' }), /audit_retention_env_invalid/);
  assert.throws(() => loadAuditRetentionPolicyFromEnv({ AMF_AUDIT_RETENTION_EPHEMERAL_OPERATIONAL_DAYS: '6' }), /audit_retention_env_invalid/);
  assert.equal(loadAuditRetentionPolicyFromEnv({ AMF_AUDIT_RETENTION_LONG_RETAINED_EXTERNAL_ARCHIVE: 'true' }).long_retained.externalArchive, true);
});

test('isAuditRetentionExpired: boundary is strict — exactly at the window edge is retained, one tick past is expired', () => {
  const ts = '2026-01-01T00:00:00.000Z';
  const exactlyAtWindow = new Date(new Date(ts).getTime() + 2 * 86_400_000);
  const justInsideWindow = new Date(exactlyAtWindow.getTime() - 1);
  const justOutsideWindow = new Date(exactlyAtWindow.getTime() + 1);
  assert.equal(isAuditRetentionExpired('ephemeral_status', ts, exactlyAtWindow), false, 'ts = now - window is kept');
  assert.equal(isAuditRetentionExpired('ephemeral_status', ts, justInsideWindow), false);
  assert.equal(isAuditRetentionExpired('ephemeral_status', ts, justOutsideWindow), true, 'one ms past the window is expired');
});

test('isAuditRetentionExpired: long_retained never expires', () => {
  assert.equal(isAuditRetentionExpired('long_retained', '2000-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), false);
});

test('AuditSampler: a burst of N calls in one bucket flushes exactly one aggregated row with sampledCount = N', async () => {
  const flushed = [];
  let nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  const sampler = new AuditSampler({ bucketMs: 300_000, autoFlush: false, clock: () => nowMs, flush: async event => { flushed.push(event); } });
  for (let i = 0; i < 7; i += 1) sampler.record('actor-a');
  for (let i = 0; i < 3; i += 1) sampler.record('actor-b');
  nowMs += 300_000;
  await sampler.flushExpired();
  assert.equal(flushed.length, 2);
  const byActor = Object.fromEntries(flushed.map(event => [event.actorTag, event]));
  assert.equal(byActor['actor-a'].sampledCount, 7);
  assert.equal(byActor['actor-b'].sampledCount, 3);
  assert.equal(byActor['actor-a'].windowStart, new Date(Date.UTC(2026, 0, 1, 0, 0, 0)).toISOString());
  assert.equal(byActor['actor-a'].windowEnd, new Date(Date.UTC(2026, 0, 1, 0, 5, 0)).toISOString());
});

test('AuditSampler: a bucket not yet rolled over is never flushed early', async () => {
  const flushed = [];
  let nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  const sampler = new AuditSampler({ bucketMs: 300_000, autoFlush: false, clock: () => nowMs, flush: async event => { flushed.push(event); } });
  sampler.record('actor-a');
  nowMs += 299_999;
  await sampler.flushExpired();
  assert.equal(flushed.length, 0);
});

test('AuditSampler: close() flushes every remaining bucket regardless of rollover', async () => {
  const flushed = [];
  const sampler = new AuditSampler({ bucketMs: 300_000, autoFlush: false, clock: () => Date.UTC(2026, 0, 1), flush: async event => { flushed.push(event); } });
  sampler.record('actor-a');
  sampler.record('actor-a');
  await sampler.close();
  assert.equal(flushed.length, 1);
  assert.equal(flushed[0].sampledCount, 2);
  assert.throws(() => sampler.record('actor-a'), /audit_sampler_closed/);
});

test('AuditSampler never aggregates a non-allowed outcome — callers must not route denied/failed calls through record()', () => {
  // AuditSampler has no outcome parameter by design: §3 requires every
  // memory_status call with a non-allowed outcome, and every other action, to
  // keep writing through the normal per-call fail-closed audit path.
  const sampler = new AuditSampler({ bucketMs: 300_000, autoFlush: false, flush: async () => {} });
  assert.equal(typeof sampler.record, 'function');
  assert.equal(sampler.record.length, 1);
});

test('AuditSampler validates its construction inputs', () => {
  assert.throws(() => new AuditSampler({}), /audit_sampler_flush_required/);
  assert.throws(() => new AuditSampler({ flush: async () => {}, bucketMs: 10 }), /audit_sampler_bucket_ms_invalid/);
});
