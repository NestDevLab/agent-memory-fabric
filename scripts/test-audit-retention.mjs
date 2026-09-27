import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  AUDIT_RETENTION_CLASSES, AUDIT_RETENTION_TABLE, AuditSampler, DEFAULT_AUDIT_RETENTION_POLICY,
  auditRetentionCutoff, auditRetentionPairsByClass, auditRetentionWindowDays, buildPhaseAPredicate,
  classifyAuditEvent, classifyAuditEventStrict, isAuditRetentionExpired, loadAuditRetentionPolicyFromEnv,
  validateAuditRetentionPolicy
} from '../src/audit-retention.mjs';
import { qualifiedAuditTable } from '../src/audit-retention-cleanup.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

function sourceFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith('.mjs') ? [full] : [];
  });
}

const EXPECTED = {
  ephemeral_status: [['memory_status', 'allowed']],
  security_review: [
    ['authenticate', 'denied'],
    ['raw_decrypt_intent', 'authorized'],
    ['raw_ingest_decrypt_intent', 'authorized'],
    ['raw_redacted_decrypt_intent', 'authorized'],
    ['raw_session_search_decrypt_intent', 'authorized'],
    ['memory_read', 'denied'], ['memory_search', 'failed'], ['raw_event_ingest', 'failed'],
    ['raw_delivery_proof', 'failed'], ['documents_search', 'denied'], ['context_search', 'failed']
  ],
  ephemeral_operational: [
    ['raw_event_ingest', 'stored'], ['raw_event_ingest', 'duplicate'], ['raw_delivery_proof', 'verified'],
    ['session_transcript', 'allowed'], ['sessions_search', 'allowed'], ['memory_search', 'allowed']
  ],
  long_retained: [
    ['curation_proposal_decrypt_intent', 'authorized'],
    ['curation_decision_receipt', 'recorded'], ['curation_decision_receipt', 'superseded'],
    ['curation_apply_receipt', 'recorded'], ['raw_reconcile', 'eligible'], ['raw_reconcile', 'blocked'],
    ['document_delete', 'tombstoned'], ['document_upsert', 'stored'], ['document_upsert', 'failed'],
    ['raw_event_recovery', 'recovered'], ['retention_apply', 'applied'], ['retention_plan', 'denied'],
    ['identity_merge', 'failed'], ['memory_propose', 'denied'], ['curation_receipt', 'failed']
  ]
};

test('owner-fixed and production-observed pairs classify exactly', () => {
  for (const [retentionClass, pairs] of Object.entries(EXPECTED)) {
    for (const [action, outcome] of pairs) {
      assert.equal(classifyAuditEventStrict(action, outcome), retentionClass, `${action}/${outcome}`);
    }
  }
});

test('every literal audit action written anywhere in src/ is in the table', () => {
  const written = new Set();
  for (const file of sourceFiles(path.join(ROOT, 'src'))) {
    const text = fs.readFileSync(file, 'utf8');
    if (!/audit/i.test(text)) continue;
    for (const match of text.matchAll(/action:\s*["']([a-z][a-z0-9_]*)["']/g)) written.add(match[1]);
    for (const match of text.matchAll(/\?\s*'((?:curation)_[a-z_]+_receipt)'\s*:\s*'((?:curation)_[a-z_]+_receipt)'/g)) { written.add(match[1]); written.add(match[2]); }
    for (const match of text.matchAll(/const action = \w+ \? '([a-z_]+)' : '([a-z_]+)'/g)) { written.add(match[1]); written.add(match[2]); }
  }
  written.add('identity_merge');
  written.add('identity_split');
  const nonAudit = new Set(['provision']);
  const tableActions = new Set(AUDIT_RETENTION_TABLE.map(row => row.action));
  const missing = [...written].filter(action => !nonAudit.has(action) && !tableActions.has(action));
  assert.deepEqual(missing, []);
  for (const action of ['curation_apply_receipt', 'curation_decision_receipt', 'document_upsert', 'document_delete', 'raw_event_recovery']) {
    assert.ok(written.has(action), `source scan should see ${action}`);
  }
});

test('long_retained actions never have a deletable outcome and denied/failed is never ephemeral', () => {
  const longActions = new Set(auditRetentionPairsByClass('long_retained').map(pair => pair.action));
  for (const row of AUDIT_RETENTION_TABLE) {
    if (longActions.has(row.action)) assert.equal(row.retentionClass, 'long_retained', `${row.action}/${row.outcome}`);
    if (['denied', 'failed'].includes(row.outcome)) assert.ok(['security_review', 'long_retained'].includes(row.retentionClass), `${row.action}/${row.outcome}`);
  }
});

test('unknown or malformed pairs are long_retained and never throw; strict variant throws', () => {
  assert.equal(classifyAuditEvent('totally_unknown_action', 'allowed'), 'long_retained');
  assert.equal(classifyAuditEvent('memory_status', 'throttled'), 'long_retained');
  assert.equal(classifyAuditEvent('authenticate', 'allowed'), 'long_retained');
  assert.equal(classifyAuditEvent(undefined, null), 'long_retained');
  assert.equal(classifyAuditEvent('', ''), 'long_retained');
  assert.throws(() => classifyAuditEventStrict('memory_status', 'throttled'), /audit_retention_class_unmapped/);
});

test('Phase A predicate is generated from the table: every deletable pair appears once, no long_retained pair appears', () => {
  const asOf = '2026-09-27T12:00:00.000Z';
  const predicate = buildPhaseAPredicate({ asOf });
  const listed = [...predicate.text.matchAll(/\('([a-z0-9_]+)','([a-z0-9_]+)'\)/g)].map(match => `${match[1]}/${match[2]}`);
  const deletable = AUDIT_RETENTION_TABLE.filter(row => row.retentionClass !== 'long_retained').map(row => `${row.action}/${row.outcome}`);
  assert.deepEqual([...listed].sort(), [...deletable].sort());
  assert.equal(new Set(listed).size, listed.length);
  for (const row of AUDIT_RETENTION_TABLE.filter(item => item.retentionClass === 'long_retained')) {
    assert.ok(!listed.includes(`${row.action}/${row.outcome}`), `${row.action}/${row.outcome}`);
  }
  assert.deepEqual(predicate.values, [
    auditRetentionCutoff('ephemeral_status', asOf).toISOString(),
    auditRetentionCutoff('ephemeral_operational', asOf).toISOString(),
    auditRetentionCutoff('security_review', asOf).toISOString()
  ]);
  assert.match(buildPhaseAPredicate({ asOf, firstParam: 2 }).text, /\$2::timestamptz[\s\S]*\$3::timestamptz[\s\S]*\$4::timestamptz/);
});

test('only the canonical audit table is accepted, and it is quoted', () => {
  assert.equal(qualifiedAuditTable(), '"agent_memory_fabric"."audit_events_v2"');
  assert.throws(() => qualifiedAuditTable('audit_events_v2_legacy'), /audit_retention_table_not_allowed/);
  assert.throws(() => qualifiedAuditTable('audit_events_v2; DROP TABLE x'), /audit_retention_table_not_allowed/);
});

test('the four retention classes and default windows', () => {
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

test('isAuditRetentionExpired: exactly at the cutoff is retained, one ms older is expired', () => {
  const now = '2026-01-03T00:00:00.000Z';
  const cutoff = auditRetentionCutoff('ephemeral_status', now);
  assert.equal(cutoff.toISOString(), '2026-01-01T00:00:00.000Z');
  assert.equal(isAuditRetentionExpired('ephemeral_status', cutoff, now), false);
  assert.equal(isAuditRetentionExpired('ephemeral_status', new Date(cutoff.getTime() + 1), now), false);
  assert.equal(isAuditRetentionExpired('ephemeral_status', new Date(cutoff.getTime() - 1), now), true);
  assert.equal(isAuditRetentionExpired('long_retained', '2000-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), false);
});

function manualSampler(overrides = {}) {
  const state = { nowMs: Date.UTC(2026, 0, 1, 0, 0, 0), flushed: [], errors: [], failNext: 0 };
  const sampler = new AuditSampler({
    bucketMs: 300_000, autoFlush: false, clock: () => state.nowMs,
    flush: async event => {
      if (state.failNext > 0) { state.failNext -= 1; throw new Error('audit_unavailable'); }
      state.flushed.push(event);
    },
    onFlushError: (error, bucket) => state.errors.push({ code: error.code || error.message, bucket }),
    ...overrides
  });
  return { sampler, state };
}

test('AuditSampler: a burst of N calls in one bucket flushes one aggregated row with sampledCount = N', async () => {
  const { sampler, state } = manualSampler();
  for (let i = 0; i < 7; i += 1) sampler.record('actor-a');
  for (let i = 0; i < 3; i += 1) sampler.record('actor-b');
  state.nowMs += 300_000;
  await sampler.flushExpired();
  assert.equal(state.flushed.length, 2);
  const byActor = Object.fromEntries(state.flushed.map(event => [event.actorTag, event]));
  assert.equal(byActor['actor-a'].sampledCount, 7);
  assert.equal(byActor['actor-b'].sampledCount, 3);
  assert.equal(byActor['actor-a'].windowStart, '2026-01-01T00:00:00.000Z');
  assert.equal(byActor['actor-a'].windowEnd, '2026-01-01T00:05:00.000Z');
});

test('AuditSampler: a bucket not yet rolled over is never flushed early', async () => {
  const { sampler, state } = manualSampler();
  sampler.record('actor-a');
  state.nowMs += 299_999;
  await sampler.flushExpired();
  assert.equal(state.flushed.length, 0);
});

test('AuditSampler: a failed flush keeps the bucket, reports the error, and retries on the next flush', async () => {
  const { sampler, state } = manualSampler();
  sampler.record('actor-a');
  sampler.record('actor-a');
  state.nowMs += 300_000;
  state.failNext = 1;
  const first = await sampler.flushExpired();
  assert.deepEqual(first, { flushed: 0, failed: 1, pending: 1 });
  assert.equal(state.errors.length, 1);
  assert.equal(state.errors[0].bucket.sampledCount, 2);
  sampler.record('actor-a');
  state.nowMs += 300_000;
  const second = await sampler.flushExpired();
  assert.deepEqual(second, { flushed: 2, failed: 0, pending: 0 });
  assert.deepEqual(state.flushed.map(event => [event.windowStart, event.sampledCount]), [
    ['2026-01-01T00:00:00.000Z', 2], ['2026-01-01T00:05:00.000Z', 1]
  ]);
});

test('AuditSampler: overlapping flush calls never emit the same bucket twice', async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const flushed = [];
  let nowMs = Date.UTC(2026, 0, 1);
  const sampler = new AuditSampler({ bucketMs: 300_000, autoFlush: false, clock: () => nowMs, flush: async event => { await gate; flushed.push(event); } });
  sampler.record('actor-a');
  nowMs += 300_000;
  const first = sampler.flushExpired();
  const second = sampler.flushExpired();
  release();
  await Promise.all([first, second]);
  assert.equal(flushed.length, 1);
});

test('AuditSampler: pending buckets are bounded and dropped buckets are reported', async () => {
  const { sampler, state } = manualSampler({ maxPendingBuckets: 2 });
  for (const actor of ['a', 'b', 'c']) sampler.record(actor);
  state.nowMs += 300_000;
  state.failNext = 3;
  const result = await sampler.flushExpired();
  assert.equal(result.pending, 2);
  assert.equal(state.errors.filter(error => error.code === 'audit_sampler_bucket_dropped').length, 1);
});

test('AuditSampler: close() waits for an in-flight flush, flushes the rest, and rejects later records', async () => {
  const { sampler, state } = manualSampler();
  sampler.record('actor-a');
  sampler.record('actor-a');
  state.nowMs += 300_000;
  sampler.record('actor-b');
  const inflight = sampler.flushExpired();
  const closed = await sampler.close();
  await inflight;
  assert.equal(state.flushed.length, 2);
  assert.equal(closed.pending, 0);
  assert.throws(() => sampler.record('actor-a'), /audit_sampler_closed/);
});

test('AuditSampler: close() reports buckets it could not write', async () => {
  const { sampler, state } = manualSampler();
  sampler.record('actor-a');
  state.failNext = 1;
  const closed = await sampler.close();
  assert.deepEqual(closed, { flushed: 0, failed: 1, pending: 1 });
  assert.equal(state.errors.length, 1);
});

test('AuditSampler validates its construction inputs', () => {
  assert.throws(() => new AuditSampler({}), /audit_sampler_flush_required/);
  assert.throws(() => new AuditSampler({ flush: async () => {}, bucketMs: 10 }), /audit_sampler_bucket_ms_invalid/);
  assert.throws(() => new AuditSampler({ flush: async () => {}, maxPendingBuckets: 0 }), /audit_sampler_max_pending_invalid/);
});
