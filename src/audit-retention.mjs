export const AUDIT_RETENTION_CLASSES = Object.freeze([
  'ephemeral_status', 'ephemeral_operational', 'security_review', 'long_retained'
]);

export const DELETABLE_AUDIT_RETENTION_CLASSES = Object.freeze(['ephemeral_status', 'ephemeral_operational', 'security_review']);

export const DEFAULT_AUDIT_RETENTION_POLICY = Object.freeze({
  ephemeral_status: Object.freeze({ days: 2 }),
  ephemeral_operational: Object.freeze({ days: 10 }),
  security_review: Object.freeze({ days: 90 }),
  long_retained: Object.freeze({ days: null, externalArchive: false })
});

const FAILING_OUTCOMES = Object.freeze(['denied', 'failed']);

// every (action, outcome) src/ writes to audit_events_v2, by the class of its normal outcomes;
// denied/failed of a non-long_retained action becomes security_review
const ACTION_RULES = Object.freeze({
  memory_status: { retentionClass: 'ephemeral_status', outcomes: ['allowed'] },

  context_search: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  document_read: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  documents_search: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  memory_proposal_status: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  memory_read: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  memory_search: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  raw_delivery_proof: { retentionClass: 'ephemeral_operational', outcomes: ['verified'] },
  raw_event_ingest: { retentionClass: 'ephemeral_operational', outcomes: ['stored', 'duplicate'] },
  raw_extractor_session_read: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  raw_extractor_sessions_read: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  raw_extractor_transcript_read: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  session_get: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  session_transcript: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },
  sessions_search: { retentionClass: 'ephemeral_operational', outcomes: ['allowed'] },

  authenticate: { retentionClass: 'security_review', outcomes: [] },
  raw_decrypt_intent: { retentionClass: 'security_review', outcomes: ['authorized'] },
  raw_ingest_decrypt_intent: { retentionClass: 'security_review', outcomes: ['authorized'] },
  raw_redacted_decrypt_intent: { retentionClass: 'security_review', outcomes: ['authorized'] },
  raw_session_search_decrypt_intent: { retentionClass: 'security_review', outcomes: ['authorized'] },

  curation_apply_receipt: { retentionClass: 'long_retained', outcomes: ['recorded', 'duplicate', 'superseded'] },
  curation_decision_receipt: { retentionClass: 'long_retained', outcomes: ['recorded', 'duplicate', 'superseded'] },
  curation_proposal_decrypt_intent: { retentionClass: 'long_retained', outcomes: ['authorized'] },
  curation_proposal_list: { retentionClass: 'long_retained', outcomes: ['allowed'] },
  curation_proposal_read: { retentionClass: 'long_retained', outcomes: ['allowed'] },
  curation_receipt: { retentionClass: 'long_retained', outcomes: [] },
  curation_reconcile: { retentionClass: 'long_retained', outcomes: ['clean', 'findings'] },
  document_delete: { retentionClass: 'long_retained', outcomes: ['tombstoned', 'duplicate'] },
  document_upsert: { retentionClass: 'long_retained', outcomes: ['stored', 'duplicate'] },
  identity_create: { retentionClass: 'long_retained', outcomes: ['created', 'duplicate'] },
  identity_merge: { retentionClass: 'long_retained', outcomes: ['applied', 'duplicate'] },
  identity_read: { retentionClass: 'long_retained', outcomes: ['allowed'] },
  identity_split: { retentionClass: 'long_retained', outcomes: ['applied', 'duplicate'] },
  memory_propose: { retentionClass: 'long_retained', outcomes: ['queued', 'duplicate'] },
  raw_event_recovery: { retentionClass: 'long_retained', outcomes: ['recovered'] },
  raw_reconcile: { retentionClass: 'long_retained', outcomes: ['eligible', 'blocked'] },
  retention_apply: { retentionClass: 'long_retained', outcomes: ['applied'] },
  retention_plan: { retentionClass: 'long_retained', outcomes: ['allowed'] }
});

function buildRetentionTable() {
  const rows = [];
  for (const [action, rule] of Object.entries(ACTION_RULES)) {
    for (const outcome of rule.outcomes) rows.push({ action, outcome, retentionClass: rule.retentionClass });
    for (const outcome of FAILING_OUTCOMES) {
      if (rule.outcomes.includes(outcome)) continue;
      rows.push({ action, outcome, retentionClass: rule.retentionClass === 'long_retained' ? 'long_retained' : 'security_review' });
    }
  }
  rows.sort((a, b) => a.action.localeCompare(b.action) || a.outcome.localeCompare(b.outcome));
  return Object.freeze(rows.map(row => Object.freeze(row)));
}

/** Source of truth for classifier and Phase A predicate. */
export const AUDIT_RETENTION_TABLE = buildRetentionTable();

const TABLE_INDEX = new Map(AUDIT_RETENTION_TABLE.map(row => [`${row.action}\u0000${row.outcome}`, row.retentionClass]));

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/** Unknown or malformed pairs are long_retained, so Phase A never deletes them. */
export function classifyAuditEvent(action, outcome) {
  if (typeof action !== 'string' || typeof outcome !== 'string') return 'long_retained';
  return TABLE_INDEX.get(`${action}\u0000${outcome}`) ?? 'long_retained';
}

export function classifyAuditEventStrict(action, outcome) {
  const retentionClass = TABLE_INDEX.get(`${action}\u0000${outcome}`);
  if (!retentionClass) fail('audit_retention_class_unmapped');
  return retentionClass;
}

export function isKnownAuditEventPair(action, outcome) {
  return TABLE_INDEX.has(`${action}\u0000${outcome}`);
}

export function auditRetentionPairsByClass(retentionClass) {
  if (!AUDIT_RETENTION_CLASSES.includes(retentionClass)) fail('audit_retention_class_invalid');
  return AUDIT_RETENTION_TABLE.filter(row => row.retentionClass === retentionClass).map(({ action, outcome }) => ({ action, outcome }));
}

function validatePolicyEntry(retentionClass, entry) {
  if (!entry || typeof entry !== 'object') fail('audit_retention_policy_invalid');
  if (retentionClass === 'long_retained') {
    if (entry.days !== null) fail('audit_retention_policy_invalid');
    if (typeof entry.externalArchive !== 'boolean') fail('audit_retention_policy_invalid');
    return;
  }
  if (!Number.isSafeInteger(entry.days) || entry.days < 1 || entry.days > 36500) fail('audit_retention_policy_invalid');
}

export function validateAuditRetentionPolicy(policy) {
  if (!policy || typeof policy !== 'object') fail('audit_retention_policy_invalid');
  for (const retentionClass of AUDIT_RETENTION_CLASSES) validatePolicyEntry(retentionClass, policy[retentionClass]);
  return policy;
}

/** Window in days for a retention class, or null for "kept indefinitely". */
export function auditRetentionWindowDays(retentionClass, policy = DEFAULT_AUDIT_RETENTION_POLICY) {
  const entry = policy?.[retentionClass];
  if (!entry) fail('audit_retention_class_invalid');
  return entry.days;
}

function toMs(value) {
  const ms = value instanceof Date ? value.getTime() : new Date(value).getTime();
  if (!Number.isFinite(ms)) fail('audit_retention_timestamp_invalid');
  return ms;
}

/** ts < cutoff means expired. Fixed ms, not calendar days, so SQL and JS agree across DST. */
export function auditRetentionCutoff(retentionClass, asOf, policy = DEFAULT_AUDIT_RETENTION_POLICY) {
  const days = auditRetentionWindowDays(retentionClass, policy);
  if (days == null) return null;
  return new Date(toMs(asOf) - days * 86_400_000);
}

export function isAuditRetentionExpired(retentionClass, ts, now, policy = DEFAULT_AUDIT_RETENTION_POLICY) {
  const cutoff = auditRetentionCutoff(retentionClass, now, policy);
  if (!cutoff) return false;
  return toMs(ts) < cutoff.getTime();
}

function envInteger(env, name, fallback, { min, max }) {
  const raw = env[name];
  if (raw == null || raw === '') return fallback;
  if (!/^\d+$/.test(raw)) fail(`audit_retention_env_invalid:${name}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`audit_retention_env_invalid:${name}`);
  return value;
}

export function loadAuditRetentionPolicyFromEnv(env = process.env) {
  const policy = {
    ephemeral_status: { days: envInteger(env, 'AMF_AUDIT_RETENTION_EPHEMERAL_STATUS_DAYS', 2, { min: 1, max: 3 }) },
    ephemeral_operational: { days: envInteger(env, 'AMF_AUDIT_RETENTION_EPHEMERAL_OPERATIONAL_DAYS', 10, { min: 7, max: 14 }) },
    security_review: { days: envInteger(env, 'AMF_AUDIT_RETENTION_SECURITY_REVIEW_DAYS', 90, { min: 90, max: 90 }) },
    long_retained: { days: null, externalArchive: String(env.AMF_AUDIT_RETENTION_LONG_RETAINED_EXTERNAL_ARCHIVE || '') === 'true' }
  };
  return validateAuditRetentionPolicy(policy);
}

const SQL_LITERAL_PATTERN = /^[a-z][a-z0-9_]*$/;

function sqlPairList(pairs) {
  return pairs.map(({ action, outcome }) => {
    if (!SQL_LITERAL_PATTERN.test(action) || !SQL_LITERAL_PATTERN.test(outcome)) fail('audit_retention_table_invalid');
    return `('${action}','${outcome}')`;
  }).join(',');
}

/**
 * One clause per deletable class: explicit (action, outcome) IN-list plus that class's cutoff.
 * Unknown and long_retained pairs are never listed. `firstParam` = first cutoff placeholder.
 */
export function buildPhaseAPredicate({ asOf, policy = DEFAULT_AUDIT_RETENTION_POLICY, firstParam = 1 } = {}) {
  validateAuditRetentionPolicy(policy);
  const clauses = [];
  const values = [];
  for (const retentionClass of DELETABLE_AUDIT_RETENTION_CLASSES) {
    const pairs = auditRetentionPairsByClass(retentionClass);
    if (!pairs.length) continue;
    values.push(auditRetentionCutoff(retentionClass, asOf, policy).toISOString());
    clauses.push(`((action, outcome) IN (${sqlPairList(pairs)}) AND ts < $${firstParam + values.length - 1}::timestamptz)`);
  }
  return { text: `(${clauses.join(' OR ')})`, values };
}

/**
 * One memory_status/allowed audit row per (actorTag, bucket) instead of per call.
 * Bucket is kept until its write succeeds (at-least-once); a crash loses what's in memory.
 */
export class AuditSampler {
  constructor({ bucketMs = 300_000, flush, clock = () => Date.now(), autoFlush = true, onFlushError, maxPendingBuckets = 10_000 } = {}) {
    if (typeof flush !== 'function') fail('audit_sampler_flush_required');
    if (!Number.isSafeInteger(bucketMs) || bucketMs < 1000 || bucketMs > 3_600_000) fail('audit_sampler_bucket_ms_invalid');
    if (!Number.isSafeInteger(maxPendingBuckets) || maxPendingBuckets < 1) fail('audit_sampler_max_pending_invalid');
    this._bucketMs = bucketMs;
    this._flush = flush;
    this._clock = clock;
    this._onFlushError = typeof onFlushError === 'function' ? onFlushError : () => {};
    this._maxPendingBuckets = maxPendingBuckets;
    this._buckets = new Map();
    this._closed = false;
    this._timer = null;
    this._flushChain = Promise.resolve();
    if (autoFlush) {
      this._timer = setInterval(() => { this.flushExpired().catch(error => this._reportError(error, null)); }, bucketMs);
      this._timer.unref?.();
    }
  }

  get pendingBuckets() { return this._buckets.size; }

  _bucketStartFor(nowMs) { return Math.floor(nowMs / this._bucketMs) * this._bucketMs; }

  _reportError(error, bucket) {
    try { this._onFlushError(error, bucket ? this._describe(bucket) : null); } catch { /* reporting must not break flushing */ }
  }

  _describe(bucket) {
    return {
      actorTag: bucket.actorTag,
      sampledCount: bucket.count,
      windowStart: new Date(bucket.bucketStartMs).toISOString(),
      windowEnd: new Date(bucket.bucketStartMs + this._bucketMs).toISOString()
    };
  }

  /** Increments the current bucket's counter; never awaits or writes to storage. */
  record(actorTag) {
    if (this._closed) fail('audit_sampler_closed');
    if (typeof actorTag !== 'string' || !actorTag) fail('audit_sampler_actor_required');
    const bucketStartMs = this._bucketStartFor(this._clock());
    const key = `${bucketStartMs}\u0000${actorTag}`;
    let bucket = this._buckets.get(key);
    if (!bucket) { bucket = { actorTag, bucketStartMs, count: 0 }; this._buckets.set(key, bucket); }
    bucket.count += 1;
    return bucket.count;
  }

  _serialize(task) {
    const run = this._flushChain.then(task, task);
    this._flushChain = run.catch(() => {});
    return run;
  }

  async _flushWhere(isDue) {
    let flushed = 0;
    let failed = 0;
    for (const [key, bucket] of [...this._buckets]) {
      if (!isDue(bucket)) continue;
      try {
        await this._flush(this._describe(bucket));
        this._buckets.delete(key);
        flushed += 1;
      } catch (error) {
        failed += 1;
        this._reportError(error, bucket);
      }
    }
    this._dropOverflow();
    return { flushed, failed, pending: this._buckets.size };
  }

  _dropOverflow() {
    if (this._buckets.size <= this._maxPendingBuckets) return;
    const oldest = [...this._buckets].sort(([, a], [, b]) => a.bucketStartMs - b.bucketStartMs);
    for (const [key, bucket] of oldest.slice(0, this._buckets.size - this._maxPendingBuckets)) {
      this._buckets.delete(key);
      const error = new Error('audit_sampler_bucket_dropped');
      error.code = 'audit_sampler_bucket_dropped';
      this._reportError(error, bucket);
    }
  }

  /** Flushes every bucket whose window has fully rolled over, retrying earlier failures. */
  flushExpired() {
    return this._serialize(() => {
      const currentBucketStartMs = this._bucketStartFor(this._clock());
      return this._flushWhere(bucket => bucket.bucketStartMs < currentBucketStartMs);
    });
  }

  /** Flushes every bucket regardless of window state; used on shutdown. */
  flushAll() {
    return this._serialize(() => this._flushWhere(() => true));
  }

  async close() {
    if (this._closed) return this._closeResult;
    this._closed = true;
    if (this._timer) clearInterval(this._timer);
    this._closeResult = this.flushAll();
    return this._closeResult;
  }
}
