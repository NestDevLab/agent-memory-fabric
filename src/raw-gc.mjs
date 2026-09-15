import crypto from 'node:crypto';

import { retentionDeadline } from './identity-retention.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId } from './migration/m4-v2-conversation-projector.mjs';

const SCHEMA = 'agent_memory_fabric';
const DEFAULT_SESSION_BATCH_SIZE = 50;
const DEFAULT_PENDING_DRAIN_TIMEOUT_MS = 2000;
const DEFAULT_PENDING_POLL_INTERVAL_MS = 10;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function isoNow(clock) {
  const value = clock();
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

/**
 * §5 condition 1: every raw_events_v2 row for the session has a matching row
 * in conversation_archive_events_v1, via the legacy->v3 id mapping.
 */
export async function computeSessionCoverage(pool, sessionId) {
  const conversationId = deriveM4V3ConversationIdFromLegacySessionId(sessionId);
  const events = await pool.query({
    text: `SELECT event_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1`,
    values: [sessionId]
  });
  const sourceEventCount = events.rows.length;
  if (sourceEventCount === 0) return { conversationId, sourceEventCount: 0, archivedEventCount: 0, ok: true };
  const mappedIds = events.rows.map(row => deriveM4V3EventIdFromLegacyEventId(row.event_id));
  const archived = await pool.query({
    text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.conversation_archive_events_v1 WHERE conversation_id = $1 AND event_id = ANY($2::text[])`,
    values: [conversationId, mappedIds]
  });
  const archivedEventCount = Number(archived.rows[0].count);
  return { conversationId, sourceEventCount, archivedEventCount, ok: archivedEventCount === sourceEventCount };
}

/**
 * §5 condition 2, shadow branch. The runtime only tracks global counters, not
 * per-session ones, so this drives one live comparison for the session and
 * treats a clean delta (compared>=1, zero mismatched/inconclusive/unavailable)
 * across that call as proof for this session. A concurrent shadow comparison
 * from unrelated traffic landing in the same window would also show as a
 * clean delta; this is a documented approximation of the design's per-session
 * requirement, not a per-session counter the runtime exposes today.
 */
export async function verifyShadowParity({
  runtime, sessionId,
  pendingDrainTimeoutMs = DEFAULT_PENDING_DRAIN_TIMEOUT_MS,
  pendingPollIntervalMs = DEFAULT_PENDING_POLL_INTERVAL_MS,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
}) {
  if (!runtime || !runtime.reader) return { ok: false, mismatchCount: null };
  const before = runtime.status();
  await runtime.reader.get({ id: sessionId });
  const deadline = Date.now() + pendingDrainTimeoutMs;
  let after = runtime.status();
  while (after.pending > 0 && Date.now() < deadline) {
    await sleep(pendingPollIntervalMs);
    after = runtime.status();
  }
  const delta = {
    compared: after.compared - before.compared,
    mismatched: after.mismatched - before.mismatched,
    inconclusive: after.inconclusive - before.inconclusive,
    unavailable: after.unavailable - before.unavailable
  };
  const ok = delta.compared >= 1 && delta.mismatched === 0 && delta.inconclusive === 0 && delta.unavailable === 0;
  return { ok, mismatchCount: after.mismatched };
}

/**
 * §5 conditions 1-2, checked live and cached into session_archive_proof_v1.
 * The cache is never trusted for the delete decision itself (§6 step 3
 * re-checks 4-6 at delete time) — it exists for observability/resume only.
 */
export async function verifySessionArchiveProof({ pool, runtime, sessionId, clock = () => new Date(), verifyShadow = verifyShadowParity }) {
  const coverage = await computeSessionCoverage(pool, sessionId);
  const mode = runtime ? runtime.status().mode : 'disabled';
  let readPathOk = false;
  let shadowMismatchCount = null;
  if (mode === 'active') {
    readPathOk = true;
  } else if (mode === 'shadow' && coverage.ok) {
    const shadow = await verifyShadow({ runtime, sessionId });
    readPathOk = shadow.ok;
    shadowMismatchCount = shadow.mismatchCount;
  }
  const archived = coverage.ok && readPathOk;
  const verifiedAt = isoNow(clock);
  await pool.query({
    text: `INSERT INTO ${SCHEMA}.session_archive_proof_v1
        (session_id, v3_conversation_id, source_event_count, archived_event_count, reader_mode_at_verification, shadow_mismatch_count, verified_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (session_id) DO UPDATE SET
        v3_conversation_id = EXCLUDED.v3_conversation_id,
        source_event_count = EXCLUDED.source_event_count,
        archived_event_count = EXCLUDED.archived_event_count,
        reader_mode_at_verification = EXCLUDED.reader_mode_at_verification,
        shadow_mismatch_count = EXCLUDED.shadow_mismatch_count,
        verified_at = EXCLUDED.verified_at`,
    values: [sessionId, coverage.conversationId, coverage.sourceEventCount, coverage.archivedEventCount, mode, shadowMismatchCount, verifiedAt]
  });
  return {
    archived,
    reason: archived ? null : (!coverage.ok ? 'coverage_incomplete' : 'read_path_not_authoritative'),
    proof: {
      sessionId, v3ConversationId: coverage.conversationId, sourceEventCount: coverage.sourceEventCount,
      archivedEventCount: coverage.archivedEventCount, readerModeAtVerification: mode, shadowMismatchCount, verifiedAt
    }
  };
}

/**
 * Re-derives whether a stored session_archive_proof_v1 row represents a
 * successful archive proof (§5 conditions 1-2) — the row itself is written
 * for every verification attempt, successful or not, so existence alone is
 * not proof; deriving from its columns is what atomicity re-checks (§6 step 3)
 * must use instead of an "archived" flag the schema does not carry.
 */
export function isArchivedProofRow(row) {
  if (!row) return false;
  const coverageOk = Number(row.source_event_count) === Number(row.archived_event_count);
  if (!coverageOk) return false;
  if (row.reader_mode_at_verification === 'active') return true;
  if (row.reader_mode_at_verification === 'shadow') return Number(row.shadow_mismatch_count) === 0;
  return false;
}

/** §5 condition 3, anchored on raw_sessions_v1.first_occurred_at, held fixed. */
export function isSessionRetentionElapsed(session, now, policy = {}, scope = null) {
  const deadline = retentionDeadline(new Date(session.firstOccurredAt).toISOString(), scope, policy);
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  return nowMs >= new Date(deadline).getTime();
}

/**
 * §5 condition 4, extended from applyRetention()'s fabric_proposals check
 * (fabric-store.mjs) to content ids sourced from raw_events_v2 instead of
 * only raw_retention_v2. Returns the subset of contentIds still referenced.
 */
export async function findLiveCurationReferences(pool, contentIds) {
  if (contentIds.length === 0) return new Set();
  const result = await pool.query({
    text: `SELECT DISTINCT content_id FROM ${SCHEMA}.fabric_proposals WHERE content_id = ANY($1::text[]) AND status NOT IN ('revoked','rejected')`,
    values: [contentIds]
  });
  return new Set(result.rows.map(row => row.content_id));
}

async function fetchLogicalMessageUnits(client, sessionId) {
  const result = await client.query({
    text: `SELECT DISTINCT logical_message_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1`,
    values: [sessionId]
  });
  return result.rows.map(row => row.logical_message_id);
}

async function fetchLogicalMessageMembership(client, logicalMessageId) {
  const message = await client.query({
    text: `SELECT logical_message_id, event_ids FROM ${SCHEMA}.logical_messages_v2 WHERE logical_message_id = $1`,
    values: [logicalMessageId]
  });
  if (message.rows.length === 0) return null;
  const eventIds = message.rows[0].event_ids;
  const events = await client.query({
    text: `SELECT event_id, session_id, content_id FROM ${SCHEMA}.raw_events_v2 WHERE event_id = ANY($1::text[])`,
    values: [eventIds]
  });
  return { logicalMessageId, eventIds, events: events.rows.map(row => ({ eventId: row.event_id, sessionId: row.session_id, contentId: row.content_id })) };
}

/**
 * §5 condition 6 checks raw_events_v2 references, but raw_objects_v2 also
 * carries an unconditional FK from fabric_proposals(content_id) — unlike the
 * live-curation-reference check (§5 condition 4), that FK holds regardless of
 * proposal status, so a revoked/rejected proposal row still blocks physical
 * deletion of the content object it once pointed at.
 */
async function contentObjectHasSurvivors(client, contentId) {
  const events = await client.query({
    text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE content_id = $1`,
    values: [contentId]
  });
  if (Number(events.rows[0].count) > 0) return true;
  const proposals = await client.query({
    text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.fabric_proposals WHERE content_id = $1`,
    values: [contentId]
  });
  return Number(proposals.rows[0].count) > 0;
}

/**
 * One idempotency-tagged, resumable, dry-run-capable GC operation over
 * raw_events_v2 per docs/audit-retention-gc-v1.md §6. The row identified by
 * idempotencyTag is UNIQUE and persists across invocations: counters and the
 * cursor are cumulative, so calling run() again with nothing left eligible
 * performs zero additional deletes and reports unchanged counters.
 */
export class RawGcEngine {
  constructor({
    pool,
    runtime = null,
    retentionPolicy = {},
    resolveScope = () => null,
    onDeleteContentObject = async () => {},
    idFactory = () => crypto.randomUUID(),
    clock = () => new Date(),
    sessionBatchSize = DEFAULT_SESSION_BATCH_SIZE,
    minVerifiedSessionsToProceed = 0,
    maxBytesReclaimedPerRun = Infinity,
    minFreeBytesFloor = 0,
    freeBytesProbe = async () => Infinity,
    verifyShadow = verifyShadowParity
  } = {}) {
    if (!pool) fail('raw_gc_pool_required');
    this.pool = pool;
    this.runtime = runtime;
    this.retentionPolicy = retentionPolicy;
    this.resolveScope = resolveScope;
    this.onDeleteContentObject = onDeleteContentObject;
    this.idFactory = idFactory;
    this.clock = clock;
    this.sessionBatchSize = sessionBatchSize;
    this.minVerifiedSessionsToProceed = minVerifiedSessionsToProceed;
    this.maxBytesReclaimedPerRun = maxBytesReclaimedPerRun;
    this.minFreeBytesFloor = minFreeBytesFloor;
    this.freeBytesProbe = freeBytesProbe;
    this.verifyShadow = verifyShadow;
  }

  async _loadOrCreateOperation(idempotencyTag, dryRun) {
    const existing = await this.pool.query({
      text: `SELECT * FROM ${SCHEMA}.raw_gc_operations_v1 WHERE idempotency_tag = $1`,
      values: [idempotencyTag]
    });
    if (existing.rows.length > 0) {
      const row = existing.rows[0];
      if (row.dry_run !== dryRun) fail('raw_gc_idempotency_tag_dry_run_mismatch');
      if (row.status !== 'running') {
        await this.pool.query({
          text: `UPDATE ${SCHEMA}.raw_gc_operations_v1 SET status = 'running', completed_at = NULL WHERE id = $1`,
          values: [row.id]
        });
      }
      return { ...row, status: 'running' };
    }
    const id = this.idFactory();
    const startedAt = isoNow(this.clock);
    await this.pool.query({
      text: `INSERT INTO ${SCHEMA}.raw_gc_operations_v1
          (id, idempotency_tag, dry_run, status, cursor_state_json, batches_processed, logical_messages_deleted, content_objects_deleted, bytes_reclaimed_estimate, started_at)
        VALUES ($1,$2,$3,'running','{}'::jsonb,0,0,0,0,$4)`,
      values: [id, idempotencyTag, dryRun, startedAt]
    });
    return { id, idempotency_tag: idempotencyTag, dry_run: dryRun, status: 'running', cursor_state_json: {},
      batches_processed: 0, logical_messages_deleted: 0, content_objects_deleted: 0, bytes_reclaimed_estimate: 0 };
  }

  async _eligibleSessionBatch(cursorSessionId) {
    const result = await this.pool.query({
      text: `SELECT session_id, first_occurred_at, last_occurred_at, event_count
          FROM ${SCHEMA}.raw_sessions_v1
          WHERE gc_completed_at IS NULL AND session_id > $1
          ORDER BY session_id LIMIT $2`,
      values: [cursorSessionId || '', this.sessionBatchSize]
    });
    return result.rows.map(row => ({
      sessionId: row.session_id, firstOccurredAt: row.first_occurred_at, lastOccurredAt: row.last_occurred_at, eventCount: Number(row.event_count)
    }));
  }

  async _processLogicalMessage(client, { logicalMessageId, sessionId, dryRun, now }) {
    const membership = await fetchLogicalMessageMembership(client, logicalMessageId);
    if (!membership || membership.events.length === 0) return { deleted: false, reason: 'logical_message_missing' };

    for (const event of membership.events) {
      if (event.sessionId === sessionId) continue;
      const proof = await client.query({
        text: `SELECT source_event_count, archived_event_count, reader_mode_at_verification, shadow_mismatch_count
            FROM ${SCHEMA}.session_archive_proof_v1 WHERE session_id = $1`,
        values: [event.sessionId]
      });
      if (proof.rows.length === 0 || !isArchivedProofRow(proof.rows[0])) return { deleted: false, reason: 'atomicity_sibling_unverified' };
    }

    const contentIds = [...new Set(membership.events.map(event => event.contentId))];
    const referenced = await findLiveCurationReferences(client, contentIds);
    if (referenced.size > 0) return { deleted: false, reason: 'live_curation_reference' };

    if (dryRun) {
      const eventIds = membership.events.map(event => event.eventId);
      let wouldDeleteContentObjects = 0;
      let wouldReclaimBytes = 0;
      for (const contentId of contentIds) {
        const survivorCount = await client.query({
          text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE content_id = $1 AND event_id <> ALL($2::text[])`,
          values: [contentId, eventIds]
        });
        if (Number(survivorCount.rows[0].count) > 0) continue;
        const proposalSurvivorCount = await client.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.fabric_proposals WHERE content_id = $1`, values: [contentId] });
        if (Number(proposalSurvivorCount.rows[0].count) > 0) continue;
        const object = await client.query({ text: `SELECT byte_length FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`, values: [contentId] });
        if (object.rows.length === 0) continue;
        wouldDeleteContentObjects += 1;
        wouldReclaimBytes += Number(object.rows[0].byte_length);
      }
      return { deleted: true, dryRun: true, contentIds, eventIds, contentObjectsDeleted: wouldDeleteContentObjects, bytesReclaimed: wouldReclaimBytes };
    }

    const tombstoneId = this.idFactory();
    await client.query({
      text: `INSERT INTO ${SCHEMA}.raw_gc_tombstones_v1 (id, unit_type, unit_id, session_id, content_ids_json, reason_code, archive_proof_ref, expired_at)
        VALUES ($1,'logical_message',$2,$3,$4::jsonb,'retention_expired',$5,$6)`,
      values: [tombstoneId, logicalMessageId, sessionId, JSON.stringify(contentIds), sessionId, now]
    });
    await client.query({
      text: `DELETE FROM ${SCHEMA}.logical_message_aliases_v2 WHERE logical_message_id = $1`,
      values: [logicalMessageId]
    });
    await client.query({
      text: `DELETE FROM ${SCHEMA}.raw_events_v2 WHERE event_id = ANY($1::text[])`,
      values: [membership.events.map(event => event.eventId)]
    });
    await client.query({
      text: `DELETE FROM ${SCHEMA}.logical_messages_v2 WHERE logical_message_id = $1`,
      values: [logicalMessageId]
    });

    let contentObjectsDeleted = 0;
    let bytesReclaimed = 0;
    for (const contentId of contentIds) {
      if (await contentObjectHasSurvivors(client, contentId)) continue;
      const object = await client.query({
        text: `SELECT content_id, storage_ref, media_type, byte_length FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`,
        values: [contentId]
      });
      if (object.rows.length === 0) continue;
      const row = object.rows[0];
      await client.query({
        text: `INSERT INTO ${SCHEMA}.raw_gc_tombstones_v1 (id, unit_type, unit_id, session_id, content_ids_json, reason_code, archive_proof_ref, expired_at)
          VALUES ($1,'content_object',$2,$3,$4::jsonb,'retention_expired',$5,$6)`,
        values: [this.idFactory(), contentId, sessionId, JSON.stringify([contentId]), sessionId, now]
      });
      await client.query({ text: `DELETE FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`, values: [contentId] });
      await this.onDeleteContentObject({ contentId, storageRef: row.storage_ref, mediaType: row.media_type, byteLength: Number(row.byte_length) });
      contentObjectsDeleted += 1;
      bytesReclaimed += Number(row.byte_length);
    }

    return { deleted: true, dryRun: false, contentIds, eventIds: membership.events.map(event => event.eventId), contentObjectsDeleted, bytesReclaimed };
  }

  async _processSession(session, { dryRun, now }) {
    const proof = await verifySessionArchiveProof({ pool: this.pool, runtime: this.runtime, sessionId: session.sessionId, clock: this.clock, verifyShadow: this.verifyShadow });
    if (!proof.archived) return { verified: false, reason: proof.reason, logicalMessagesDeleted: 0, contentObjectsDeleted: 0, bytesReclaimed: 0 };
    const scope = this.resolveScope(session);
    if (!isSessionRetentionElapsed(session, now, this.retentionPolicy, scope)) {
      return { verified: true, reason: 'retention_not_elapsed', logicalMessagesDeleted: 0, contentObjectsDeleted: 0, bytesReclaimed: 0 };
    }

    const client = await this.pool.connect();
    let logicalMessagesDeleted = 0;
    let contentObjectsDeleted = 0;
    let bytesReclaimed = 0;
    let remainingEvents = session.eventCount;
    try {
      const units = await fetchLogicalMessageUnits(client, session.sessionId);
      for (const logicalMessageId of units) {
        // Postgres serialization/deadlock failures (40P01/40001) are expected
        // under concurrent GC/app traffic on the same rows; retry the single
        // logical-message transaction rather than aborting the whole batch.
        for (let attempt = 1; ; attempt += 1) {
          await client.query('BEGIN');
          try {
            const result = await this._processLogicalMessage(client, { logicalMessageId, sessionId: session.sessionId, dryRun, now });
            if (result.deleted) {
              logicalMessagesDeleted += 1;
              contentObjectsDeleted += result.contentObjectsDeleted || 0;
              bytesReclaimed += result.bytesReclaimed || 0;
              if (!dryRun) {
                remainingEvents = Math.max(0, remainingEvents - (result.eventIds?.length || 0));
                await client.query({
                  text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = $2 WHERE session_id = $1`,
                  values: [session.sessionId, remainingEvents]
                });
                if (remainingEvents === 0) {
                  await client.query({
                    text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET gc_completed_at = $2 WHERE session_id = $1`,
                    values: [session.sessionId, now]
                  });
                }
              }
            }
            await client.query(dryRun ? 'ROLLBACK' : 'COMMIT');
            break;
          } catch (error) {
            await client.query('ROLLBACK').catch(() => {});
            const retryable = error?.code === '40P01' || error?.code === '40001';
            if (!retryable || attempt >= 5) throw error;
            await new Promise(resolve => setTimeout(resolve, 10 * attempt));
          }
        }
      }
    } finally {
      client.release();
    }
    return { verified: true, reason: null, logicalMessagesDeleted, contentObjectsDeleted, bytesReclaimed };
  }

  /** Runs at most one bounded batch of sessions. Call repeatedly to drain a backlog. */
  async run({ idempotencyTag, dryRun = true }) {
    if (typeof idempotencyTag !== 'string' || !idempotencyTag) fail('raw_gc_idempotency_tag_required');
    const operation = await this._loadOrCreateOperation(idempotencyTag, dryRun);
    const cursor = operation.cursor_state_json?.lastSessionId || '';
    const freeBytes = await this.freeBytesProbe();
    if (freeBytes < this.minFreeBytesFloor) {
      await this.pool.query({ text: `UPDATE ${SCHEMA}.raw_gc_operations_v1 SET status = 'aborted' WHERE id = $1`, values: [operation.id] });
      fail('raw_gc_free_space_floor_breached');
    }

    const batch = await this._eligibleSessionBatch(cursor);
    const now = isoNow(this.clock);
    let verifiedCount = 0;
    let lastSessionId = cursor;
    let deltaLogicalMessages = 0;
    let deltaContentObjects = 0;
    let deltaBytes = 0;
    const sessionOutcomes = [];

    for (const session of batch) {
      const outcome = await this._processSession(session, { dryRun, now });
      sessionOutcomes.push({ sessionId: session.sessionId, ...outcome });
      if (outcome.verified) verifiedCount += 1;
      deltaLogicalMessages += outcome.logicalMessagesDeleted;
      deltaContentObjects += outcome.contentObjectsDeleted;
      deltaBytes += outcome.bytesReclaimed;
      lastSessionId = session.sessionId;
    }

    if (batch.length > 0 && verifiedCount < this.minVerifiedSessionsToProceed) {
      await this.pool.query({ text: `UPDATE ${SCHEMA}.raw_gc_operations_v1 SET status = 'aborted' WHERE id = $1`, values: [operation.id] });
      fail('raw_gc_verification_floor_breached');
    }

    const newTotalBytes = Number(operation.bytes_reclaimed_estimate) + deltaBytes;
    if (newTotalBytes > this.maxBytesReclaimedPerRun) {
      await this.pool.query({ text: `UPDATE ${SCHEMA}.raw_gc_operations_v1 SET status = 'aborted' WHERE id = $1`, values: [operation.id] });
      fail('raw_gc_bytes_ceiling_breached');
    }

    const completed = batch.length < this.sessionBatchSize;
    const updated = await this.pool.query({
      text: `UPDATE ${SCHEMA}.raw_gc_operations_v1 SET
          status = $2,
          cursor_state_json = $3::jsonb,
          batches_processed = batches_processed + 1,
          logical_messages_deleted = logical_messages_deleted + $4,
          content_objects_deleted = content_objects_deleted + $5,
          bytes_reclaimed_estimate = bytes_reclaimed_estimate + $6,
          completed_at = CASE WHEN $2 = 'completed' THEN $7::timestamptz ELSE completed_at END
        WHERE id = $1
        RETURNING *`,
      values: [operation.id, completed ? 'completed' : 'running', JSON.stringify({ lastSessionId }), deltaLogicalMessages, deltaContentObjects, deltaBytes, now]
    });
    const row = updated.rows[0];
    return {
      operationId: row.id,
      idempotencyTag,
      dryRun,
      status: row.status,
      sessionsScanned: batch.length,
      sessionsVerified: verifiedCount,
      sessionOutcomes,
      delta: { logicalMessagesDeleted: deltaLogicalMessages, contentObjectsDeleted: deltaContentObjects, bytesReclaimed: deltaBytes },
      counters: {
        batchesProcessed: Number(row.batches_processed),
        logicalMessagesDeleted: Number(row.logical_messages_deleted),
        contentObjectsDeleted: Number(row.content_objects_deleted),
        bytesReclaimedEstimate: Number(row.bytes_reclaimed_estimate)
      },
      cursor: row.cursor_state_json
    };
  }
}
