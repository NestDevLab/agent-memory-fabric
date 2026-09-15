import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { PostgresCatalog } from '../src/fabric-store.mjs';
import { RawGcEngine, verifySessionArchiveProof } from '../src/raw-gc.mjs';
import {
  copyAuditEventsBatch, createAuditEventsV2NextSchema, cutoverAuditEventsV2, runPhaseADeleteBatch
} from '../src/audit-partition-migration.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId } from '../src/migration/m4-v2-conversation-projector.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';
const SCHEMA = 'agent_memory_fabric';

function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function opaque(namespace, value) { return `hmac-sha256:integration:${digest(`${namespace}:${value}`)}`; }

function activeRuntime() { return { status: () => ({ mode: 'active', pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 }), reader: null }; }
function disabledRuntime() { return { status: () => ({ mode: 'disabled', pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 }), reader: null }; }

test('audit retention GC engine and audit partitioning migration against real PostgreSQL', { skip: !enabled }, async () => {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
  assert.match(databaseName, /(^|[-_])test($|[-_])/i, 'AMF_TEST_POSTGRES_URL must reference an isolated test database');
  const catalog = new PostgresCatalog({ connectionString, ssl: process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? false : { rejectUnauthorized: true } });
  const suffix = crypto.randomUUID().replace(/-/g, '');
  const sessionIds = new Set();
  const contentIds = new Set();
  let catalogReady = false;

  function sid(marker) { const id = `ses_${digest(`${suffix}:session:${marker}`)}`; sessionIds.add(id); return id; }
  function cid(marker) { const id = digest(`${suffix}:content:${marker}`); contentIds.add(id); return id; }
  function eid(marker) { return `evt_${digest(`${suffix}:event:${marker}`)}`; }
  function lmid(marker) { return `lmsg_${digest(`${suffix}:logical:${marker}`)}`; }

  async function insertSession(sessionId, firstOccurredAt) {
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,context_tags_json,first_occurred_at,last_occurred_at,event_count,created_at)
        VALUES ($1,'hermes',$2,$3,'group','{}'::jsonb,$4,$4,0,$4)
        ON CONFLICT (session_id) DO NOTHING`,
      values: [sessionId, opaque('owner', sessionId), opaque('source', sessionId), firstOccurredAt]
    });
  }

  async function insertRawObject(contentId, byteLength = 128) {
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at)
        VALUES ($1,'application/octet-stream',$2,$3,now()) ON CONFLICT (content_id) DO NOTHING`,
      values: [contentId, byteLength, `integration/${contentId}.bin`]
    });
  }

  async function insertEvent({ eventId, sessionId, logicalMessageId, contentId }) {
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at)
        VALUES ($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7,now()) ON CONFLICT (event_id) DO NOTHING`,
      values: [eventId, sessionId, logicalMessageId, contentId, `digest-${eventId}`, opaque('owner', sessionId), opaque('source', sessionId)]
    });
  }

  async function insertLogicalMessage(logicalMessageId, eventIds, preferredObservationId = eventIds[0]) {
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.logical_messages_v2(logical_message_id,preferred_observation_id,payload_conflict,tombstoned,selection_version,event_ids,updated_at)
        VALUES ($1,$2,false,false,'integration/v1',$3::jsonb,now())
        ON CONFLICT (logical_message_id) DO UPDATE SET event_ids = EXCLUDED.event_ids`,
      values: [logicalMessageId, preferredObservationId, JSON.stringify(eventIds)]
    });
  }

  async function seedArchiveCoverage(sessionId, eventIds) {
    const conversationId = deriveM4V3ConversationIdFromLegacySessionId(sessionId);
    for (const eventId of eventIds) {
      const archiveEventId = deriveM4V3EventIdFromLegacyEventId(eventId);
      await catalog.pool.query({
        text: `INSERT INTO ${SCHEMA}.conversation_archive_events_v1
            (event_id,conversation_id,source_instance_id,state,logical_digest,payload_digest,source_occurred_at,source_time_key,source_sequence,expires_at,expires_time_key,event_json,expired)
          VALUES ($1,$2,'integration','native','digest','digest','2020-01-01T00:00:00.000Z','2020-01-01T00:00:00.000000000',1,'2099-01-01T00:00:00.000Z','2099-01-01T00:00:00.000000000','{}'::jsonb,false)
          ON CONFLICT (event_id) DO NOTHING`,
        values: [archiveEventId, conversationId]
      });
    }
  }

  async function insertProposal({ id, contentId, status }) {
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.fabric_proposals(id,owner_tag,scope_tag,status,content_id,idempotency_tag,source_tag,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,now()) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status`,
      values: [id, opaque('owner', id), opaque('scope', id), status, contentId, `idempotency-${id}`, opaque('source', id)]
    });
  }

  const PAST = '2000-01-01T00:00:00.000Z';
  const RECENT = '2026-07-01T00:00:00.000Z';
  const now = () => new Date('2026-07-12T12:00:00.000Z');

  try {
    await catalog.ready();
    catalogReady = true;
    // conversation_archive_events_v1 is bootstrapped by PostgresConversationArchive
    // (src/conversation-archive-v1.mjs), not by PostgresCatalog; create it here
    // so the coverage check (§5 condition 1) has a real table to query.
    await catalog.pool.query(`CREATE TABLE IF NOT EXISTS ${SCHEMA}.conversation_archive_events_v1 (event_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, state TEXT NOT NULL, logical_digest TEXT NOT NULL, payload_digest TEXT NOT NULL, source_occurred_at TEXT NOT NULL, source_time_key TEXT NOT NULL, source_sequence BIGINT NOT NULL, expires_at TEXT NOT NULL, expires_time_key TEXT NOT NULL, event_json JSONB NOT NULL, expired BOOLEAN NOT NULL DEFAULT false)`);

    // ---- §5/§6: a fully eligible session GCs cleanly in 'active' reader mode ----
    const activeSession = sid('active-basic');
    await insertSession(activeSession, PAST);
    const activeContent = cid('active-basic');
    await insertRawObject(activeContent);
    const activeEvent = eid('active-basic');
    const activeLogical = lmid('active-basic');
    await insertEvent({ eventId: activeEvent, sessionId: activeSession, logicalMessageId: activeLogical, contentId: activeContent });
    await insertLogicalMessage(activeLogical, [activeEvent]);
    await seedArchiveCoverage(activeSession, [activeEvent]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [activeSession] });

    const proofEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now });
    const proof = await proofEngine._processSession({ sessionId: activeSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(proof.verified, true);
    assert.equal(proof.logicalMessagesDeleted, 1);
    assert.equal(proof.contentObjectsDeleted, 1);
    const survivingEvents = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1`, values: [activeSession] });
    assert.equal(Number(survivingEvents.rows[0].count), 0);
    const survivingObject = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`, values: [activeContent] });
    assert.equal(Number(survivingObject.rows[0].count), 0);
    const tombstones = await catalog.pool.query({ text: `SELECT unit_type, reason_code FROM ${SCHEMA}.raw_gc_tombstones_v1 WHERE session_id = $1 ORDER BY unit_type`, values: [activeSession] });
    assert.deepEqual(tombstones.rows.map(row => row.unit_type), ['content_object', 'logical_message']);
    assert.ok(tombstones.rows.every(row => row.reason_code === 'retention_expired'));
    const sessionRow = await catalog.pool.query({ text: `SELECT event_count, gc_completed_at FROM ${SCHEMA}.raw_sessions_v1 WHERE session_id = $1`, values: [activeSession] });
    assert.equal(Number(sessionRow.rows[0].event_count), 0);
    assert.ok(sessionRow.rows[0].gc_completed_at);

    // ---- §5 condition 2: 'disabled' reader mode never authorizes deletion ----
    const disabledSession = sid('disabled-mode');
    await insertSession(disabledSession, PAST);
    const disabledEvent = eid('disabled-mode');
    const disabledLogical = lmid('disabled-mode');
    const disabledContent = cid('disabled-mode');
    await insertRawObject(disabledContent);
    await insertEvent({ eventId: disabledEvent, sessionId: disabledSession, logicalMessageId: disabledLogical, contentId: disabledContent });
    await insertLogicalMessage(disabledLogical, [disabledEvent]);
    await seedArchiveCoverage(disabledSession, [disabledEvent]);
    const disabledProofResult = await verifySessionArchiveProof({ pool: catalog.pool, runtime: disabledRuntime(), sessionId: disabledSession, clock: now });
    assert.equal(disabledProofResult.archived, false);
    assert.equal(disabledProofResult.reason, 'read_path_not_authoritative');
    const disabledOutcome = await new RawGcEngine({ pool: catalog.pool, runtime: disabledRuntime(), clock: now })
      ._processSession({ sessionId: disabledSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(disabledOutcome.verified, false);
    const disabledStillThere = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1`, values: [disabledSession] });
    assert.equal(Number(disabledStillThere.rows[0].count), 1, 'unverified session must not be touched');

    // ---- §5 condition 5 (atomicity): a logical message spanning two sessions is retained
    //      until the sibling session also has a recorded archive proof ----
    const atomA = sid('atom-a');
    const atomB = sid('atom-b');
    await insertSession(atomA, PAST);
    await insertSession(atomB, PAST);
    const atomEventA = eid('atom-a');
    const atomEventB = eid('atom-b');
    const atomLogical = lmid('atom-shared');
    const atomContent = cid('atom-shared');
    await insertRawObject(atomContent);
    await insertEvent({ eventId: atomEventA, sessionId: atomA, logicalMessageId: atomLogical, contentId: atomContent });
    await insertEvent({ eventId: atomEventB, sessionId: atomB, logicalMessageId: atomLogical, contentId: atomContent });
    await insertLogicalMessage(atomLogical, [atomEventA, atomEventB]);
    await seedArchiveCoverage(atomA, [atomEventA]);
    await seedArchiveCoverage(atomB, [atomEventB]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = ANY($1::text[])`, values: [[atomA, atomB]] });

    const atomEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now });
    const atomOutcomeA = await atomEngine._processSession({ sessionId: atomA, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(atomOutcomeA.verified, true);
    assert.equal(atomOutcomeA.logicalMessagesDeleted, 0, 'sibling session atomB has no archive proof yet: message retained');
    const stillBothEvents = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE logical_message_id = $1`, values: [atomLogical] });
    assert.equal(Number(stillBothEvents.rows[0].count), 2);

    // atomA's own verifySessionArchiveProof call already recorded a proof row
    // even though its own delete was refused, so atomB's pass now sees a
    // proven sibling and deletes the shared logical message as one unit.
    const atomOutcomeB = await atomEngine._processSession({ sessionId: atomB, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(atomOutcomeB.verified, true);
    assert.equal(atomOutcomeB.logicalMessagesDeleted, 1, 'once both siblings have a recorded proof, the shared logical message is deleted as one unit');
    const bothGone = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE logical_message_id = $1`, values: [atomLogical] });
    assert.equal(Number(bothGone.rows[0].count), 0);

    // A stored proof row that exists but represents a *failed* verification
    // (e.g. incomplete coverage) must not be mistaken for a proven sibling —
    // existence of the row is not the same as isArchivedProofRow(row).
    const atomFailC = sid('atom-fail-c');
    const atomFailD = sid('atom-fail-d');
    await insertSession(atomFailC, PAST);
    await insertSession(atomFailD, PAST);
    const atomFailEventC = eid('atom-fail-c');
    const atomFailEventD = eid('atom-fail-d');
    const atomFailLogical = lmid('atom-fail-shared');
    const atomFailContent = cid('atom-fail-shared');
    await insertRawObject(atomFailContent);
    await insertEvent({ eventId: atomFailEventC, sessionId: atomFailC, logicalMessageId: atomFailLogical, contentId: atomFailContent });
    await insertEvent({ eventId: atomFailEventD, sessionId: atomFailD, logicalMessageId: atomFailLogical, contentId: atomFailContent });
    await insertLogicalMessage(atomFailLogical, [atomFailEventC, atomFailEventD]);
    await seedArchiveCoverage(atomFailC, [atomFailEventC]);
    // atomFailD deliberately has NO archive coverage seeded: its proof will be recorded but archived=false
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = ANY($1::text[])`, values: [[atomFailC, atomFailD]] });
    const atomFailEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now });
    await atomFailEngine._processSession({ sessionId: atomFailD, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    const atomFailDProof = await catalog.pool.query({ text: `SELECT source_event_count, archived_event_count FROM ${SCHEMA}.session_archive_proof_v1 WHERE session_id = $1`, values: [atomFailD] });
    assert.notEqual(Number(atomFailDProof.rows[0].source_event_count), Number(atomFailDProof.rows[0].archived_event_count), 'sanity: atomFailD really did fail coverage');
    const atomFailOutcomeC = await atomFailEngine._processSession({ sessionId: atomFailC, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(atomFailOutcomeC.logicalMessagesDeleted, 0, 'a recorded-but-failed sibling proof must still block the shared logical message');
    const failStillBoth = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE logical_message_id = $1`, values: [atomFailLogical] });
    assert.equal(Number(failStillBoth.rows[0].count), 2);

    // ---- §5 condition 6 (content dedup): shared raw_objects_v2 row survives until every referencing event is gone ----
    const dedupSession1 = sid('dedup-1');
    const dedupSession2 = sid('dedup-2');
    await insertSession(dedupSession1, PAST);
    await insertSession(dedupSession2, PAST);
    const dedupContent = cid('dedup-shared');
    await insertRawObject(dedupContent, 256);
    const dedupEvent1 = eid('dedup-1');
    const dedupEvent2 = eid('dedup-2');
    const dedupLogical1 = lmid('dedup-1');
    const dedupLogical2 = lmid('dedup-2');
    await insertEvent({ eventId: dedupEvent1, sessionId: dedupSession1, logicalMessageId: dedupLogical1, contentId: dedupContent });
    await insertEvent({ eventId: dedupEvent2, sessionId: dedupSession2, logicalMessageId: dedupLogical2, contentId: dedupContent });
    await insertLogicalMessage(dedupLogical1, [dedupEvent1]);
    await insertLogicalMessage(dedupLogical2, [dedupEvent2]);
    await seedArchiveCoverage(dedupSession1, [dedupEvent1]);
    await seedArchiveCoverage(dedupSession2, [dedupEvent2]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = ANY($1::text[])`, values: [[dedupSession1, dedupSession2]] });

    const dedupEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now });
    await dedupEngine._processSession({ sessionId: dedupSession1, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    const survivesOneReference = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`, values: [dedupContent] });
    assert.equal(Number(survivesOneReference.rows[0].count), 1, 'content object survives while dedupSession2 still references it');
    await dedupEngine._processSession({ sessionId: dedupSession2, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    const goneAfterBoth = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = $1`, values: [dedupContent] });
    assert.equal(Number(goneAfterBoth.rows[0].count), 0);

    // ---- §5 condition 4 (live curation reference): a promoted proposal blocks deletion until revoked ----
    const curatedSession = sid('curated');
    await insertSession(curatedSession, PAST);
    const curatedContent = cid('curated');
    await insertRawObject(curatedContent);
    const curatedEvent = eid('curated');
    const curatedLogical = lmid('curated');
    await insertEvent({ eventId: curatedEvent, sessionId: curatedSession, logicalMessageId: curatedLogical, contentId: curatedContent });
    await insertLogicalMessage(curatedLogical, [curatedEvent]);
    await seedArchiveCoverage(curatedSession, [curatedEvent]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [curatedSession] });
    await insertProposal({ id: `proposal-${suffix}`, contentId: curatedContent, status: 'promoted' });

    const curatedEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now });
    const curatedBlocked = await curatedEngine._processSession({ sessionId: curatedSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(curatedBlocked.logicalMessagesDeleted, 0, 'a promoted proposal referencing the content blocks GC');
    await insertProposal({ id: `proposal-${suffix}`, contentId: curatedContent, status: 'revoked' });
    const curatedProceeds = await curatedEngine._processSession({ sessionId: curatedSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(curatedProceeds.logicalMessagesDeleted, 1, 'GC proceeds once the proposal is revoked');

    // ---- retention not yet elapsed: a recent session is verified-archived but never deleted ----
    const freshSession = sid('fresh');
    await insertSession(freshSession, RECENT);
    const freshContent = cid('fresh');
    await insertRawObject(freshContent);
    const freshEvent = eid('fresh');
    const freshLogical = lmid('fresh');
    await insertEvent({ eventId: freshEvent, sessionId: freshSession, logicalMessageId: freshLogical, contentId: freshContent });
    await insertLogicalMessage(freshLogical, [freshEvent]);
    await seedArchiveCoverage(freshSession, [freshEvent]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [freshSession] });
    const freshOutcome = await new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now })
      ._processSession({ sessionId: freshSession, firstOccurredAt: RECENT, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(freshOutcome.reason, 'retention_not_elapsed');
    const freshStillThere = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1`, values: [freshSession] });
    assert.equal(Number(freshStillThere.rows[0].count), 1);

    // ---- §7 replay/idempotency: run() twice on the same idempotency tag performs zero additional deletes on the second call ----
    const replaySession = sid('replay');
    await insertSession(replaySession, PAST);
    const replayContent = cid('replay');
    await insertRawObject(replayContent);
    const replayEvent = eid('replay');
    const replayLogical = lmid('replay');
    await insertEvent({ eventId: replayEvent, sessionId: replaySession, logicalMessageId: replayLogical, contentId: replayContent });
    await insertLogicalMessage(replayLogical, [replayEvent]);
    await seedArchiveCoverage(replaySession, [replayEvent]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [replaySession] });

    const idempotencyTag = `gc-integration-${suffix}`;
    const runEngine = new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now, sessionBatchSize: 1000 });
    const firstRun = await runEngine.run({ idempotencyTag, dryRun: false });
    assert.ok(firstRun.delta.logicalMessagesDeleted >= 1);
    assert.equal(firstRun.status, 'completed');
    const secondRun = await runEngine.run({ idempotencyTag, dryRun: false });
    assert.equal(secondRun.delta.logicalMessagesDeleted, 0, 'replaying the same idempotency tag with nothing new eligible deletes nothing further');
    assert.equal(secondRun.delta.contentObjectsDeleted, 0);
    assert.equal(secondRun.delta.bytesReclaimed, 0);
    // batchesProcessed is an operational run-count, not a delete count — it
    // legitimately increments on every call, including a no-op replay.
    const { batchesProcessed: firstBatches, ...firstDeleteCounters } = firstRun.counters;
    const { batchesProcessed: secondBatches, ...secondDeleteCounters } = secondRun.counters;
    assert.deepEqual(secondDeleteCounters, firstDeleteCounters, 'cumulative delete counters are unchanged on a no-op replay');
    assert.equal(secondBatches, firstBatches + 1);
    await assert.rejects(runEngine.run({ idempotencyTag, dryRun: true }), /raw_gc_idempotency_tag_dry_run_mismatch/);

    // ---- §7 crash recovery mid-GC: a transaction that never commits leaves no partial state ----
    const crashSession = sid('crash');
    await insertSession(crashSession, PAST);
    const crashContent = cid('crash');
    await insertRawObject(crashContent);
    const crashEvent = eid('crash');
    const crashLogical = lmid('crash');
    await insertEvent({ eventId: crashEvent, sessionId: crashSession, logicalMessageId: crashLogical, contentId: crashContent });
    await insertLogicalMessage(crashLogical, [crashEvent]);
    await seedArchiveCoverage(crashSession, [crashEvent]);
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [crashSession] });

    const crashClient = await catalog.pool.connect();
    try {
      await crashClient.query('BEGIN');
      await crashClient.query({
        text: `INSERT INTO ${SCHEMA}.raw_gc_tombstones_v1 (id, unit_type, unit_id, session_id, content_ids_json, reason_code, archive_proof_ref, expired_at)
          VALUES ($1,'logical_message',$2,$3,$4::jsonb,'retention_expired',$3,now())`,
        values: [`${suffix}-crash-tombstone`, crashLogical, crashSession, JSON.stringify([crashContent])]
      });
      await crashClient.query({ text: `DELETE FROM ${SCHEMA}.raw_events_v2 WHERE event_id = $1`, values: [crashEvent] });
      // simulated crash: the process dies here, before COMMIT
      await crashClient.query('ROLLBACK');
    } finally {
      crashClient.release();
    }
    const noPartialTombstone = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_gc_tombstones_v1 WHERE id = $1`, values: [`${suffix}-crash-tombstone`] });
    assert.equal(Number(noPartialTombstone.rows[0].count), 0, 'the rolled-back tombstone insert left no trace');
    const eventSurvivedRollback = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE event_id = $1`, values: [crashEvent] });
    assert.equal(Number(eventSurvivedRollback.rows[0].count), 1, 'the rolled-back delete left the event intact');
    const crashOutcome = await new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now })
      ._processSession({ sessionId: crashSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(crashOutcome.logicalMessagesDeleted, 1, 'the next run completes the batch cleanly from the committed state');
    const crashTombstoneNow = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_gc_tombstones_v1 WHERE session_id = $1 AND unit_type='logical_message'`, values: [crashSession] });
    assert.equal(Number(crashTombstoneNow.rows[0].count), 1);

    // ---- §7 transcript readability: a session skipped for a failed archive proof is provably untouched,
    //      and sibling untouched sessions still read back correctly through the catalog's session APIs ----
    const untouchedSession = sid('untouched');
    await insertSession(untouchedSession, PAST);
    const untouchedContent = cid('untouched');
    await insertRawObject(untouchedContent);
    const untouchedEvent = eid('untouched');
    const untouchedLogical = lmid('untouched');
    await insertEvent({ eventId: untouchedEvent, sessionId: untouchedSession, logicalMessageId: untouchedLogical, contentId: untouchedContent });
    await insertLogicalMessage(untouchedLogical, [untouchedEvent]);
    // no archive coverage seeded: coverage check fails -> proof is refused -> GC must not touch it
    await catalog.pool.query({ text: `UPDATE ${SCHEMA}.raw_sessions_v1 SET event_count = 1 WHERE session_id = $1`, values: [untouchedSession] });
    const beforeEvents = await catalog.pool.query({ text: `SELECT event_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1 ORDER BY event_id`, values: [untouchedSession] });
    const uncoveredOutcome = await new RawGcEngine({ pool: catalog.pool, runtime: activeRuntime(), clock: now })
      ._processSession({ sessionId: untouchedSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
    assert.equal(uncoveredOutcome.verified, false);
    assert.equal(uncoveredOutcome.reason, 'coverage_incomplete');
    const afterEvents = await catalog.pool.query({ text: `SELECT event_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = $1 ORDER BY event_id`, values: [untouchedSession] });
    assert.deepEqual(afterEvents.rows, beforeEvents.rows, 'row counts unchanged for a session that failed the archive proof');
    for (const mode of ['shadow', 'active']) {
      const runtime = mode === 'active' ? activeRuntime() : { status: () => ({ mode: 'shadow', pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 }), reader: { get: async () => {} } };
      const modeOutcome = await new RawGcEngine({ pool: catalog.pool, runtime, clock: now })
        ._processSession({ sessionId: untouchedSession, firstOccurredAt: PAST, eventCount: 1 }, { dryRun: false, now: now().toISOString() });
      assert.equal(modeOutcome.verified, false, `${mode}: still refused without archive coverage`);
    }
    const transcriptPage = await catalog.listSessionEventsPage({ id: untouchedSession, offset: 0, limit: 10 });
    assert.equal(transcriptPage.items.length, 1);
    assert.equal(transcriptPage.items[0].eventId, untouchedEvent);
    const replayTranscript = await catalog.listSessionEventsPage({ id: replaySession, offset: 0, limit: 10 });
    assert.equal(replayTranscript.items.length, 0, 'the GC\'d replay session correctly reads back empty, not broken');

    // ---- §4/§7 audit partitioning migration end-to-end ----
    // Exercised against an isolated clone of audit_events_v2 (same column
    // shape) rather than the live table, so Phase A/C/D's DDL and renames
    // cannot contend with concurrently-running suites that write real audit
    // rows into the shared table.
    // Kept short: partition child names append up to
    // "_security_review_202607" (24 chars) and Postgres identifiers truncate
    // silently past 63 bytes, which would otherwise collide two partitions.
    const migrationSuffix = `mig${suffix.slice(0, 6)}`;
    const migrationTable = `audit_v2_test_${suffix.slice(0, 8)}`;
    await catalog.pool.query(`CREATE TABLE ${SCHEMA}.${migrationTable} (
        id TEXT PRIMARY KEY, ts TIMESTAMPTZ NOT NULL, actor_tag TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
        request_id TEXT, target_id TEXT, scope_tag TEXT, details_json JSONB NOT NULL DEFAULT '{}'::jsonb)`);
    const auditIds = [];
    async function insertAuditRow({ marker, action, outcome, ts }) {
      const id = `${migrationSuffix}-${marker}`;
      auditIds.push(id);
      await catalog.pool.query({
        text: `INSERT INTO ${SCHEMA}.${migrationTable}(id, ts, actor_tag, action, outcome, request_id, target_id, scope_tag, details_json)
          VALUES ($1,$2,$3,$4,$5,NULL,NULL,NULL,'{}'::jsonb)`,
        values: [id, ts, opaque('actor', id), action, outcome]
      });
      return id;
    }
    const migrationNow = '2026-07-12T12:00:00.000Z';
    const expiredStatusId = await insertAuditRow({ marker: 'expired-status', action: 'memory_status', outcome: 'allowed', ts: '2026-07-01T00:00:00.000Z' });
    const freshStatusId = await insertAuditRow({ marker: 'fresh-status', action: 'memory_status', outcome: 'allowed', ts: '2026-07-12T11:00:00.000Z' });
    const longRetainedId = await insertAuditRow({ marker: 'long-retained', action: 'memory_propose', outcome: 'applied', ts: '2000-01-01T00:00:00.000Z' });
    const deniedId = await insertAuditRow({ marker: 'denied-recent', action: 'memory_read', outcome: 'denied', ts: '2026-07-12T00:00:00.000Z' });

    const phaseAResult = await runPhaseADeleteBatch({ pool: catalog.pool, table: migrationTable, asOf: migrationNow, batchSize: 1000 });
    assert.ok(phaseAResult.deletedIds.includes(expiredStatusId), 'expired ephemeral_status row is deleted by Phase A');
    assert.ok(!phaseAResult.deletedIds.includes(freshStatusId), 'fresh ephemeral_status row survives Phase A');
    assert.ok(!phaseAResult.deletedIds.includes(longRetainedId), 'long_retained row is never deleted by Phase A');
    assert.ok(!phaseAResult.deletedIds.includes(deniedId), 'recent security_review row survives Phase A');
    const remainingAfterA = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.${migrationTable} WHERE id = ANY($1::text[])`, values: [auditIds] });
    assert.deepEqual(remainingAfterA.rows.map(row => row.id).sort(), [freshStatusId, longRetainedId, deniedId].sort());

    await createAuditEventsV2NextSchema(catalog.pool, migrationTable);
    const beforeCopyCount = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.${migrationTable} WHERE id = ANY($1::text[])`, values: [auditIds] });
    const copyResult = await copyAuditEventsBatch({ pool: catalog.pool, table: migrationTable, batchSize: 10_000 });
    assert.ok(copyResult.copiedCount >= Number(beforeCopyCount.rows[0].count));
    const copiedRows = await catalog.pool.query({ text: `SELECT id, retention_class FROM ${SCHEMA}.${migrationTable}_next WHERE id = ANY($1::text[])`, values: [auditIds] });
    const byId = Object.fromEntries(copiedRows.rows.map(row => [row.id, row.retention_class]));
    assert.equal(byId[freshStatusId], 'ephemeral_status');
    assert.equal(byId[longRetainedId], 'long_retained');
    assert.equal(byId[deniedId], 'security_review');

    const cutover = await cutoverAuditEventsV2({ pool: catalog.pool, table: migrationTable, legacySuffix: migrationSuffix });
    const postCutoverNew = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.${migrationTable} WHERE id = ANY($1::text[])`, values: [auditIds] });
    assert.deepEqual(postCutoverNew.rows.map(row => row.id).sort(), [freshStatusId, longRetainedId, deniedId].sort(), 'the clone table now serves from the partitioned table');
    const legacyStillHasSurvivors = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${cutover.legacyTable} WHERE id = ANY($1::text[])`, values: [auditIds] });
    assert.equal(Number(legacyStillHasSurvivors.rows[0].count), 3, 'the renamed legacy table still holds its rows for the rollback window');

    await catalog.pool.query(`DROP TABLE IF EXISTS ${cutover.legacyTable}`);
    await catalog.pool.query(`DROP TABLE IF EXISTS ${SCHEMA}.${migrationTable} CASCADE`);
  } finally {
    try {
      await catalog.pool.query(`DROP TABLE IF EXISTS ${SCHEMA}.audit_v2_test_${suffix.slice(0, 8)} CASCADE`);
      await catalog.pool.query(`DROP TABLE IF EXISTS ${SCHEMA}.audit_v2_test_${suffix.slice(0, 8)}_legacy_mig${suffix.slice(0, 6)} CASCADE`);
    } catch {}
    let cleanupClient;
    try {
      if (catalogReady) {
        cleanupClient = await catalog.pool.connect();
        await cleanupClient.query('BEGIN');
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.raw_gc_tombstones_v1 WHERE session_id = ANY($1::text[]) OR id LIKE $2`, values: [[...sessionIds], `${suffix}-%`] });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.raw_gc_operations_v1 WHERE idempotency_tag LIKE $1`, values: [`gc-integration-${suffix}%`] });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.session_archive_proof_v1 WHERE session_id = ANY($1::text[])`, values: [[...sessionIds]] });
        await cleanupClient.query({
          text: `DELETE FROM ${SCHEMA}.conversation_archive_events_v1 WHERE conversation_id = ANY($1::text[])`,
          values: [[...sessionIds].map(id => deriveM4V3ConversationIdFromLegacySessionId(id))]
        });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.fabric_proposals WHERE id LIKE $1`, values: [`proposal-${suffix}%`] });
        await cleanupClient.query({
          text: `DELETE FROM ${SCHEMA}.logical_message_aliases_v2 WHERE logical_message_id IN (
              SELECT DISTINCT logical_message_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = ANY($1::text[]))`,
          values: [[...sessionIds]]
        });
        await cleanupClient.query({
          text: `DELETE FROM ${SCHEMA}.logical_messages_v2 WHERE logical_message_id IN (
              SELECT DISTINCT logical_message_id FROM ${SCHEMA}.raw_events_v2 WHERE session_id = ANY($1::text[]))`,
          values: [[...sessionIds]]
        });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.raw_events_v2 WHERE session_id = ANY($1::text[])`, values: [[...sessionIds]] });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.raw_sessions_v1 WHERE session_id = ANY($1::text[])`, values: [[...sessionIds]] });
        await cleanupClient.query({ text: `DELETE FROM ${SCHEMA}.raw_objects_v2 WHERE content_id = ANY($1::text[])`, values: [[...contentIds]] });
        await cleanupClient.query('COMMIT');
      }
    } catch (cleanupError) {
      try { await cleanupClient?.query('ROLLBACK'); } catch {}
      throw cleanupError;
    } finally {
      cleanupClient?.release();
      await catalog.close();
    }
  }
});
