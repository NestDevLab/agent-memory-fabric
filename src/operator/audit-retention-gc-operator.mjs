import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  DEFAULT_AUDIT_RETENTION_POLICY, auditRetentionActionsByClass, auditRetentionWindowDays
} from '../audit-retention.mjs';
import {
  copyAuditEventsBatch, createAuditEventsV2NextSchema, cutoverAuditEventsV2,
  rollbackAuditEventsV2Cutover, runPhaseADeleteBatch
} from '../audit-partition-migration.mjs';
import { RawGcEngine } from '../raw-gc.mjs';

const SCHEMA = 'agent_memory_fabric';
const DEFAULT_TABLE = 'audit_events_v2';
const DEFAULT_RAW_TABLE = 'raw_events_v2';

/**
 * Design §8.5: each of these is its own point-in-time approval, never a
 * blanket sign-off. A run must name exactly the checkpoint its own mutation
 * class requires.
 */
export const CHECKPOINTS = Object.freeze({
  AUDIT_BULK_DELETE: 'audit-bulk-delete',
  AUDIT_PARTITION_MIGRATION: 'audit-partition-migration',
  RAW_GC_LIVE: 'raw-gc-live'
});

const CHECKPOINT_IDS = new Set(Object.values(CHECKPOINTS));

export function fail(code, details) {
  const error = new Error(code);
  error.code = code;
  if (details) error.details = details;
  throw error;
}

/** Never trusts a database name alone as a "safe to mutate" signal on its own; distinct guard from the operator's live-target confirmation. */
export function isTestDatabaseUrl(databaseUrl) {
  let name;
  try { name = decodeURIComponent(new URL(databaseUrl).pathname.replace(/^\//, '')); } catch { return false; }
  return /(^|[-_])test($|[-_])/i.test(name);
}

/** host:port/dbname, derived only from the connection string, never logged with credentials. */
export function connectionTarget(databaseUrl) {
  let url;
  try { url = new URL(databaseUrl); } catch { fail('operator_database_url_invalid'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) fail('operator_database_url_invalid');
  const dbName = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (!dbName) fail('operator_database_url_invalid');
  const port = url.port || '5432';
  return `${url.hostname}:${port}/${dbName}`;
}

export function sslConfigFromMode(mode, caPath) {
  if (!['disable', 'require', 'verify-full'].includes(mode)) fail('operator_ssl_mode_invalid');
  if (mode === 'disable') return false;
  if (mode === 'require') return { rejectUnauthorized: false };
  const config = { rejectUnauthorized: true };
  if (caPath) config.ca = fs.readFileSync(path.resolve(caPath), 'utf8');
  return config;
}

/**
 * The mutation gate all `--apply` subcommands share. Distinct from the
 * test-database guard used by the integration test suite: this one binds
 * the exact connected target, so a copy-pasted command for the wrong host
 * refuses instead of silently running.
 */
export function requireLiveMutationGuard({
  apply, approval, requiredCheckpoint, iKnowThisIsLive, confirmTarget, resolvedTarget
}) {
  if (!apply) return { willMutate: false };
  if (!CHECKPOINT_IDS.has(requiredCheckpoint)) fail('operator_checkpoint_unknown');
  if (approval !== requiredCheckpoint) fail('operator_approval_missing_or_wrong', { required: requiredCheckpoint });
  if (iKnowThisIsLive !== true) fail('operator_live_confirmation_required');
  if (!confirmTarget || confirmTarget !== resolvedTarget) fail('operator_target_confirmation_mismatch', { resolvedTarget });
  return { willMutate: true };
}

/** Refuses a stale or missing verified-backup attestation before any destructive apply. */
export function requireBackupAttestation({ backupId, backupVerifiedAt, maxAgeHours = 24, now = () => new Date() }) {
  if (!backupId || typeof backupId !== 'string') fail('operator_backup_id_required');
  const verifiedAtMs = Date.parse(backupVerifiedAt || '');
  if (!Number.isFinite(verifiedAtMs)) fail('operator_backup_verified_at_invalid');
  const ageMs = now().getTime() - verifiedAtMs;
  if (ageMs < 0) fail('operator_backup_verified_at_in_future');
  if (ageMs > maxAgeHours * 3_600_000) fail('operator_backup_attestation_stale', { ageHours: ageMs / 3_600_000, maxAgeHours });
  return { backupId, verifiedAt: new Date(verifiedAtMs).toISOString(), ageHours: ageMs / 3_600_000 };
}

/** fs.statfsSync-backed free-space probe; a fixed function so tests can inject a fake without touching the real filesystem. */
export function freeBytesOf(targetPath) {
  const stat = fs.statfsSync(targetPath);
  return stat.bavail * stat.bsize;
}

/** Refuses when free space would drop below the floor once `estimateBytes` of temporary space is consumed. Never assumes; the estimate must be measured live by the caller. */
export function requireFreeSpaceFloor({ freeBytes, floorBytes, estimateBytes = 0 }) {
  if (!Number.isSafeInteger(floorBytes) || floorBytes < 0) fail('operator_free_space_floor_invalid');
  if (!Number.isSafeInteger(estimateBytes) || estimateBytes < 0) fail('operator_free_space_estimate_invalid');
  const projected = freeBytes - estimateBytes;
  if (projected < floorBytes) fail('operator_free_space_floor_breached', { freeBytes, floorBytes, estimateBytes, projectedFreeBytes: projected });
  return { freeBytes, projectedFreeBytes: projected };
}

async function tableSizeBytes(pool, table) {
  const result = await pool.query({ text: 'SELECT pg_total_relation_size($1::regclass)::bigint AS bytes', values: [`${SCHEMA}.${table}`] });
  return Number(result.rows[0].bytes);
}

async function tableRowEstimate(pool, table) {
  const result = await pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.${table}` });
  return Number(result.rows[0].count);
}

async function postgresMajorVersion(pool) {
  const result = await pool.query('SHOW server_version_num');
  return Math.floor(Number(result.rows[0].server_version_num) / 10000);
}

/**
 * §8 step 1 (read-only). Row counts by retention class come from a single
 * GROUP BY (action, outcome) scan classified client-side, not from scanning
 * with per-class date filters, because the action->window mapping already
 * lives in audit-retention.mjs and duplicating it as SQL CASE branches would
 * be a second, driftable copy of the same rule.
 */
export async function collectAuditRowCountsByClass(pool, { table = DEFAULT_TABLE, classify } = {}) {
  const result = await pool.query(`SELECT action, outcome, count(*)::bigint AS count FROM ${SCHEMA}.${table} GROUP BY action, outcome`);
  const byClass = { ephemeral_status: 0, ephemeral_operational: 0, security_review: 0, long_retained: 0 };
  for (const row of result.rows) byClass[classify(row.action, row.outcome)] += Number(row.count);
  return byClass;
}

/** §8 step 1: how many rows Phase A would delete right now, per class, without deleting any. Mirrors runPhaseADeleteBatch's predicate as a COUNT, never a DELETE. */
export async function countAuditPhaseAWouldDelete(pool, { table = DEFAULT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString() } = {}) {
  const ephemeralOperationalActions = auditRetentionActionsByClass('ephemeral_operational');
  const longRetainedActions = auditRetentionActionsByClass('long_retained');
  const result = await pool.query({
    text: `SELECT
        count(*) FILTER (WHERE action = 'memory_status' AND outcome = 'allowed' AND ts < $1::timestamptz - ($2 || ' days')::interval)::bigint AS ephemeral_status,
        count(*) FILTER (WHERE action = ANY($3::text[]) AND outcome NOT IN ('denied','failed') AND ts < $1::timestamptz - ($4 || ' days')::interval)::bigint AS ephemeral_operational,
        count(*) FILTER (WHERE (outcome IN ('denied','failed') AND action <> ALL($5::text[]) AND ts < $1::timestamptz - ($6 || ' days')::interval)
                            OR (action = 'authenticate' AND ts < $1::timestamptz - ($6 || ' days')::interval))::bigint AS security_review
      FROM ${SCHEMA}.${table}`,
    values: [
      asOf,
      String(auditRetentionWindowDays('ephemeral_status', policy)),
      ephemeralOperationalActions,
      String(auditRetentionWindowDays('ephemeral_operational', policy)),
      longRetainedActions,
      String(auditRetentionWindowDays('security_review', policy))
    ]
  });
  const row = result.rows[0];
  return {
    ephemeral_status: Number(row.ephemeral_status),
    ephemeral_operational: Number(row.ephemeral_operational),
    security_review: Number(row.security_review),
    long_retained: 0
  };
}

/** §8 step 1, entirely read-only: no subcommand here ever writes. */
export async function runInventory({
  pool, table = DEFAULT_TABLE, rawTable = DEFAULT_RAW_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY,
  asOf = new Date().toISOString(), classify, filesystemPath = process.cwd(), env = process.env,
  freeBytesProbe = freeBytesOf
}) {
  const [postgresMajor, auditBytes, rawBytes, rowCountsByClass, wouldDeleteByClass, rawEventCount] = await Promise.all([
    postgresMajorVersion(pool),
    tableSizeBytes(pool, table),
    tableSizeBytes(pool, rawTable).catch(() => null),
    collectAuditRowCountsByClass(pool, { table, classify }),
    countAuditPhaseAWouldDelete(pool, { table, policy, asOf }),
    tableRowEstimate(pool, rawTable).catch(() => null)
  ]);
  let filesystemFreeBytes = null;
  try { filesystemFreeBytes = freeBytesProbe(filesystemPath); } catch { filesystemFreeBytes = null; }
  return {
    schema: 'amf.audit-retention-gc-inventory/v1',
    asOf,
    postgresMajorVersion: postgresMajor,
    tables: {
      [table]: { totalBytes: auditBytes, rowCountsByRetentionClass: rowCountsByClass, wouldDeleteByRetentionClass: wouldDeleteByClass },
      [rawTable]: { totalBytes: rawBytes, rowEstimate: rawEventCount }
    },
    conversationReaderMode: env.AMF_CONVERSATION_READER_MODE ?? 'disabled',
    conversationExtractorMode: env.AMF_CONVERSATION_EXTRACTOR_MODE ?? 'legacy',
    filesystem: { path: filesystemPath, freeBytes: filesystemFreeBytes }
  };
}

/** One bounded Phase A batch. Dry-run only counts victims; --apply deletes them. Resumable by construction: the predicate re-selects whatever is still eligible, no cursor to lose. */
export async function runAuditPhaseABatch({ pool, table = DEFAULT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(), batchSize = 20_000, apply }) {
  if (!apply) {
    const wouldDelete = await countAuditPhaseAWouldDelete(pool, { table, policy, asOf });
    const total = wouldDelete.ephemeral_status + wouldDelete.ephemeral_operational + wouldDelete.security_review;
    return { dryRun: true, wouldDeleteByRetentionClass: wouldDelete, wouldDeleteTotal: Math.min(total, batchSize), wouldDeleteGrandTotal: total };
  }
  const result = await runPhaseADeleteBatch({ pool, table, policy, asOf, batchSize });
  return { dryRun: false, deletedCount: result.deletedCount };
}

/** Phase C schema step: creates the partitioned replacement alongside the existing table. Idempotent (IF NOT EXISTS everywhere in createAuditEventsV2NextSchema). */
export async function runAuditPhaseCSchema({ pool, table = DEFAULT_TABLE }) {
  await createAuditEventsV2NextSchema(pool, table);
  return { step: 'schema', table: `${table}_next` };
}

function readCursorFile(cursorFile) {
  try { return JSON.parse(fs.readFileSync(cursorFile, 'utf8')); }
  catch (error) { if (error?.code === 'ENOENT') return { cursorTs: '1970-01-01T00:00:00.000Z', cursorId: '' }; fail('operator_cursor_file_invalid'); }
}

function writeCursorFileAtomic(cursorFile, cursor) {
  const tmp = `${cursorFile}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmp, JSON.stringify(cursor), { mode: 0o600 });
  fs.renameSync(tmp, cursorFile);
}

/**
 * Phase C copy: one to `maxBatches` batches per invocation, cursor persisted
 * to `cursorFile` between invocations so a restart resumes instead of
 * rescanning. copyAuditEventsBatch's own ON CONFLICT DO NOTHING makes this
 * idempotent even if the cursor file were lost.
 */
export async function runAuditPhaseCCopy({ pool, table = DEFAULT_TABLE, batchSize = 5000, maxBatches = 1, cursorFile }) {
  if (!cursorFile) fail('operator_cursor_file_required');
  let cursor = readCursorFile(cursorFile);
  const batches = [];
  let drained = false;
  for (let index = 0; index < maxBatches; index += 1) {
    const result = await copyAuditEventsBatch({ pool, table, cursorTs: cursor.cursorTs, cursorId: cursor.cursorId, batchSize });
    batches.push({ copiedCount: result.copiedCount });
    if (result.copiedCount === 0) { drained = true; break; }
    cursor = { cursorTs: result.cursorTs, cursorId: result.cursorId };
    writeCursorFileAtomic(cursorFile, cursor);
  }
  return { step: 'copy', batches, drained, cursor };
}

/** Phase D cutover. Requires the operator to have already driven Phase C to drained (checked by the caller/CLI, not silently assumed here). */
export async function runAuditPhaseDCutover({ pool, table = DEFAULT_TABLE, legacySuffix }) {
  return { step: 'cutover', ...(await cutoverAuditEventsV2({ pool, table, ...(legacySuffix ? { legacySuffix } : {}) })) };
}

/** Rollback while the legacy table is still retained (§8 step 4). No backup attestation required: this itself is the recovery path when something else already went wrong. */
export async function runAuditRollback({ pool, table = DEFAULT_TABLE, legacyTable }) {
  await rollbackAuditEventsV2Cutover({ pool, table, legacyTable });
  return { step: 'rollback', table, legacyTable };
}

/** Design §5/§6: GC eligibility stays gated by the engine's own archive proof. This is an additional, earlier refusal for the live path only — it never widens what the engine accepts. */
export function requireReaderModeForLiveGc(env = process.env) {
  const mode = env.AMF_CONVERSATION_READER_MODE ?? 'disabled';
  if (mode !== 'active' && mode !== 'shadow') fail('raw_gc_reader_mode_disabled', { mode });
  return { mode };
}

/**
 * Runs up to `maxRuns` bounded batches of RawGcEngine.run(), printing each
 * batch's counters. `dryRun=true` performs zero writes and needs no
 * checkpoint/backup/live guard; `dryRun=false` is the caller's
 * responsibility to gate with requireLiveMutationGuard + requireReaderModeForLiveGc first.
 */
export async function runRawGc({ engine, idempotencyTag, dryRun = true, maxRuns = 1 }) {
  const runs = [];
  for (let index = 0; index < maxRuns; index += 1) {
    const result = await engine.run({ idempotencyTag, dryRun });
    runs.push(result);
    if (result.status === 'completed') break;
  }
  return { dryRun, runs };
}

export function createRawGcEngine({ pool, ...options }) {
  return new RawGcEngine({ pool, ...options });
}
