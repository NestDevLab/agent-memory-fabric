import crypto from 'node:crypto';

import { DEFAULT_AUDIT_RETENTION_POLICY, auditRetentionActionsByClass, auditRetentionWindowDays, classifyAuditEvent } from './audit-retention.mjs';

const SCHEMA = 'agent_memory_fabric';
const DEFAULT_SOURCE_TABLE = 'audit_events_v2';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function rowDigest(rows) {
  const canonical = rows
    .map(row => `${row.id}|${row.ts}|${row.actor_tag}|${row.action}|${row.outcome}|${row.request_id ?? ''}|${row.target_id ?? ''}|${row.scope_tag ?? ''}|${JSON.stringify(row.details_json)}`)
    .sort();
  return crypto.createHash('sha256').update(canonical.join('\n')).digest('hex');
}

/**
 * Phase A (§4.2): one bounded delete batch under the retention policy,
 * computed inline in the predicate — never persisted onto existing rows.
 * `table` defaults to the real audit_events_v2 but can name an isolated
 * clone (same column shape) so this can be exercised without contending
 * with concurrent writers of the live table — e.g. in tests.
 */
export async function runPhaseADeleteBatch({ pool, table = DEFAULT_SOURCE_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(), batchSize = 20_000 }) {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100_000) fail('audit_migration_batch_size_invalid');
  const ephemeralOperationalActions = auditRetentionActionsByClass('ephemeral_operational');
  const longRetainedActions = auditRetentionActionsByClass('long_retained');
  const result = await pool.query({
    text: `WITH victims AS (
        SELECT id FROM ${SCHEMA}.${table}
        WHERE (
            (action = 'memory_status' AND outcome = 'allowed' AND ts < $1::timestamptz - ($2 || ' days')::interval)
         OR (action = ANY($3::text[]) AND outcome NOT IN ('denied','failed') AND ts < $1::timestamptz - ($4 || ' days')::interval)
         OR (outcome IN ('denied','failed') AND action <> ALL($5::text[]) AND ts < $1::timestamptz - ($6 || ' days')::interval)
         OR (action = 'authenticate' AND ts < $1::timestamptz - ($6 || ' days')::interval)
        )
        ORDER BY ts LIMIT $7
      )
      DELETE FROM ${SCHEMA}.${table} a USING victims WHERE a.id = victims.id
      RETURNING a.id`,
    values: [
      asOf,
      String(auditRetentionWindowDays('ephemeral_status', policy)),
      ephemeralOperationalActions,
      String(auditRetentionWindowDays('ephemeral_operational', policy)),
      longRetainedActions,
      String(auditRetentionWindowDays('security_review', policy)),
      batchSize
    ]
  });
  return { deletedCount: result.rows.length, deletedIds: result.rows.map(row => row.id) };
}

/** Repeats Phase A batches until a batch deletes nothing, vacuuming every few batches. */
export async function runPhaseAUntilDrained({ pool, table = DEFAULT_SOURCE_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(), batchSize = 20_000, vacuumEvery = 5, maxBatches = 100_000, onProgress = () => {} }) {
  let totalDeleted = 0;
  let batches = 0;
  for (; batches < maxBatches; batches += 1) {
    const { deletedCount } = await runPhaseADeleteBatch({ pool, table, policy, asOf, batchSize });
    totalDeleted += deletedCount;
    onProgress({ batch: batches + 1, deletedCount, totalDeleted });
    if (deletedCount === 0) break;
    if ((batches + 1) % vacuumEvery === 0) await pool.query(`VACUUM (ANALYZE) ${SCHEMA}.${table}`);
  }
  await pool.query(`VACUUM (ANALYZE) ${SCHEMA}.${table}`);
  return { totalDeleted, batches };
}

function partitionNames(table) {
  return {
    next: `${table}_next`,
    longRetained: `${table}_long_retained`,
    ephemeral: `${table}_ephemeral`,
    securityReview: `${table}_security_review`
  };
}

/** Phase C (§4.2): the partitioned replacement schema, created alongside the existing table. */
export async function createAuditEventsV2NextSchema(pool, table = DEFAULT_SOURCE_TABLE) {
  const names = partitionNames(table);
  const statements = [
    `CREATE TABLE IF NOT EXISTS ${SCHEMA}.${names.next} (
      id TEXT NOT NULL,
      ts TIMESTAMPTZ NOT NULL,
      actor_tag TEXT NOT NULL,
      action TEXT NOT NULL,
      outcome TEXT NOT NULL,
      request_id TEXT,
      target_id TEXT,
      scope_tag TEXT,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      retention_class TEXT NOT NULL CHECK (retention_class IN
        ('ephemeral_status','ephemeral_operational','security_review','long_retained')),
      PRIMARY KEY (retention_class, ts, id)
    ) PARTITION BY LIST (retention_class)`,
    `CREATE TABLE IF NOT EXISTS ${SCHEMA}.${names.longRetained} PARTITION OF ${SCHEMA}.${names.next}
      FOR VALUES IN ('long_retained')`,
    `CREATE TABLE IF NOT EXISTS ${SCHEMA}.${names.ephemeral} PARTITION OF ${SCHEMA}.${names.next}
      FOR VALUES IN ('ephemeral_status','ephemeral_operational') PARTITION BY RANGE (ts)`,
    `CREATE TABLE IF NOT EXISTS ${SCHEMA}.${names.securityReview} PARTITION OF ${SCHEMA}.${names.next}
      FOR VALUES IN ('security_review') PARTITION BY RANGE (ts)`
  ];
  for (const statement of statements) await pool.query(statement);
}

function isoWeekStart(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay() || 7;
  if (day !== 1) d.setUTCDate(d.getUTCDate() - day + 1);
  return d;
}

/** Idempotently ensures the weekly ephemeral child partition covering `date` exists. */
export async function ensureEphemeralWeekPartition(pool, date = new Date(), table = DEFAULT_SOURCE_TABLE) {
  const names = partitionNames(table);
  const start = isoWeekStart(date);
  const end = new Date(start.getTime() + 7 * 86_400_000);
  const suffix = start.toISOString().slice(0, 10).replace(/-/g, '');
  const name = `${names.ephemeral}_${suffix}`;
  await pool.query(`CREATE TABLE IF NOT EXISTS ${SCHEMA}.${name} PARTITION OF ${SCHEMA}.${names.ephemeral}
    FOR VALUES FROM ('${start.toISOString()}') TO ('${end.toISOString()}')`);
  return { name, start: start.toISOString(), end: end.toISOString() };
}

/** Idempotently ensures the monthly security_review child partition covering `date` exists. */
export async function ensureSecurityReviewMonthPartition(pool, date = new Date(), table = DEFAULT_SOURCE_TABLE) {
  const names = partitionNames(table);
  const start = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
  const end = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1));
  const suffix = start.toISOString().slice(0, 7).replace('-', '');
  const name = `${names.securityReview}_${suffix}`;
  await pool.query(`CREATE TABLE IF NOT EXISTS ${SCHEMA}.${name} PARTITION OF ${SCHEMA}.${names.securityReview}
    FOR VALUES FROM ('${start.toISOString()}') TO ('${end.toISOString()}')`);
  return { name, start: start.toISOString(), end: end.toISOString() };
}

async function ensurePartitionsFor(pool, rows, table) {
  const weeks = new Set();
  const months = new Set();
  for (const row of rows) {
    if (row.retention_class === 'security_review') months.add(new Date(row.ts).toISOString().slice(0, 7));
    else if (row.retention_class !== 'long_retained') weeks.add(isoWeekStart(new Date(row.ts)).toISOString());
  }
  for (const week of weeks) await ensureEphemeralWeekPartition(pool, new Date(week), table);
  for (const month of months) await ensureSecurityReviewMonthPartition(pool, new Date(`${month}-01T00:00:00.000Z`), table);
}

/** Copies and verifies one batch using an already-connected client; no transaction management of its own. */
async function copyAuditEventsBatchWithClient(client, { table, cursorTs = '1970-01-01T00:00:00.000Z', cursorId = '', batchSize = 5000 }) {
  const names = partitionNames(table);
  const source = await client.query({
    text: `SELECT id, ts, actor_tag, action, outcome, request_id, target_id, scope_tag, details_json
        FROM ${SCHEMA}.${table}
        WHERE (ts, id) > ($1::timestamptz, $2)
        ORDER BY ts, id LIMIT $3`,
    values: [cursorTs, cursorId, batchSize]
  });
  if (source.rows.length === 0) return { copiedCount: 0, cursorTs, cursorId, verified: true };
  await ensurePartitionsFor(client, source.rows.map(row => ({ ts: row.ts, retention_class: classifyAuditEvent(row.action, row.outcome) })), table);
  for (const row of source.rows) {
    const retentionClass = classifyAuditEvent(row.action, row.outcome);
    await client.query({
      text: `INSERT INTO ${SCHEMA}.${names.next} (id, ts, actor_tag, action, outcome, request_id, target_id, scope_tag, details_json, retention_class)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (retention_class, ts, id) DO NOTHING`,
      values: [row.id, row.ts, row.actor_tag, row.action, row.outcome, row.request_id, row.target_id, row.scope_tag, row.details_json, retentionClass]
    });
  }
  const ids = source.rows.map(row => row.id);
  const verify = await client.query({
    text: `SELECT id, ts, actor_tag, action, outcome, request_id, target_id, scope_tag, details_json FROM ${SCHEMA}.${names.next} WHERE id = ANY($1::text[])`,
    values: [ids]
  });
  const verified = verify.rows.length === source.rows.length && rowDigest(verify.rows) === rowDigest(source.rows);
  if (!verified) fail('audit_migration_phase_c_digest_mismatch');
  const last = source.rows[source.rows.length - 1];
  const lastTs = last.ts?.toISOString ? last.ts.toISOString() : last.ts;
  return { copiedCount: source.rows.length, cursorTs: lastTs, cursorId: last.id, verified: true };
}

/**
 * Phase C copy (§4.2): one ts-ordered batch of survivors from the legacy
 * table into <table>_next, verified by row-count and digest before the
 * caller advances its cursor. Resumable via the returned cursor.
 */
export async function copyAuditEventsBatch({ pool, table = DEFAULT_SOURCE_TABLE, cursorTs = '1970-01-01T00:00:00.000Z', cursorId = '', batchSize = 5000 }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await copyAuditEventsBatchWithClient(client, { table, cursorTs, cursorId, batchSize });
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export async function copyAuditEventsUntilDrained({ pool, table = DEFAULT_SOURCE_TABLE, batchSize = 5000, onProgress = () => {} }) {
  let cursorTs = '1970-01-01T00:00:00.000Z';
  let cursorId = '';
  let totalCopied = 0;
  for (;;) {
    const result = await copyAuditEventsBatch({ pool, table, cursorTs, cursorId, batchSize });
    totalCopied += result.copiedCount;
    onProgress({ ...result, totalCopied });
    if (result.copiedCount === 0) break;
    cursorTs = result.cursorTs;
    cursorId = result.cursorId;
  }
  return { totalCopied, cursorTs, cursorId };
}

/** Same drain loop, but reusing an already-open client/transaction (used by cutover's catch-up pass). */
async function copyAuditEventsUntilDrainedWithClient(client, { table, batchSize = 5000 }) {
  let cursorTs = '1970-01-01T00:00:00.000Z';
  let cursorId = '';
  let totalCopied = 0;
  for (;;) {
    const result = await copyAuditEventsBatchWithClient(client, { table, cursorTs, cursorId, batchSize });
    totalCopied += result.copiedCount;
    if (result.copiedCount === 0) break;
    cursorTs = result.cursorTs;
    cursorId = result.cursorId;
  }
  return { totalCopied };
}

/**
 * Phase D cutover (§4.2): catches up rows inserted during the copy window,
 * then renames the legacy table aside and promotes <table>_next in one
 * short transaction. The legacy table stays present under its renamed name
 * for an operator-controlled rollback window.
 */
export async function cutoverAuditEventsV2({ pool, table = DEFAULT_SOURCE_TABLE, legacySuffix = new Date().toISOString().slice(0, 10).replace(/-/g, '') }) {
  const names = partitionNames(table);
  await copyAuditEventsUntilDrained({ pool, table });
  const legacyName = `${table}_legacy_${legacySuffix}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await copyAuditEventsUntilDrainedWithClient(client, { table });
    await client.query(`ALTER TABLE ${SCHEMA}.${table} RENAME TO ${legacyName}`);
    await client.query(`ALTER TABLE ${SCHEMA}.${names.next} RENAME TO ${table}`);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return { legacyTable: `${SCHEMA}.${legacyName}` };
}

/** Rollback path for cutoverAuditEventsV2 while the legacy table is still retained. */
export async function rollbackAuditEventsV2Cutover({ pool, table = DEFAULT_SOURCE_TABLE, legacyTable }) {
  if (!legacyTable) fail('audit_migration_legacy_table_required');
  const names = partitionNames(table);
  await pool.query(`ALTER TABLE ${SCHEMA}.${table} RENAME TO ${names.next}`);
  await pool.query(`ALTER TABLE ${legacyTable} RENAME TO ${table}`);
}
