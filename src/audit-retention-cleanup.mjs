import {
  AUDIT_RETENTION_CLASSES, DEFAULT_AUDIT_RETENTION_POLICY, buildPhaseAPredicate, classifyAuditEvent,
  isAuditRetentionExpired, isKnownAuditEventPair
} from './audit-retention.mjs';

export const AUDIT_SCHEMA = 'agent_memory_fabric';
export const AUDIT_TABLE = 'audit_events_v2';

function fail(code, details) {
  const error = new Error(code);
  error.code = code;
  if (details) error.details = details;
  throw error;
}

function quoteIdentifier(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/** Only the canonical audit table, refused before any SQL runs. */
export function qualifiedAuditTable(table = AUDIT_TABLE) {
  if (table !== AUDIT_TABLE) fail('audit_retention_table_not_allowed', { table: String(table).slice(0, 128) });
  return `${quoteIdentifier(AUDIT_SCHEMA)}.${quoteIdentifier(AUDIT_TABLE)}`;
}

function emptyByClass() {
  return Object.fromEntries(AUDIT_RETENTION_CLASSES.map(retentionClass => [retentionClass, 0]));
}

async function withTransaction(pool, { readOnly, lockTimeoutMs, statementTimeoutMs }, work) {
  const client = await pool.connect();
  let discard = false;
  try {
    await client.query(readOnly ? 'BEGIN TRANSACTION READ ONLY' : 'BEGIN');
    if (Number.isSafeInteger(lockTimeoutMs)) await client.query(`SET LOCAL lock_timeout = ${lockTimeoutMs}`);
    if (Number.isSafeInteger(statementTimeoutMs)) await client.query(`SET LOCAL statement_timeout = ${statementTimeoutMs}`);
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { discard = true; }
    throw error;
  } finally {
    client.release(discard ? new Error('audit_retention_client_discarded') : undefined);
  }
}

/** Read-only inventory: row counts per (action, outcome) with their class. */
export async function countAuditRowsByPair({ pool, table = AUDIT_TABLE, statementTimeoutMs }) {
  const qualified = qualifiedAuditTable(table);
  return withTransaction(pool, { readOnly: true, statementTimeoutMs }, async client => {
    const result = await client.query(`SELECT action, outcome, count(*)::bigint AS count FROM ${qualified} GROUP BY action, outcome ORDER BY action, outcome`);
    const pairs = result.rows.map(row => ({
      action: row.action, outcome: row.outcome, count: Number(row.count),
      retentionClass: classifyAuditEvent(row.action, row.outcome), known: isKnownAuditEventPair(row.action, row.outcome)
    }));
    const byClass = emptyByClass();
    for (const pair of pairs) byClass[pair.retentionClass] += pair.count;
    return { pairs, byClass, unknownPairs: pairs.filter(pair => !pair.known) };
  });
}

/** What Phase A would delete now, per class and pair, in a READ ONLY transaction. */
export async function previewPhaseA({ pool, table = AUDIT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(), statementTimeoutMs }) {
  const qualified = qualifiedAuditTable(table);
  const predicate = buildPhaseAPredicate({ asOf, policy });
  return withTransaction(pool, { readOnly: true, statementTimeoutMs }, async client => {
    const result = await client.query({
      text: `SELECT action, outcome, count(*)::bigint AS count FROM ${qualified} WHERE ${predicate.text} GROUP BY action, outcome ORDER BY action, outcome`,
      values: predicate.values
    });
    const byClass = emptyByClass();
    const pairs = result.rows.map(row => {
      const retentionClass = classifyAuditEvent(row.action, row.outcome);
      byClass[retentionClass] += Number(row.count);
      return { action: row.action, outcome: row.outcome, retentionClass, count: Number(row.count) };
    });
    if (byClass.long_retained !== 0) fail('audit_retention_predicate_mismatch');
    return { asOf: new Date(asOf).toISOString(), eligibleByClass: byClass, eligibleTotal: pairs.reduce((sum, pair) => sum + pair.count, 0), pairs };
  });
}

/** One bounded delete batch; rolls back if any deleted row disagrees with the classifier. */
export async function runPhaseADeleteBatch({
  pool, table = AUDIT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(),
  batchSize = 5000, lockTimeoutMs = 5000, statementTimeoutMs = 120_000
}) {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100_000) fail('audit_retention_batch_size_invalid');
  const qualified = qualifiedAuditTable(table);
  const predicate = buildPhaseAPredicate({ asOf, policy, firstParam: 2 });
  return withTransaction(pool, { readOnly: false, lockTimeoutMs, statementTimeoutMs }, async client => {
    const result = await client.query({
      text: `WITH victims AS (
          SELECT id FROM ${qualified} WHERE ${predicate.text} ORDER BY ts LIMIT $1
        )
        DELETE FROM ${qualified} a USING victims WHERE a.id = victims.id
        RETURNING a.action, a.outcome, a.ts`,
      values: [batchSize, ...predicate.values]
    });
    const byClass = emptyByClass();
    for (const row of result.rows) {
      const retentionClass = classifyAuditEvent(row.action, row.outcome);
      if (retentionClass === 'long_retained' || !isAuditRetentionExpired(retentionClass, row.ts, asOf, policy)) {
        fail('audit_retention_predicate_mismatch');
      }
      byClass[retentionClass] += 1;
    }
    return { deletedCount: result.rows.length, deletedByClass: byClass };
  });
}
