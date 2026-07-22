import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4ReconciliationEventAccumulator } from '../migration/m4-reconciliation-snapshot.mjs';

const REQUIRED = ['event_id', 'state', 'logical_digest', 'payload_digest', 'source_occurred_at', 'event_json'];
const DOMAIN = 'amf.m4-v3-reconciliation-source/v1';
function fail(code) { const error = new Error(code); error.code = code; throw error; }
function exact(value, keys) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function projection(row, code) {
  if (!row || typeof row.event_id !== 'string' || typeof row.payload_digest !== 'string' || typeof row.logical_digest !== 'string' || typeof row.source_occurred_at !== 'string' || typeof row.occurred_at !== 'string' || typeof row.state !== 'string') fail(code);
  const value = { eventId: row.event_id, payloadDigest: row.payload_digest, logicalDigest: row.logical_digest, sourceOccurredAt: row.source_occurred_at, occurredAt: row.occurred_at, state: row.state };
  if (row.replaces_event_id != null) value.replacesEventId = row.replaces_event_id;
  if (row.tombstones_event_id != null) value.tombstonesEventId = row.tombstones_event_id;
  if (row.conflicts_with_event_ids != null) { try { value.conflictsWithEventIds = Array.isArray(row.conflicts_with_event_ids) ? row.conflicts_with_event_ids : JSON.parse(row.conflicts_with_event_ids); } catch { fail(code); } }
  return value;
}
function sql(postgres) { const json = name => postgres ? `event_json->>'${name}'` : `json_extract(event_json,'$.${name}')`; return `SELECT event_id,payload_digest,logical_digest,source_occurred_at,${json('occurredAt')} AS occurred_at,state,${json('replacesEventId')} AS replaces_event_id,${json('tombstonesEventId')} AS tombstones_event_id,${postgres ? "event_json->'conflictsWithEventIds'" : "json_extract(event_json,'$.conflictsWithEventIds')"} AS conflicts_with_event_ids FROM ${postgres ? 'agent_memory_fabric.conversation_archive_events_v1' : 'conversation_archive_events_v1'} WHERE event_id>${postgres ? '$1' : '?'} ORDER BY event_id ASC LIMIT ${postgres ? '$2' : '?'}`; }
function config(input, kind) { if (!exact(input, kind === 'sqlite' ? ['db', 'pageSize'] : ['acquireClient', 'pageSize']) || !Number.isSafeInteger(input.pageSize) || input.pageSize < 1 || input.pageSize > 10000) fail('m4_reconciliation_collector_source_invalid'); return input; }
function source({ kind, db, acquireClient, pageSize }) {
  let state = 'new'; let handle = null; let revision = null; let revisionSet = null;
  let iterated = false; let complete = false;
  const code = 'm4_reconciliation_collector_source_invalid';
  async function query(statement, values = []) { if (kind === 'sqlite') return db.prepare(statement).all(...values); return (await handle.query(statement, values)).rows; }
  async function begin() {
    if (kind === 'sqlite') { db.exec('BEGIN'); handle = db; state = 'open'; const columns = db.prepare('PRAGMA table_info(conversation_archive_events_v1)').all().map(row => row.name); if (REQUIRED.some(name => !columns.includes(name))) fail(code); }
    else { handle = await acquireClient(); if (!handle?.query || typeof handle.release !== 'function') { try { handle?.release?.(); } catch {} handle = null; fail(code); } state = 'open'; await handle.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'); const columns = (await handle.query("SELECT column_name FROM information_schema.columns WHERE table_schema='agent_memory_fabric' AND table_name='conversation_archive_events_v1'", [])).rows.map(row => row.column_name); if (REQUIRED.some(name => !columns.includes(name))) fail(code); }
  }
  async function end(commit) { if (state !== 'open') return; state = 'closed'; try { if (kind === 'sqlite') db.exec(commit ? 'COMMIT' : 'ROLLBACK'); else await handle.query(commit ? 'COMMIT' : 'ROLLBACK'); } catch { if (commit) fail(code); } finally { if (kind === 'postgres') handle.release(); handle = null; } }
  async function* rows() { let after = ''; for (;;) { const page = await query(sql(kind === 'postgres'), [after, pageSize]); if (!Array.isArray(page) || page.length > pageSize) fail(code); if (!page.length) return; for (const row of page) { const item = projection(row, code); after = item.eventId; yield item; } if (page.length < pageSize) return; } }
  return {
    async revisionSource() { if (state !== 'new') fail(code); try { await begin(); const accumulator = createM4ReconciliationEventAccumulator(); const ordered = crypto.createHash('sha256'); ordered.update(`${DOMAIN}\0v3\0`, 'utf8'); for await (const item of rows()) { accumulator.add(item); const encoded = canonicalJson(item); ordered.update(`${Buffer.byteLength(encoded, 'utf8')}\0`, 'utf8'); ordered.update(encoded, 'utf8'); } const set = accumulator.finish(); revisionSet = structuredClone(set); const value = { eventCount: set.eventCount, eventSetDigest: set.eventSetDigest, orderedRowsDigest: `sha256:${ordered.digest('hex')}` }; const checkpointDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson([DOMAIN, value]), 'utf8').digest('hex')}`; revision = { state: 'complete', checkpoint: { id: `m4v3-${checkpointDigest.slice(7)}`, digest: checkpointDigest } }; return structuredClone(revision); } catch (error) { await end(false); if (error?.code) throw error; fail(code); } },
    get events() { return { async *[Symbol.asyncIterator]() { if (state !== 'open' || !revision || !revisionSet || iterated) fail(code); iterated = true; try { const accumulator = createM4ReconciliationEventAccumulator(); for await (const item of rows()) { accumulator.add(item); yield item; } const current = accumulator.finish(); if (current.eventCount !== revisionSet.eventCount || current.eventSetDigest !== revisionSet.eventSetDigest) fail(code); complete = true; } catch (error) { if (error?.code) throw error; fail(code); } finally { if (!complete) await end(false); } } }; },
    async close() { if (state === 'closed') return; if (state !== 'open') fail(code); await end(complete); },
  };
}

export function createM4SqliteReconciliationCollector(input = {}) { const value = config(input, 'sqlite'); if (!value.db?.prepare || typeof value.db.exec !== 'function') fail('m4_reconciliation_collector_source_invalid'); return source({ kind: 'sqlite', ...value }); }
export function createM4PostgresReconciliationCollector(input = {}) { const value = config(input, 'postgres'); if (typeof value.acquireClient !== 'function') fail('m4_reconciliation_collector_source_invalid'); return source({ kind: 'postgres', ...value }); }
