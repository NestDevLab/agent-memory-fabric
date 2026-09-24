import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { PostgresCatalog } from '../src/fabric-store.mjs';
import { runCli } from './amf-audit-retention-gc-operator.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';
const SCHEMA = 'agent_memory_fabric';
const SSL_MODE = process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? 'disable' : 'verify-full';

function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function opaque(namespace, value) { return `hmac-sha256:integration:${digest(`${namespace}:${value}`)}`; }

function activeRuntimeDeps() {
  return {
    createFabricStoreFromEnv: () => ({ createSessionReader: () => null }),
    createConversationSessionRuntimeFromEnv: async () => ({
      status: () => ({ mode: 'active', pending: 0, compared: 0, matched: 0, mismatched: 0, unavailable: 0, inconclusive: 0, skipped: 0 }),
      reader: null,
      close: async () => {}
    })
  };
}

async function cli(args, dependencies) {
  return runCli(['node', 'amf-audit-retention-gc-operator.mjs', ...args], dependencies);
}

async function refusalCode(promise) {
  try { await promise; }
  catch (error) { return error.code; }
  throw new Error('expected a refusal but the call succeeded');
}

test('audit retention/GC operator CLI against real PostgreSQL', { skip: !enabled }, async () => {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
  assert.match(databaseName, /(^|[-_])test($|[-_])/i, 'AMF_TEST_POSTGRES_URL must reference an isolated test database');
  const catalog = new PostgresCatalog({ connectionString, ssl: SSL_MODE === 'disable' ? false : { rejectUnauthorized: true } });
  const suffix = crypto.randomUUID().replace(/-/g, '');
  const target = new URL(connectionString);
  const resolvedTarget = `${target.hostname}:${target.port || 5432}/${databaseName}`;
  const baseArgs = ['--database-url', connectionString, '--ssl-mode', SSL_MODE];
  const liveArgs = (checkpoint) => [
    '--apply', '--approval', checkpoint, '--i-know-this-is-live',
    '--confirm-target', resolvedTarget,
    '--backup-id', `backup-${suffix}`, '--backup-verified-at', new Date().toISOString()
  ];

  try {
    await catalog.ready();

    // ---- fixtures: audit_events_v2 rows spanning every retention class, some already expired ----
    const oldTs = '2000-01-01T00:00:00.000Z';
    const freshTs = new Date().toISOString();
    async function insertAudit(id, ts, action, outcome) {
      await catalog.pool.query({
        text: `INSERT INTO ${SCHEMA}.audit_events_v2(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json)
          VALUES ($1,$2,$3,$4,$5,NULL,NULL,NULL,'{}'::jsonb) ON CONFLICT (id) DO NOTHING`,
        values: [id, ts, opaque('actor', id), action, outcome]
      });
    }
    const expiredStatusId = `audit-${suffix}-expired-status`;
    const expiredOperationalId = `audit-${suffix}-expired-operational`;
    const freshOperationalId = `audit-${suffix}-fresh-operational`;
    const longRetainedId = `audit-${suffix}-long-retained`;
    await insertAudit(expiredStatusId, oldTs, 'memory_status', 'allowed');
    await insertAudit(expiredOperationalId, oldTs, 'session_get', 'allowed');
    await insertAudit(freshOperationalId, freshTs, 'session_get', 'allowed');
    await insertAudit(longRetainedId, oldTs, 'memory_propose', 'allowed');

    // ---- default dry-run makes zero writes ----
    const dryRun = await cli(['audit-phase-a', ...baseArgs, '--json']);
    assert.equal(dryRun.result.dryRun, true);
    assert.ok(dryRun.result.wouldDeleteByRetentionClass.ephemeral_status >= 1);
    assert.ok(dryRun.result.wouldDeleteByRetentionClass.ephemeral_operational >= 1);
    const afterDryRunCount = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.audit_events_v2 WHERE id = ANY($1::text[])`, values: [[expiredStatusId, expiredOperationalId, freshOperationalId, longRetainedId]] });
    assert.equal(Number(afterDryRunCount.rows[0].count), 4, 'dry run issued no DELETE');

    // ---- --apply without --approval refuses ----
    assert.equal(await refusalCode(cli(['audit-phase-a', ...baseArgs, '--apply'])), 'operator_approval_missing_or_wrong');

    // ---- --apply with the WRONG approval refuses ----
    assert.equal(await refusalCode(cli(['audit-phase-a', ...baseArgs, '--apply', '--approval', 'raw-gc-live', '--i-know-this-is-live',
      '--confirm-target', resolvedTarget, '--backup-id', 'b', '--backup-verified-at', new Date().toISOString()])), 'operator_approval_missing_or_wrong');

    // ---- --confirm-target mismatch refuses (the accidental-live-target guard) ----
    assert.equal(await refusalCode(cli(['audit-phase-a', ...baseArgs, '--apply', '--approval', 'audit-bulk-delete', '--i-know-this-is-live',
      '--confirm-target', 'wrong-host:5432/wrong-db', '--backup-id', 'b', '--backup-verified-at', new Date().toISOString()])), 'operator_target_confirmation_mismatch');

    // ---- stale backup attestation refuses ----
    const staleVerifiedAt = new Date(Date.now() - 48 * 3_600_000).toISOString();
    assert.equal(await refusalCode(cli(['audit-phase-a', ...baseArgs, '--apply', '--approval', 'audit-bulk-delete', '--i-know-this-is-live',
      '--confirm-target', resolvedTarget, '--backup-id', 'b', '--backup-verified-at', staleVerifiedAt, '--max-backup-age-hours', '24'])), 'operator_backup_attestation_stale');

    // ---- free-space floor refuses ----
    assert.equal(await refusalCode(cli(['audit-phase-a', ...baseArgs, ...liveArgs('audit-bulk-delete'), '--free-space-floor-bytes', String(Number.MAX_SAFE_INTEGER)])),
      'operator_free_space_floor_breached');

    // ---- correct dry-run then approved apply works end-to-end ----
    const applied = await cli(['audit-phase-a', ...baseArgs, ...liveArgs('audit-bulk-delete'), '--json']);
    assert.equal(applied.result.dryRun, false);
    assert.ok(applied.result.deletedCount >= 2, 'expired ephemeral_status and ephemeral_operational rows were deleted');
    const survivors = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.audit_events_v2 WHERE id = ANY($1::text[]) ORDER BY id`, values: [[expiredStatusId, expiredOperationalId, freshOperationalId, longRetainedId]] });
    const survivorIds = survivors.rows.map(row => row.id);
    assert.ok(!survivorIds.includes(expiredStatusId), 'expired memory_status/allowed row was deleted');
    assert.ok(!survivorIds.includes(expiredOperationalId), 'expired session_get/allowed row was deleted');
    assert.ok(survivorIds.includes(freshOperationalId), 'fresh row within its window survives');
    assert.ok(survivorIds.includes(longRetainedId), 'long_retained row is never auto-pruned');

    // ---- idempotent re-run: nothing left eligible, second apply deletes 0 ----
    const secondApply = await cli(['audit-phase-a', ...baseArgs, ...liveArgs('audit-bulk-delete'), '--json']);
    assert.equal(secondApply.result.deletedCount, 0, 'a second apply after the eligible set is drained performs zero additional deletes');

    // ---- raw-gc: wrong reader mode refuses the live subcommand ----
    const rawGcSession = `ses_${digest(`${suffix}:rawgc`)}`;
    delete process.env.AMF_CONVERSATION_READER_MODE;
    assert.equal(await refusalCode(cli(['raw-gc', ...baseArgs, ...liveArgs('raw-gc-live'), '--idempotency-tag', `gc-${suffix}`], activeRuntimeDeps())),
      'raw_gc_reader_mode_disabled');

    // ---- raw-gc dry-run then approved apply, gated by reader mode + all mutation guards ----
    await catalog.pool.query({ text: `CREATE TABLE IF NOT EXISTS ${SCHEMA}.conversation_archive_events_v1 (event_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, state TEXT NOT NULL, logical_digest TEXT NOT NULL, payload_digest TEXT NOT NULL, source_occurred_at TEXT NOT NULL, source_time_key TEXT NOT NULL, source_sequence BIGINT NOT NULL, expires_at TEXT NOT NULL, expires_time_key TEXT NOT NULL, event_json JSONB NOT NULL, expired BOOLEAN NOT NULL DEFAULT false)` });
    const { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId } = await import('../src/migration/m4-v2-conversation-projector.mjs');
    const rawGcContent = digest(`${suffix}:rawgc:content`);
    const rawGcEvent = `evt_${digest(`${suffix}:rawgc:event`)}`;
    const rawGcLogical = `lmsg_${digest(`${suffix}:rawgc:logical`)}`;
    await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,context_tags_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES ($1,'hermes',$2,$3,'group','{}'::jsonb,$4,$4,1,$4) ON CONFLICT (session_id) DO NOTHING`, values: [rawGcSession, opaque('owner', rawGcSession), opaque('source', rawGcSession), oldTs] });
    await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.raw_objects_v2(content_id,media_type,byte_length,storage_ref,created_at) VALUES ($1,'application/octet-stream',128,$2,now()) ON CONFLICT (content_id) DO NOTHING`, values: [rawGcContent, `integration/${rawGcContent}.bin`] });
    await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.raw_events_v2(event_id,session_id,logical_message_id,content_id,payload_digest,projection_json,owner_tag,source_tag,created_at) VALUES ($1,$2,$3,$4,$5,'{}'::jsonb,$6,$7,now()) ON CONFLICT (event_id) DO NOTHING`, values: [rawGcEvent, rawGcSession, rawGcLogical, rawGcContent, `digest-${rawGcEvent}`, opaque('owner', rawGcSession), opaque('source', rawGcSession)] });
    await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.logical_messages_v2(logical_message_id,preferred_observation_id,payload_conflict,tombstoned,selection_version,event_ids,updated_at) VALUES ($1,$2,false,false,'integration/v1',$3::jsonb,now()) ON CONFLICT (logical_message_id) DO NOTHING`, values: [rawGcLogical, rawGcEvent, JSON.stringify([rawGcEvent])] });
    const rawGcConversationId = deriveM4V3ConversationIdFromLegacySessionId(rawGcSession);
    const rawGcArchiveEventId = deriveM4V3EventIdFromLegacyEventId(rawGcEvent);
    await catalog.pool.query({ text: `INSERT INTO ${SCHEMA}.conversation_archive_events_v1 (event_id,conversation_id,source_instance_id,state,logical_digest,payload_digest,source_occurred_at,source_time_key,source_sequence,expires_at,expires_time_key,event_json,expired) VALUES ($1,$2,'integration','native','digest','digest','2020-01-01T00:00:00.000Z','2020-01-01T00:00:00.000000000',1,'2099-01-01T00:00:00.000Z','2099-01-01T00:00:00.000000000','{}'::jsonb,false) ON CONFLICT (event_id) DO NOTHING`, values: [rawGcArchiveEventId, rawGcConversationId] });

    process.env.AMF_CONVERSATION_READER_MODE = 'active';
    const rawGcTag = `gc-${suffix}`;
    // RawGcEngine binds dry_run to the operation row for a tag (raw-gc.mjs:
    // raw_gc_idempotency_tag_dry_run_mismatch), so a measurement-only preview
    // uses its own throwaway tag rather than the tag the live run will use.
    const rawGcDryRun = await cli(['raw-gc', ...baseArgs, '--idempotency-tag', `${rawGcTag}-preview`, '--json'], activeRuntimeDeps());
    assert.equal(rawGcDryRun.result.dryRun, true);
    assert.equal(rawGcDryRun.result.runs[0].status, 'completed');
    assert.ok(rawGcDryRun.result.runs[0].counters.logicalMessagesDeleted >= 1, 'dry run reports what it would delete');
    const stillThereAfterDryRun = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE event_id = $1`, values: [rawGcEvent] });
    assert.equal(Number(stillThereAfterDryRun.rows[0].count), 1, 'dry run issued no DELETE on raw_events_v2');

    const rawGcApplied = await cli(['raw-gc', ...baseArgs, ...liveArgs('raw-gc-live'), '--idempotency-tag', rawGcTag, '--json'], activeRuntimeDeps());
    assert.equal(rawGcApplied.result.dryRun, false);
    assert.equal(rawGcApplied.result.runs[0].status, 'completed');
    assert.ok(rawGcApplied.result.runs[0].counters.logicalMessagesDeleted >= 1);
    const goneAfterApply = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE event_id = $1`, values: [rawGcEvent] });
    assert.equal(Number(goneAfterApply.rows[0].count), 0, 'approved apply actually deletes');

    // ---- raw-gc idempotent re-run with the same tag performs zero additional deletes ----
    const rawGcSecondApply = await cli(['raw-gc', ...baseArgs, ...liveArgs('raw-gc-live'), '--idempotency-tag', rawGcTag, '--json'], activeRuntimeDeps());
    assert.equal(rawGcSecondApply.result.runs[0].counters.logicalMessagesDeleted, rawGcApplied.result.runs[0].counters.logicalMessagesDeleted, 'idempotency tag makes counters cumulative, not re-incremented on a drained backlog');
    const stillGone = await catalog.pool.query({ text: `SELECT count(*)::bigint AS count FROM ${SCHEMA}.raw_events_v2 WHERE event_id = $1`, values: [rawGcEvent] });
    assert.equal(Number(stillGone.rows[0].count), 0);

    // ---- Phase C/D happy path: schema -> copy -> cutover -> rollback, driven entirely through the CLI ----
    const phaseCTable = `audit_events_v2_op_${suffix}`;
    await catalog.pool.query(`CREATE TABLE ${SCHEMA}.${phaseCTable} (LIKE ${SCHEMA}.audit_events_v2 INCLUDING ALL)`);
    const survivingRowId = `audit-${suffix}-phase-c-survivor`;
    await catalog.pool.query({
      text: `INSERT INTO ${SCHEMA}.${phaseCTable}(id,ts,actor_tag,action,outcome,request_id,target_id,scope_tag,details_json) VALUES ($1,$2,$3,'memory_propose','allowed',NULL,NULL,NULL,'{}'::jsonb)`,
      values: [survivingRowId, freshTs, opaque('actor', survivingRowId)]
    });
    const cursorFile = `/tmp/amf-audit-phase-c-cursor-${suffix}.json`;

    await cli(['audit-phase-c-schema', ...baseArgs, ...liveArgs('audit-partition-migration'), '--table', phaseCTable]);
    const nextSchemaExists = await catalog.pool.query({ text: `SELECT to_regclass($1) AS relation`, values: [`${SCHEMA}.${phaseCTable}_next`] });
    assert.ok(nextSchemaExists.rows[0].relation, 'Phase C schema step creates <table>_next');

    const copyResult = await cli(['audit-phase-c-copy', ...baseArgs, ...liveArgs('audit-partition-migration'), '--table', phaseCTable, '--cursor-file', cursorFile, '--json']);
    assert.ok(copyResult.result.batches.some(batch => batch.copiedCount >= 1), 'Phase C copy moved the survivor row');

    await cli(['audit-phase-d', ...baseArgs, ...liveArgs('audit-partition-migration'), '--table', phaseCTable, '--legacy-suffix', suffix.slice(0, 8)]);
    const cutoverSurvivor = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.${phaseCTable} WHERE id = $1`, values: [survivingRowId] });
    assert.equal(cutoverSurvivor.rows.length, 1, 'cutover promotes the partitioned table under the original name, survivor still readable');
    const legacyTableName = `${phaseCTable}_legacy_${suffix.slice(0, 8)}`;
    const legacyExists = await catalog.pool.query({ text: `SELECT to_regclass($1) AS relation`, values: [`${SCHEMA}.${legacyTableName}`] });
    assert.ok(legacyExists.rows[0].relation, 'legacy table retained under its renamed name for the rollback window');

    await cli(['audit-rollback', ...baseArgs, ...liveArgs('audit-partition-migration'), '--table', phaseCTable, '--legacy-table', `${SCHEMA}.${legacyTableName}`]);
    const rolledBackRow = await catalog.pool.query({ text: `SELECT id FROM ${SCHEMA}.${phaseCTable} WHERE id = $1`, values: [survivingRowId] });
    assert.equal(rolledBackRow.rows.length, 1, 'rollback restores the pre-cutover table under the original name');
    const nextGoneAgain = await catalog.pool.query({ text: `SELECT to_regclass($1) AS relation`, values: [`${SCHEMA}.${phaseCTable}_next`] });
    assert.ok(nextGoneAgain.rows[0].relation, 'rollback renames legacy back to the original name and the partitioned copy back to _next');

    await catalog.pool.query(`DROP TABLE IF EXISTS ${SCHEMA}.${phaseCTable}_next CASCADE`);
    await catalog.pool.query(`DROP TABLE IF EXISTS ${SCHEMA}.${phaseCTable} CASCADE`);
    fs.rmSync(cursorFile, { force: true });
  } finally {
    delete process.env.AMF_CONVERSATION_READER_MODE;
    await catalog.close().catch(() => {});
  }
});
