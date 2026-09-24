#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { classifyAuditEvent, DEFAULT_AUDIT_RETENTION_POLICY } from '../src/audit-retention.mjs';
import { createConversationSessionRuntimeFromEnv } from '../src/conversation-session-runtime.mjs';
import { createFabricStoreFromEnv } from '../src/fabric-store.mjs';
import {
  CHECKPOINTS, connectionTarget, countAuditPhaseAWouldDelete, createRawGcEngine, fail, freeBytesOf,
  requireBackupAttestation, requireFreeSpaceFloor, requireLiveMutationGuard, requireReaderModeForLiveGc,
  runAuditPhaseABatch, runAuditPhaseCCopy, runAuditPhaseCSchema, runAuditPhaseDCutover, runAuditRollback,
  runInventory, runRawGc, sslConfigFromMode
} from '../src/operator/audit-retention-gc-operator.mjs';

const DEFAULT_TABLE = 'audit_events_v2';
const DEFAULT_RAW_TABLE = 'raw_events_v2';
const DEFAULT_FREE_SPACE_FLOOR_BYTES = 2_000_000_000; // matches design §4.1's stated no-margin-below-this-line figure
const DEFAULT_MAX_BACKUP_AGE_HOURS = 24;

const COMMON_FLAGS = new Set(['--apply', '--json']);
const COMMON_SINGLES = new Set([
  '--database-url', '--ssl-mode', '--ssl-ca-path', '--table', '--filesystem-path',
  '--approval', '--confirm-target', '--backup-id', '--backup-verified-at',
  '--max-backup-age-hours', '--free-space-floor-bytes'
]);

const SPECS = {
  inventory: {
    flags: new Set(['--json']),
    singles: new Set(['--database-url', '--ssl-mode', '--ssl-ca-path', '--table', '--raw-table', '--filesystem-path']),
    mutating: false
  },
  'audit-phase-a': {
    flags: new Set([...COMMON_FLAGS]),
    singles: new Set([...COMMON_SINGLES, '--batch-size']),
    mutating: true,
    checkpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    requiresBackup: true
  },
  'audit-phase-c-schema': {
    flags: new Set([...COMMON_FLAGS, '--i-know-this-is-live']),
    singles: new Set([...COMMON_SINGLES]),
    mutating: true,
    checkpoint: CHECKPOINTS.AUDIT_PARTITION_MIGRATION,
    requiresBackup: true
  },
  'audit-phase-c-copy': {
    flags: new Set([...COMMON_FLAGS, '--i-know-this-is-live']),
    singles: new Set([...COMMON_SINGLES, '--batch-size', '--max-batches', '--cursor-file']),
    mutating: true,
    checkpoint: CHECKPOINTS.AUDIT_PARTITION_MIGRATION,
    requiresBackup: true,
    estimateFromTable: true
  },
  'audit-phase-d': {
    flags: new Set([...COMMON_FLAGS, '--i-know-this-is-live']),
    singles: new Set([...COMMON_SINGLES, '--legacy-suffix']),
    mutating: true,
    checkpoint: CHECKPOINTS.AUDIT_PARTITION_MIGRATION,
    requiresBackup: true
  },
  'audit-rollback': {
    flags: new Set([...COMMON_FLAGS, '--i-know-this-is-live']),
    singles: new Set([...COMMON_SINGLES, '--legacy-table']),
    mutating: true,
    checkpoint: CHECKPOINTS.AUDIT_PARTITION_MIGRATION,
    requiresBackup: false
  },
  'raw-gc': {
    flags: new Set([...COMMON_FLAGS, '--i-know-this-is-live']),
    singles: new Set([...COMMON_SINGLES, '--idempotency-tag', '--max-runs', '--session-batch-size',
      '--min-verified-sessions-to-proceed', '--max-bytes-reclaimed-per-run', '--fabric-root']),
    mutating: true,
    checkpoint: CHECKPOINTS.RAW_GC_LIVE,
    requiresBackup: true
  }
};
// --i-know-this-is-live is boolean everywhere it appears; audit-phase-a keeps it inside COMMON_FLAGS already.
SPECS['audit-phase-a'].flags.add('--i-know-this-is-live');

function parseArguments(argv) {
  const command = argv[2];
  const spec = SPECS[command];
  if (!spec) fail('operator_cli_command_invalid', { command });
  const values = {};
  for (let index = 3; index < argv.length; index += 1) {
    const name = argv[index];
    if (spec.flags.has(name)) { values[name] = true; continue; }
    if (spec.singles.has(name)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) fail('operator_cli_argument_value_required', { flag: name });
      if (values[name] !== undefined) fail('operator_cli_argument_repeated', { flag: name });
      values[name] = value;
      index += 1;
      continue;
    }
    fail('operator_cli_argument_unknown', { flag: name });
  }
  return { command, spec, values };
}

function integerFlag(values, name, fallback, { min, max }) {
  const raw = values[name];
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) fail('operator_cli_argument_invalid', { flag: name });
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('operator_cli_argument_invalid', { flag: name });
  return value;
}

async function connect(values, { Pool }) {
  const databaseUrl = values['--database-url'] || process.env.AMF_OPERATOR_DATABASE_URL;
  if (!databaseUrl) fail('operator_database_url_required');
  const sslMode = values['--ssl-mode'] || 'verify-full';
  const pool = new Pool({ connectionString: databaseUrl, ssl: sslConfigFromMode(sslMode, values['--ssl-ca-path']), max: 4 });
  return { pool, databaseUrl, resolvedTarget: connectionTarget(databaseUrl) };
}

function guardFor(spec, values, resolvedTarget) {
  const apply = Boolean(values['--apply']);
  const guard = requireLiveMutationGuard({
    apply,
    approval: values['--approval'],
    requiredCheckpoint: spec.checkpoint,
    iKnowThisIsLive: Boolean(values['--i-know-this-is-live']),
    confirmTarget: values['--confirm-target'],
    resolvedTarget
  });
  if (guard.willMutate && spec.requiresBackup) {
    requireBackupAttestation({
      backupId: values['--backup-id'],
      backupVerifiedAt: values['--backup-verified-at'],
      maxAgeHours: integerFlag(values, '--max-backup-age-hours', DEFAULT_MAX_BACKUP_AGE_HOURS, { min: 1, max: 168 })
    });
  }
  return { apply, guard };
}

async function freeSpaceCheck(values, { estimateBytes = 0 } = {}) {
  const filesystemPath = values['--filesystem-path'] || process.cwd();
  const floorBytes = integerFlag(values, '--free-space-floor-bytes', DEFAULT_FREE_SPACE_FLOOR_BYTES, { min: 0, max: Number.MAX_SAFE_INTEGER });
  const freeBytes = freeBytesOf(filesystemPath);
  return requireFreeSpaceFloor({ freeBytes, floorBytes, estimateBytes });
}

async function run(command, spec, values, deps) {
  const { Pool } = deps;
  const { pool, resolvedTarget } = await connect(values, { Pool });
  let runtime = null;
  try {
    const table = values['--table'] || DEFAULT_TABLE;
    if (command === 'inventory') {
      return {
        command, target: resolvedTarget,
        ...await runInventory({
          pool, table, rawTable: values['--raw-table'] || DEFAULT_RAW_TABLE, policy: DEFAULT_AUDIT_RETENTION_POLICY,
          classify: classifyAuditEvent, filesystemPath: values['--filesystem-path'] || process.cwd()
        })
      };
    }

    const { apply } = guardFor(spec, values, resolvedTarget);

    if (command === 'audit-phase-a') {
      if (apply) await freeSpaceCheck(values);
      const batchSize = integerFlag(values, '--batch-size', 20_000, { min: 1, max: 100_000 });
      return { command, target: resolvedTarget, ...await runAuditPhaseABatch({ pool, table, policy: DEFAULT_AUDIT_RETENTION_POLICY, batchSize, apply }) };
    }

    if (command === 'audit-phase-c-schema') {
      if (!apply) return { command, target: resolvedTarget, dryRun: true, note: 'no schema created; rerun with --apply and the audit-partition-migration checkpoint' };
      await freeSpaceCheck(values);
      return { command, target: resolvedTarget, dryRun: false, ...await runAuditPhaseCSchema({ pool, table }) };
    }

    if (command === 'audit-phase-c-copy') {
      const cursorFile = values['--cursor-file'];
      if (!cursorFile) fail('operator_cli_argument_value_required', { flag: '--cursor-file' });
      if (!apply) {
        const wouldDelete = await countAuditPhaseAWouldDelete(pool, { table, policy: DEFAULT_AUDIT_RETENTION_POLICY });
        return { command, target: resolvedTarget, dryRun: true, note: 'copy performs no writes without --apply', remainingPhaseACandidates: wouldDelete };
      }
      const estimateBytes = await pool.query({ text: 'SELECT pg_total_relation_size($1::regclass)::bigint AS bytes', values: [`agent_memory_fabric.${table}`] }).then(r => Number(r.rows[0].bytes));
      await freeSpaceCheck(values, { estimateBytes });
      const batchSize = integerFlag(values, '--batch-size', 5000, { min: 1, max: 50_000 });
      const maxBatches = integerFlag(values, '--max-batches', 20, { min: 1, max: 10_000 });
      return { command, target: resolvedTarget, dryRun: false, ...await runAuditPhaseCCopy({ pool, table, batchSize, maxBatches, cursorFile }) };
    }

    if (command === 'audit-phase-d') {
      if (!apply) return { command, target: resolvedTarget, dryRun: true, note: 'no cutover performed; rerun with --apply once Phase C copy is drained' };
      await freeSpaceCheck(values);
      return { command, target: resolvedTarget, dryRun: false, ...await runAuditPhaseDCutover({ pool, table, legacySuffix: values['--legacy-suffix'] }) };
    }

    if (command === 'audit-rollback') {
      const legacyTable = values['--legacy-table'];
      if (!legacyTable) fail('operator_cli_argument_value_required', { flag: '--legacy-table' });
      if (!apply) return { command, target: resolvedTarget, dryRun: true, note: 'no rollback performed' };
      return { command, target: resolvedTarget, dryRun: false, ...await runAuditRollback({ pool, table, legacyTable }) };
    }

    if (command === 'raw-gc') {
      const idempotencyTag = values['--idempotency-tag'];
      if (!idempotencyTag) fail('operator_cli_argument_value_required', { flag: '--idempotency-tag' });
      const maxRuns = integerFlag(values, '--max-runs', 1, { min: 1, max: 10_000 });
      const fabricRoot = values['--fabric-root'] || process.cwd();

      if (apply) {
        requireReaderModeForLiveGc(process.env);
        await freeSpaceCheck(values);
      }

      try {
        const fabricStore = deps.createFabricStoreFromEnv({ rootPath: fabricRoot, env: process.env });
        const legacyReader = fabricStore.createSessionReader?.() || null;
        runtime = await deps.createConversationSessionRuntimeFromEnv({ env: process.env, rootPath: fabricRoot, legacyReader });
      } catch {
        runtime = null; // unconfigured fabric/runtime => every session fails archive proof; safe default, never a bypass
      }

      const engine = createRawGcEngine({
        pool, runtime,
        retentionPolicy: {},
        sessionBatchSize: integerFlag(values, '--session-batch-size', 50, { min: 1, max: 1000 }),
        minVerifiedSessionsToProceed: integerFlag(values, '--min-verified-sessions-to-proceed', 0, { min: 0, max: 100_000 }),
        maxBytesReclaimedPerRun: integerFlag(values, '--max-bytes-reclaimed-per-run', Number.MAX_SAFE_INTEGER, { min: 0, max: Number.MAX_SAFE_INTEGER }),
        minFreeBytesFloor: integerFlag(values, '--free-space-floor-bytes', DEFAULT_FREE_SPACE_FLOOR_BYTES, { min: 0, max: Number.MAX_SAFE_INTEGER }),
        freeBytesProbe: async () => freeBytesOf(values['--filesystem-path'] || process.cwd())
      });
      return { command, target: resolvedTarget, ...await runRawGc({ engine, idempotencyTag, dryRun: !apply, maxRuns }) };
    }

    fail('operator_cli_command_invalid', { command });
  } finally {
    try { if (runtime) await runtime.close(); } catch { /* best-effort on a process about to exit */ }
    try { await pool.end(); } catch { /* best-effort on a process about to exit */ }
  }
}

function summarize(command, result) {
  const lines = [`command: ${command}`, `target: ${result.target ?? '(read-only)'}`];
  if (result.dryRun !== undefined) lines.push(`mode: ${result.dryRun ? 'dry-run (no writes)' : 'apply'}`);
  for (const [key, value] of Object.entries(result)) {
    if (['command', 'target', 'dryRun'].includes(key)) continue;
    lines.push(`${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`);
  }
  return lines.join('\n');
}

export async function runCli(argv = process.argv, dependencies = {}) {
  const { command, spec, values } = parseArguments(argv);
  const deps = {
    Pool: dependencies.Pool ?? pg.Pool,
    createFabricStoreFromEnv: dependencies.createFabricStoreFromEnv ?? createFabricStoreFromEnv,
    createConversationSessionRuntimeFromEnv: dependencies.createConversationSessionRuntimeFromEnv ?? createConversationSessionRuntimeFromEnv
  };
  const result = await run(command, spec, values, deps);
  return { result, json: Boolean(values['--json']) };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runCli().then(({ result, json }) => {
    process.stdout.write(json ? `${JSON.stringify(result)}\n` : `${summarize(result.command || 'inventory', result)}\n`);
  }).catch(error => {
    const code = typeof error?.code === 'string' && /^[a-z][a-z0-9_]{2,63}$/.test(error.code) ? error.code : 'operator_cli_failed';
    process.stderr.write(`${JSON.stringify({ ok: false, error: code, details: error?.details })}\n`);
    process.exitCode = 78;
  });
}
