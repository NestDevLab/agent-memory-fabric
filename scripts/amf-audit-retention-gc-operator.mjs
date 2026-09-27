#!/usr/bin/env node
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { DEFAULT_AUDIT_RETENTION_POLICY } from '../src/audit-retention.mjs';
import { AUDIT_TABLE, previewPhaseA } from '../src/audit-retention-cleanup.mjs';
import {
  ATTESTATION_NOTICE, CHECKPOINTS, createPctDbHostProbe, defaultRunCommand, fail, openOperatorLog,
  readTargetIdentity, requireBackupAttestation, requireFreeSpace, requireLiveMutationGuard, runAuditPhaseAApply,
  runInventory, sslConfigFromMode
} from '../src/operator/audit-retention-gc-operator.mjs';

const DEFAULT_FREE_SPACE_FLOOR_BYTES = 2_000_000_000;
const DEFAULT_MAX_FREE_SPACE_DROP_BYTES = 256 * 1024 * 1024;
const DEFAULT_MAX_BACKUP_AGE_HOURS = 24;
const DEFAULT_READ_ONLY_STATEMENT_TIMEOUT_MS = 300_000;
const DEFAULT_APPLY_STATEMENT_TIMEOUT_MS = 120_000;

const CONNECTION_SINGLES = ['--database-url', '--ssl-mode', '--ssl-ca-path', '--table', '--db-host-probe', '--proxmox-host', '--ctid'];

const SPECS = {
  inventory: {
    flags: new Set(['--json']),
    singles: new Set([...CONNECTION_SINGLES, '--statement-timeout-ms'])
  },
  'audit-phase-a': {
    flags: new Set(['--json', '--apply', '--i-know-this-is-live']),
    singles: new Set([...CONNECTION_SINGLES, '--approval', '--confirm-target', '--backup-id', '--backup-verified-at',
      '--max-backup-age-hours', '--operator-log', '--batch-size', '--pause-ms', '--max-batches', '--vacuum-every',
      '--free-space-floor-bytes', '--max-free-space-drop-bytes', '--lock-timeout-ms', '--statement-timeout-ms'])
  }
};

function parseArguments(argv) {
  const command = argv[2];
  const spec = SPECS[command];
  if (!spec) fail('operator_cli_command_invalid', { command: String(command).slice(0, 64) });
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
    fail('operator_cli_argument_unknown', { flag: String(name).slice(0, 64) });
  }
  if (values['--table'] !== undefined && values['--table'] !== AUDIT_TABLE) fail('audit_retention_table_not_allowed', { allowed: AUDIT_TABLE });
  return { command, values };
}

function integerFlag(values, name, fallback, { min, max }) {
  const raw = values[name];
  if (raw === undefined) return fallback;
  if (!/^\d+$/.test(raw)) fail('operator_cli_argument_invalid', { flag: name });
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('operator_cli_argument_invalid', { flag: name });
  return value;
}

function probeFor(values, identity, runCommand) {
  const method = values['--db-host-probe'];
  if (method === undefined) {
    if (values['--proxmox-host'] !== undefined || values['--ctid'] !== undefined) fail('operator_db_host_probe_method_required');
    return null;
  }
  if (method !== 'pct') fail('operator_db_host_probe_method_invalid');
  if (!values['--proxmox-host'] || !values['--ctid']) fail('operator_db_host_probe_arguments_required');
  return createPctDbHostProbe({ host: values['--proxmox-host'], ctid: values['--ctid'], identity, runCommand });
}

function publicIdentity(identity) {
  return {
    systemIdentifier: identity.systemIdentifier, database: identity.database, dataDirectory: identity.dataDirectory,
    serverVersion: identity.serverVersion, confirmTarget: `${identity.systemIdentifier}/${identity.database}`
  };
}

function errorCode(error) {
  return typeof error?.code === 'string' && /^[a-z][a-z0-9_]{2,63}$/.test(error.code) ? error.code : 'operator_cli_failed';
}

function readOnlyTimeout(values) {
  return integerFlag(values, '--statement-timeout-ms', DEFAULT_READ_ONLY_STATEMENT_TIMEOUT_MS, { min: 1000, max: 3_600_000 });
}

function applyOptions(values) {
  const options = {
    batchSize: integerFlag(values, '--batch-size', 5000, { min: 1, max: 100_000 }),
    pauseMs: integerFlag(values, '--pause-ms', 1000, { min: 0, max: 600_000 }),
    maxBatches: integerFlag(values, '--max-batches', 100, { min: 1, max: 100_000 }),
    floorBytes: integerFlag(values, '--free-space-floor-bytes', DEFAULT_FREE_SPACE_FLOOR_BYTES, { min: 0, max: Number.MAX_SAFE_INTEGER }),
    maxDropBytes: integerFlag(values, '--max-free-space-drop-bytes', DEFAULT_MAX_FREE_SPACE_DROP_BYTES, { min: 0, max: Number.MAX_SAFE_INTEGER }),
    lockTimeoutMs: integerFlag(values, '--lock-timeout-ms', 5000, { min: 100, max: 600_000 }),
    statementTimeoutMs: integerFlag(values, '--statement-timeout-ms', DEFAULT_APPLY_STATEMENT_TIMEOUT_MS, { min: 1000, max: 3_600_000 }),
    vacuumEvery: integerFlag(values, '--vacuum-every', 0, { min: 0, max: 100_000 })
  };
  if (options.vacuumEvery > options.maxBatches) fail('operator_vacuum_every_invalid');
  return options;
}

async function runPhaseA({ pool, values, identity, makeProbe, deps }) {
  const { now } = deps;
  const policy = DEFAULT_AUDIT_RETENTION_POLICY;
  if (!values['--apply']) {
    const probe = makeProbe();
    const preview = await previewPhaseA({ pool, policy, statementTimeoutMs: readOnlyTimeout(values) });
    return { dryRun: true, ...preview, freeSpace: probe ? await probe() : 'unknown' };
  }

  const log = deps.openOperatorLog(values['--operator-log']);
  const runId = crypto.randomUUID();
  const write = record => log.append({ schema: 'amf.audit-retention-operator-log/v2', runId, command: 'audit-phase-a', ts: now().toISOString(), ...record });
  const header = {
    target: publicIdentity(identity), checkpoint: values['--approval'] ?? null,
    backup: { id: values['--backup-id'] ?? null, verifiedAt: values['--backup-verified-at'] ?? null },
    attestation: ATTESTATION_NOTICE
  };
  let started = false;
  let result = null;
  let failure = null;
  try {
    requireLiveMutationGuard({
      apply: true, approval: values['--approval'], requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
      iKnowThisIsLive: Boolean(values['--i-know-this-is-live']), confirmTarget: values['--confirm-target'], identity
    });
    requireBackupAttestation({
      backupId: values['--backup-id'], backupVerifiedAt: values['--backup-verified-at'], now,
      maxAgeHours: integerFlag(values, '--max-backup-age-hours', DEFAULT_MAX_BACKUP_AGE_HOURS, { min: 1, max: 168 })
    });
    const probe = makeProbe();
    if (!probe) fail('operator_db_host_probe_required');
    const options = applyOptions(values);
    const initialProbe = requireFreeSpace({ probe: await probe(), previous: null, floorBytes: options.floorBytes, maxDropBytes: options.maxDropBytes });
    const asOf = now().toISOString();
    try { write({ type: 'start', ...header, asOf, options, initialProbe }); } catch { fail('operator_log_write_failed'); }
    started = true;
    result = await runAuditPhaseAApply({
      pool, policy, asOf, probe, initialProbe, ...options, sleepFn: deps.sleep,
      onBatch: record => write({ type: 'batch', ...record })
    });
    failure = result.error;
  } catch (error) {
    failure = error;
  }

  try {
    if (!started) {
      try { write({ type: 'refused', ...header, error: errorCode(failure) }); } catch { /* refusing anyway */ }
      throw failure;
    }
    try {
      write({
        type: 'end', outcome: failure ? 'stopped' : 'completed', stopReason: result?.stopReason ?? 'error',
        totalDeleted: result?.totalDeleted ?? 0, batches: result?.batches.length ?? 0, ...(failure ? { error: errorCode(failure) } : {})
      });
    } catch {
      failure ??= Object.assign(new Error('operator_log_write_failed'), { code: 'operator_log_write_failed' });
    }
    if (failure) {
      failure.details = { ...failure.details, runId, stopReason: result?.stopReason ?? 'error', totalDeleted: result?.totalDeleted ?? 0, batches: result?.batches.length ?? 0 };
      throw failure;
    }
    const { error, ...summary } = result;
    return { dryRun: false, runId, attestation: ATTESTATION_NOTICE, ...summary };
  } finally {
    log.close();
  }
}

async function run(command, values, deps) {
  const databaseUrl = values['--database-url'] || process.env.AMF_OPERATOR_DATABASE_URL;
  if (!databaseUrl) fail('operator_database_url_required');
  const pool = new deps.Pool({ connectionString: databaseUrl, ssl: sslConfigFromMode(values['--ssl-mode'] || 'verify-full', values['--ssl-ca-path']), max: 2 });
  try {
    const identity = await readTargetIdentity(pool);
    const target = publicIdentity(identity);
    try {
      const makeProbe = () => probeFor(values, identity, deps.runCommand);
      if (command === 'inventory') return { command, target, ...await runInventory({ pool, probe: makeProbe(), statementTimeoutMs: readOnlyTimeout(values) }) };
      return { command, target, ...await runPhaseA({ pool, values, identity, makeProbe, deps }) };
    } catch (error) {
      if (error && typeof error === 'object') error.target = target;
      throw error;
    }
  } finally {
    try { await pool.end(); } catch { /* process is about to exit */ }
  }
}

function summarize(result) {
  const lines = [`command: ${result.command}`, `target: ${JSON.stringify(result.target)}`];
  if (result.dryRun !== undefined) lines.push(`mode: ${result.dryRun ? 'preview (read-only)' : 'apply'}`);
  for (const [key, value] of Object.entries(result)) {
    if (['command', 'target', 'dryRun'].includes(key)) continue;
    lines.push(`${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`);
  }
  return lines.join('\n');
}

export async function runCli(argv = process.argv, dependencies = {}) {
  const { command, values } = parseArguments(argv);
  const deps = {
    Pool: dependencies.Pool ?? pg.Pool,
    runCommand: dependencies.runCommand ?? defaultRunCommand,
    now: dependencies.now ?? (() => new Date()),
    sleep: dependencies.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms))),
    openOperatorLog: dependencies.openOperatorLog ?? openOperatorLog
  };
  const result = await run(command, values, deps);
  return { result, json: Boolean(values['--json']) };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runCli().then(({ result, json }) => {
    process.stdout.write(json ? `${JSON.stringify(result)}\n` : `${summarize(result)}\n`);
  }).catch(error => {
    process.stderr.write(`${JSON.stringify({ ok: false, error: errorCode(error), details: error?.details, target: error?.target })}\n`);
    process.exitCode = 78;
  });
}
