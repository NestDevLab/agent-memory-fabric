import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

import { DEFAULT_AUDIT_RETENTION_POLICY } from '../audit-retention.mjs';
import {
  AUDIT_TABLE, countAuditRowsByPair, previewPhaseA, qualifiedAuditTable, runPhaseADeleteBatch
} from '../audit-retention-cleanup.mjs';

export const CHECKPOINTS = Object.freeze({ AUDIT_BULK_DELETE: 'audit-bulk-delete' });

export const ATTESTATION_NOTICE = 'approval and backup flags are operator attestations recorded in the operator log; this CLI cannot verify them';

export function fail(code, details) {
  const error = new Error(code);
  error.code = code;
  if (details) error.details = details;
  throw error;
}

export function isTestDatabaseUrl(databaseUrl) {
  let name;
  try { name = decodeURIComponent(new URL(databaseUrl).pathname.replace(/^\//, '')); } catch { return false; }
  return /(^|[-_])test($|[-_])/i.test(name);
}

export function sslConfigFromMode(mode, caPath) {
  if (!['disable', 'require', 'verify-full'].includes(mode)) fail('operator_ssl_mode_invalid');
  if (mode === 'disable') return false;
  if (mode === 'require') return { rejectUnauthorized: false };
  const config = { rejectUnauthorized: true };
  if (caPath) config.ca = fs.readFileSync(path.resolve(caPath), 'utf8');
  return config;
}

/** Identity of the server the pool is actually connected to, read in a READ ONLY transaction. */
export async function readTargetIdentity(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    const row = (await client.query(`SELECT (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier,
      current_database() AS database, current_setting('data_directory') AS data_directory,
      current_setting('server_version') AS server_version`)).rows[0];
    await client.query('COMMIT');
    if (!/^\d{1,20}$/.test(String(row.system_identifier || '')) || !row.database || !row.data_directory) fail('operator_target_identity_unavailable');
    return { systemIdentifier: row.system_identifier, database: row.database, dataDirectory: row.data_directory, serverVersion: row.server_version };
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection already unusable */ }
    if (error?.code === 'operator_target_identity_unavailable') throw error;
    fail('operator_target_identity_unavailable');
  } finally {
    client.release();
  }
}

export function targetIdentityKey(identity) {
  return `${identity.systemIdentifier}/${identity.database}`;
}

export function requireLiveMutationGuard({ apply, approval, requiredCheckpoint, iKnowThisIsLive, confirmTarget, identity }) {
  if (!apply) return { willMutate: false };
  if (!Object.values(CHECKPOINTS).includes(requiredCheckpoint)) fail('operator_checkpoint_unknown');
  if (approval !== requiredCheckpoint) fail('operator_approval_missing_or_wrong', { required: requiredCheckpoint });
  if (iKnowThisIsLive !== true) fail('operator_live_confirmation_required');
  const expected = targetIdentityKey(identity);
  if (!confirmTarget || confirmTarget !== expected) fail('operator_target_confirmation_mismatch', { connectedTarget: expected });
  return { willMutate: true };
}

/** Checks shape and age only; the backup itself is an operator attestation. */
export function requireBackupAttestation({ backupId, backupVerifiedAt, maxAgeHours = 24, now = () => new Date() }) {
  if (!backupId || typeof backupId !== 'string') fail('operator_backup_id_required');
  const verifiedAtMs = Date.parse(backupVerifiedAt || '');
  if (!Number.isFinite(verifiedAtMs)) fail('operator_backup_verified_at_invalid');
  const ageMs = now().getTime() - verifiedAtMs;
  if (ageMs < 0) fail('operator_backup_verified_at_in_future');
  if (ageMs > maxAgeHours * 3_600_000) fail('operator_backup_attestation_stale', { ageHours: ageMs / 3_600_000, maxAgeHours });
  return { backupId, verifiedAt: new Date(verifiedAtMs).toISOString(), ageHours: ageMs / 3_600_000 };
}

const HOST_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/;
const DATA_DIRECTORY_PATTERN = /^\/[A-Za-z0-9._/-]{1,4095}$/;

export function validateProbeHost(host) {
  if (typeof host !== 'string' || !HOST_PATTERN.test(host)) fail('operator_probe_host_invalid');
  return host;
}

export function validateProbeCtid(ctid) {
  if (typeof ctid !== 'string' || !/^[1-9]\d{0,8}$/.test(ctid)) fail('operator_probe_ctid_invalid');
  return ctid;
}

function validateDataDirectory(dataDirectory) {
  if (typeof dataDirectory !== 'string' || !DATA_DIRECTORY_PATTERN.test(dataDirectory) || dataDirectory.split('/').includes('..')) {
    fail('operator_probe_data_directory_invalid');
  }
  return dataDirectory;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// ssh hands the remote command to a shell, so every remote argument is quoted as one word.
function sshArgv(host, remoteArgv) {
  return ['ssh', '-o', 'BatchMode=yes', host, remoteArgv.map(shellQuote).join(' ')];
}

export function dbHostProbeCommands({ host, ctid, dataDirectory }) {
  validateProbeHost(host);
  validateProbeCtid(ctid);
  validateDataDirectory(dataDirectory);
  return {
    freeSpace: sshArgv(host, ['pct', 'exec', ctid, '--', 'df', '-B1', '--output=avail,size', dataDirectory]),
    identity: sshArgv(host, ['pct', 'exec', ctid, '--', 'su', 'postgres', '-c', "psql -XAt -c 'select system_identifier from pg_control_system()'"])
  };
}

export function defaultRunCommand(argv, { timeoutMs = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(argv[0], argv.slice(1), { timeout: timeoutMs, maxBuffer: 64 * 1024, shell: false }, (error, stdout) => {
      if (error) reject(error);
      else resolve({ stdout: String(stdout) });
    });
  });
}

function parseDfOutput(stdout) {
  const lines = String(stdout).trim().split('\n').map(line => line.trim()).filter(Boolean);
  const match = lines.at(-1)?.match(/^(\d+)\s+(\d+)$/);
  if (!match) fail('operator_db_host_probe_failed', { reason: 'df_output_unparsed' });
  const freeBytes = Number(match[1]);
  const sizeBytes = Number(match[2]);
  if (!Number.isSafeInteger(freeBytes) || !Number.isSafeInteger(sizeBytes)) fail('operator_db_host_probe_failed', { reason: 'df_output_unparsed' });
  return { freeBytes, sizeBytes };
}

/**
 * Free space measured on the database server's data filesystem through Proxmox `pct exec`,
 * with the probed cluster's system_identifier checked against the connected database.
 */
export function createPctDbHostProbe({ host, ctid, identity, runCommand = defaultRunCommand }) {
  const commands = dbHostProbeCommands({ host, ctid, dataDirectory: identity.dataDirectory });
  return async function probe() {
    let identityOutput;
    let dfOutput;
    try {
      identityOutput = (await runCommand(commands.identity)).stdout;
      dfOutput = (await runCommand(commands.freeSpace)).stdout;
    } catch {
      fail('operator_db_host_probe_failed', { reason: 'command_failed' });
    }
    const probedIdentifier = String(identityOutput).trim();
    if (probedIdentifier !== identity.systemIdentifier) {
      fail('operator_db_host_identity_mismatch', { connected: identity.systemIdentifier, probed: probedIdentifier.slice(0, 32) });
    }
    return { method: 'pct', host, ctid, dataDirectory: identity.dataDirectory, systemIdentifier: probedIdentifier, ...parseDfOutput(dfOutput) };
  };
}

export function requireFreeSpace({ probe, previous, floorBytes, maxDropBytes }) {
  if (probe.freeBytes < floorBytes) fail('operator_free_space_floor_breached', { freeBytes: probe.freeBytes, floorBytes });
  if (previous && previous.freeBytes - probe.freeBytes > maxDropBytes) {
    fail('operator_free_space_dropped', { previousFreeBytes: previous.freeBytes, freeBytes: probe.freeBytes, maxDropBytes });
  }
  return probe;
}

async function readOnlyScalar(pool, text, values) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    const result = await client.query({ text, values });
    await client.query('COMMIT');
    return result.rows[0];
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection already unusable */ }
    throw error;
  } finally {
    client.release();
  }
}

/** Read-only: identity, audit table size, counts per pair and class, Phase A eligibility, free space. */
export async function runInventory({ pool, table = AUDIT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(), probe = null, statementTimeoutMs }) {
  const qualified = qualifiedAuditTable(table);
  const size = await readOnlyScalar(pool, 'SELECT pg_total_relation_size($1::regclass)::bigint AS bytes', [qualified]);
  const rows = await countAuditRowsByPair({ pool, table, statementTimeoutMs });
  const eligible = await previewPhaseA({ pool, table, policy, asOf, statementTimeoutMs });
  return {
    schema: 'amf.audit-retention-inventory/v1',
    asOf: eligible.asOf,
    table: { name: AUDIT_TABLE, totalBytes: Number(size.bytes), rowsByRetentionClass: rows.byClass, unknownPairs: rows.unknownPairs, pairs: rows.pairs },
    phaseA: { eligibleByClass: eligible.eligibleByClass, eligibleTotal: eligible.eligibleTotal },
    freeSpace: probe ? await probe() : 'unknown'
  };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function stopReasonFor(error) {
  const code = typeof error?.code === 'string' ? error.code : '';
  if (code.startsWith('operator_free_space_')) return code.replace('operator_', '');
  if (code === 'operator_log_write_failed') return 'log_write_failed';
  return 'error';
}

/**
 * Bounded Phase A apply. Free space is probed before the first batch and after every committed
 * batch (or starts from a checked `initialProbe`), so the floor and drop checks cover the last commit too. `onBatch` must durably record
 * each committed batch; if it throws, the run stops. Plain VACUUM (never FULL) only with
 * `vacuumEvery`.
 */
export async function runAuditPhaseAApply({
  pool, table = AUDIT_TABLE, policy = DEFAULT_AUDIT_RETENTION_POLICY, asOf = new Date().toISOString(),
  batchSize = 5000, pauseMs = 1000, maxBatches = 100, floorBytes, maxDropBytes, vacuumEvery = 0,
  lockTimeoutMs, statementTimeoutMs, probe, initialProbe = null, onBatch = async () => {}, sleepFn = sleep
}) {
  if (!Number.isSafeInteger(vacuumEvery) || vacuumEvery < 0 || vacuumEvery > maxBatches) fail('operator_vacuum_every_invalid');
  const qualified = qualifiedAuditTable(table);
  const batches = [];
  const probes = [];
  let stopReason = 'max_batches';
  let error = null;
  let totalDeleted = 0;
  const measure = async () => {
    const measured = await probe();
    const previous = probes.at(-1) ?? null;
    probes.push(measured);
    return requireFreeSpace({ probe: measured, previous, floorBytes, maxDropBytes });
  };
  try {
    if (initialProbe) probes.push(requireFreeSpace({ probe: initialProbe, previous: null, floorBytes, maxDropBytes }));
    else await measure();
    for (let index = 1; index <= maxBatches; index += 1) {
      const result = await runPhaseADeleteBatch({ pool, table, policy, asOf, batchSize, lockTimeoutMs, statementTimeoutMs });
      totalDeleted += result.deletedCount;
      const probesBefore = probes.length;
      let probeError = null;
      try {
        if (vacuumEvery && result.deletedCount > 0 && index % vacuumEvery === 0) await pool.query(`VACUUM (ANALYZE) ${qualified}`);
        await measure();
      } catch (caught) {
        probeError = caught;
      }
      const probeAfter = probes.length > probesBefore ? probes.at(-1) : { error: typeof probeError?.code === 'string' ? probeError.code : 'probe_failed' };
      const record = { batch: index, deletedCount: result.deletedCount, deletedByClass: result.deletedByClass, probe: probeAfter };
      batches.push(record);
      try { await onBatch(record); } catch { fail('operator_log_write_failed', { batch: index }); }
      if (probeError) throw probeError;
      if (result.deletedCount === 0) { stopReason = 'drained'; break; }
      if (index < maxBatches) await sleepFn(pauseMs);
    }
  } catch (caught) {
    error = caught;
    stopReason = stopReasonFor(caught);
  }
  return { asOf: new Date(asOf).toISOString(), totalDeleted, batches, probes, stopReason, error };
}

/** Append-only JSONL, fsynced per record; opened before any mutation so an unwritable log refuses early. */
export function openOperatorLog(logPath) {
  if (typeof logPath !== 'string' || !logPath) fail('operator_log_required');
  let fd;
  try { fd = fs.openSync(path.resolve(logPath), 'a', 0o600); } catch { fail('operator_log_unwritable'); }
  return {
    append(entry) {
      fs.writeSync(fd, `${JSON.stringify(entry)}\n`);
      fs.fsyncSync(fd);
    },
    close() { try { fs.closeSync(fd); } catch { /* already closed */ } }
  };
}
