import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  CHECKPOINTS, createPctDbHostProbe, dbHostProbeCommands, isTestDatabaseUrl, openOperatorLog,
  requireBackupAttestation, requireFreeSpace, requireLiveMutationGuard, sslConfigFromMode,
  validateProbeCtid, validateProbeHost
} from '../src/operator/audit-retention-gc-operator.mjs';
import { runCli } from './amf-audit-retention-gc-operator.mjs';

const IDENTITY = { systemIdentifier: '7412345678901234567', database: 'agent_memory_fabric', dataDirectory: '/var/lib/postgresql/16/main' };
const guardInput = overrides => ({
  apply: true, approval: CHECKPOINTS.AUDIT_BULK_DELETE, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
  iKnowThisIsLive: true, confirmTarget: '7412345678901234567/agent_memory_fabric', identity: IDENTITY, ...overrides
});

function fakeRunCommand({ systemIdentifier = IDENTITY.systemIdentifier, freeBytes = 9_000_000_000, fail = false } = {}) {
  const calls = [];
  const runCommand = async argv => {
    calls.push(argv);
    if (fail) throw new Error('ssh: connect to host refused');
    if (argv[4].includes("'psql")) return { stdout: `${systemIdentifier}\n` };
    return { stdout: `      Avail   1B-blocks\n${freeBytes} 21474836480\n` };
  };
  return { runCommand, calls };
}

test('isTestDatabaseUrl and sslConfigFromMode', () => {
  assert.equal(isTestDatabaseUrl('postgres://u@h/amf_audit_gc_test'), true);
  assert.equal(isTestDatabaseUrl('postgres://u@h/agent_memory_fabric'), false);
  assert.equal(sslConfigFromMode('disable'), false);
  assert.deepEqual(sslConfigFromMode('verify-full'), { rejectUnauthorized: true });
  assert.throws(() => sslConfigFromMode('bogus'), { code: 'operator_ssl_mode_invalid' });
});

test('mutation guard binds --confirm-target to the connected system_identifier and database', () => {
  assert.deepEqual(requireLiveMutationGuard({ apply: false }), { willMutate: false });
  assert.deepEqual(requireLiveMutationGuard(guardInput()), { willMutate: true });
  assert.throws(() => requireLiveMutationGuard(guardInput({ approval: undefined })), { code: 'operator_approval_missing_or_wrong' });
  assert.throws(() => requireLiveMutationGuard(guardInput({ approval: 'raw-gc-live' })), { code: 'operator_approval_missing_or_wrong' });
  assert.throws(() => requireLiveMutationGuard(guardInput({ iKnowThisIsLive: false })), { code: 'operator_live_confirmation_required' });
  assert.throws(() => requireLiveMutationGuard(guardInput({ confirmTarget: 'db-host:5432/agent_memory_fabric' })), { code: 'operator_target_confirmation_mismatch' });
  assert.throws(() => requireLiveMutationGuard(guardInput({ confirmTarget: '7412345678901234567/other_db' })), { code: 'operator_target_confirmation_mismatch' });
});

test('backup attestation checks shape and age only', () => {
  const now = () => new Date('2026-09-24T12:00:00Z');
  assert.throws(() => requireBackupAttestation({ backupId: null, backupVerifiedAt: '2026-09-24T00:00:00Z', now }), { code: 'operator_backup_id_required' });
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: 'nope', now }), { code: 'operator_backup_verified_at_invalid' });
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-22T00:00:00Z', now }), { code: 'operator_backup_attestation_stale' });
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-25T00:00:00Z', now }), { code: 'operator_backup_verified_at_in_future' });
  assert.equal(requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-24T01:00:00Z', now }).backupId, 'b1');
});

test('probe host and ctid are validated before any command is built', () => {
  for (const host of ['pve-node-1', 'pve.example.internal', '192.0.2.10', 'fd00::1']) assert.equal(validateProbeHost(host), host);
  for (const host of ['', '-oProxyCommand=touch_x', 'a b', 'a;b', 'root@pve', 'a$(id)', 'x'.repeat(300)]) {
    assert.throws(() => validateProbeHost(host), { code: 'operator_probe_host_invalid' }, host);
  }
  assert.equal(validateProbeCtid('112'), '112');
  for (const ctid of ['0', '-1', '1a', '112 ', '', '12345678901']) assert.throws(() => validateProbeCtid(ctid), { code: 'operator_probe_ctid_invalid' }, ctid);
  assert.throws(() => dbHostProbeCommands({ host: 'pve', ctid: '112', dataDirectory: "/var/lib/pg'; rm -rf /" }), { code: 'operator_probe_data_directory_invalid' });
  assert.throws(() => dbHostProbeCommands({ host: 'pve', ctid: '112', dataDirectory: '/var/lib/../etc' }), { code: 'operator_probe_data_directory_invalid' });
});

test('probe commands are fixed argv arrays with every remote word quoted', () => {
  const commands = dbHostProbeCommands({ host: 'pve-node-1', ctid: '112', dataDirectory: '/var/lib/postgresql/16/main' });
  assert.deepEqual(commands.freeSpace, ['ssh', '-o', 'BatchMode=yes', 'pve-node-1',
    "'pct' 'exec' '112' '--' 'df' '-B1' '--output=avail,size' '/var/lib/postgresql/16/main'"]);
  assert.deepEqual(commands.identity, ['ssh', '-o', 'BatchMode=yes', 'pve-node-1',
    `'pct' 'exec' '112' '--' 'su' 'postgres' '-c' 'psql -XAt -c '\\''select system_identifier from pg_control_system()'\\'''`]);
});

test('pct probe: identity match returns free space measured on the data directory', async () => {
  const { runCommand, calls } = fakeRunCommand();
  const probe = createPctDbHostProbe({ host: 'pve-node-1', ctid: '112', identity: IDENTITY, runCommand });
  const result = await probe();
  assert.equal(result.freeBytes, 9_000_000_000);
  assert.equal(result.sizeBytes, 21474836480);
  assert.equal(result.systemIdentifier, IDENTITY.systemIdentifier);
  assert.equal(calls.length, 2);
});

test('pct probe: identity mismatch, command failure, and unparsable output refuse', async () => {
  const mismatch = createPctDbHostProbe({ host: 'pve', ctid: '113', identity: IDENTITY, runCommand: fakeRunCommand({ systemIdentifier: '7000000000000000001' }).runCommand });
  await assert.rejects(mismatch, { code: 'operator_db_host_identity_mismatch' });
  const failing = createPctDbHostProbe({ host: 'pve', ctid: '112', identity: IDENTITY, runCommand: fakeRunCommand({ fail: true }).runCommand });
  await assert.rejects(failing, { code: 'operator_db_host_probe_failed' });
  const garbage = createPctDbHostProbe({ host: 'pve', ctid: '112', identity: IDENTITY, runCommand: async argv => ({ stdout: argv[4].includes("'psql") ? IDENTITY.systemIdentifier : 'df: no such file' }) });
  await assert.rejects(garbage, { code: 'operator_db_host_probe_failed' });
});

test('requireFreeSpace enforces the floor and the drop threshold', () => {
  assert.throws(() => requireFreeSpace({ probe: { freeBytes: 1_000 }, previous: null, floorBytes: 2_000, maxDropBytes: 0 }), { code: 'operator_free_space_floor_breached' });
  assert.throws(() => requireFreeSpace({ probe: { freeBytes: 5_000 }, previous: { freeBytes: 6_000 }, floorBytes: 0, maxDropBytes: 500 }), { code: 'operator_free_space_dropped' });
  assert.equal(requireFreeSpace({ probe: { freeBytes: 5_800 }, previous: { freeBytes: 6_000 }, floorBytes: 0, maxDropBytes: 500 }).freeBytes, 5_800);
});

test('operator log appends one JSON line per entry', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-operator-log-'));
  const logPath = path.join(dir, 'operator.jsonl');
  for (const outcome of ['refused', 'completed']) {
    const log = openOperatorLog(logPath);
    log.append({ outcome });
    log.close();
  }
  assert.deepEqual(fs.readFileSync(logPath, 'utf8').trim().split('\n').map(line => JSON.parse(line).outcome), ['refused', 'completed']);
  assert.equal(fs.statSync(logPath).mode & 0o777, 0o600);
  assert.throws(() => openOperatorLog(path.join(dir, 'missing', 'x.jsonl')), { code: 'operator_log_unwritable' });
  assert.throws(() => openOperatorLog(undefined), { code: 'operator_log_required' });
});

test('CLI exposes only inventory and audit-phase-a, and only the canonical table', async () => {
  for (const command of ['audit-phase-c-schema', 'audit-phase-c-copy', 'audit-phase-d', 'audit-rollback', 'raw-gc']) {
    await assert.rejects(runCli(['node', 'cli', command]), { code: 'operator_cli_command_invalid' });
  }
  await assert.rejects(runCli(['node', 'cli', 'inventory', '--table', 'audit_events_v2_legacy']), { code: 'audit_retention_table_not_allowed' });
  await assert.rejects(runCli(['node', 'cli', 'inventory', '--filesystem-path', '/']), { code: 'operator_cli_argument_unknown' });
});
