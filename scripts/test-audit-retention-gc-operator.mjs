import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CHECKPOINTS, connectionTarget, isTestDatabaseUrl, requireBackupAttestation,
  requireFreeSpaceFloor, requireLiveMutationGuard, requireReaderModeForLiveGc, sslConfigFromMode
} from '../src/operator/audit-retention-gc-operator.mjs';

test('connectionTarget derives host:port/dbname without leaking credentials', () => {
  assert.equal(connectionTarget('postgres://user:secret@db.example.internal:5433/agent_memory_fabric'), 'db.example.internal:5433/agent_memory_fabric');
  assert.equal(connectionTarget('postgres://user:secret@localhost/agent_memory_fabric'), 'localhost:5432/agent_memory_fabric');
  assert.throws(() => connectionTarget('not-a-url'), { code: 'operator_database_url_invalid' });
  assert.throws(() => connectionTarget('mysql://localhost/x'), { code: 'operator_database_url_invalid' });
});

test('isTestDatabaseUrl is a separate guard from the operator live-target confirmation', () => {
  assert.equal(isTestDatabaseUrl('postgres://u@h/amf_audit_gc_test'), true);
  assert.equal(isTestDatabaseUrl('postgres://u@h/agent_memory_fabric'), false);
  assert.equal(isTestDatabaseUrl('not-a-url'), false);
});

test('sslConfigFromMode', () => {
  assert.equal(sslConfigFromMode('disable'), false);
  assert.deepEqual(sslConfigFromMode('require'), { rejectUnauthorized: false });
  assert.deepEqual(sslConfigFromMode('verify-full'), { rejectUnauthorized: true });
  assert.throws(() => sslConfigFromMode('bogus'), { code: 'operator_ssl_mode_invalid' });
});

test('requireLiveMutationGuard: dry-run (no --apply) never demands anything', () => {
  const result = requireLiveMutationGuard({ apply: false });
  assert.deepEqual(result, { willMutate: false });
});

test('requireLiveMutationGuard: --apply with no approval refuses', () => {
  assert.throws(() => requireLiveMutationGuard({
    apply: true, approval: undefined, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    iKnowThisIsLive: true, confirmTarget: 'h:5432/d', resolvedTarget: 'h:5432/d'
  }), { code: 'operator_approval_missing_or_wrong' });
});

test('requireLiveMutationGuard: --apply with the WRONG checkpoint refuses (approvals are per checkpoint, never blanket)', () => {
  assert.throws(() => requireLiveMutationGuard({
    apply: true, approval: CHECKPOINTS.RAW_GC_LIVE, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    iKnowThisIsLive: true, confirmTarget: 'h:5432/d', resolvedTarget: 'h:5432/d'
  }), { code: 'operator_approval_missing_or_wrong' });
});

test('requireLiveMutationGuard: --apply without --i-know-this-is-live refuses', () => {
  assert.throws(() => requireLiveMutationGuard({
    apply: true, approval: CHECKPOINTS.AUDIT_BULK_DELETE, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    iKnowThisIsLive: false, confirmTarget: 'h:5432/d', resolvedTarget: 'h:5432/d'
  }), { code: 'operator_live_confirmation_required' });
});

test('requireLiveMutationGuard: --confirm-target mismatch refuses (this is the accidental-CT112 guard)', () => {
  assert.throws(() => requireLiveMutationGuard({
    apply: true, approval: CHECKPOINTS.AUDIT_BULK_DELETE, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    iKnowThisIsLive: true, confirmTarget: 'wrong-host:5432/d', resolvedTarget: 'ct112:5432/agent_memory_fabric'
  }), { code: 'operator_target_confirmation_mismatch' });
});

test('requireLiveMutationGuard: every guard satisfied succeeds', () => {
  const result = requireLiveMutationGuard({
    apply: true, approval: CHECKPOINTS.AUDIT_BULK_DELETE, requiredCheckpoint: CHECKPOINTS.AUDIT_BULK_DELETE,
    iKnowThisIsLive: true, confirmTarget: 'h:5432/d', resolvedTarget: 'h:5432/d'
  });
  assert.deepEqual(result, { willMutate: true });
});

test('requireBackupAttestation: missing id/timestamp refuses', () => {
  assert.throws(() => requireBackupAttestation({ backupId: null, backupVerifiedAt: '2026-09-24T00:00:00Z' }), { code: 'operator_backup_id_required' });
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: 'not-a-date' }), { code: 'operator_backup_verified_at_invalid' });
});

test('requireBackupAttestation: stale attestation refuses', () => {
  const now = () => new Date('2026-09-24T12:00:00Z');
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-22T00:00:00Z', maxAgeHours: 24, now }),
    { code: 'operator_backup_attestation_stale' });
});

test('requireBackupAttestation: a future verified-at refuses (clock skew / typo guard)', () => {
  const now = () => new Date('2026-09-24T12:00:00Z');
  assert.throws(() => requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-25T00:00:00Z', maxAgeHours: 24, now }),
    { code: 'operator_backup_verified_at_in_future' });
});

test('requireBackupAttestation: fresh attestation within the window succeeds', () => {
  const now = () => new Date('2026-09-24T12:00:00Z');
  const result = requireBackupAttestation({ backupId: 'b1', backupVerifiedAt: '2026-09-24T01:00:00Z', maxAgeHours: 24, now });
  assert.equal(result.backupId, 'b1');
  assert.ok(result.ageHours < 24);
});

test('requireFreeSpaceFloor: refuses when projected free space would drop below the floor', () => {
  assert.throws(() => requireFreeSpaceFloor({ freeBytes: 3_000_000_000, floorBytes: 2_000_000_000, estimateBytes: 2_000_000_000 }),
    { code: 'operator_free_space_floor_breached' });
});

test('requireFreeSpaceFloor: succeeds with sufficient headroom', () => {
  const result = requireFreeSpaceFloor({ freeBytes: 10_000_000_000, floorBytes: 2_000_000_000, estimateBytes: 1_000_000_000 });
  assert.equal(result.projectedFreeBytes, 9_000_000_000);
});

test('requireReaderModeForLiveGc: disabled mode refuses live GC and says why', () => {
  assert.throws(() => requireReaderModeForLiveGc({ AMF_CONVERSATION_READER_MODE: 'disabled' }), { code: 'raw_gc_reader_mode_disabled' });
  assert.throws(() => requireReaderModeForLiveGc({}), { code: 'raw_gc_reader_mode_disabled' });
});

test('requireReaderModeForLiveGc: shadow or active modes are allowed through to the engine-level proof', () => {
  assert.deepEqual(requireReaderModeForLiveGc({ AMF_CONVERSATION_READER_MODE: 'shadow' }), { mode: 'shadow' });
  assert.deepEqual(requireReaderModeForLiveGc({ AMF_CONVERSATION_READER_MODE: 'active' }), { mode: 'active' });
});
