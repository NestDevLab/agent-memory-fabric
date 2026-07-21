import assert from 'node:assert/strict';
import test from 'node:test';

import {
  aggregatePauseCheckpointInputs,
  createPauseManifest,
} from '../src/migration-pause.mjs';
import {
  createM4BackfillGateVerifier,
  createM4RollbackManifest,
  verifyM4BackfillGate,
  verifyM4RollbackManifest,
} from '../src/migration/m4-backfill-gate.mjs';
import { planM4BackfillBatch } from '../src/migration/m4-backfill-coordinator.mjs';

const COLLECTOR = `pause-collector-${'1'.repeat(64)}`;
const digest = byte => `sha256:${byte.repeat(64)}`;
const checkpoint = (id, byte) => ({ id, digest: digest(byte) });
const keyDocument = (keyId = 'migration-key-pause', byte = 9) => ({
  schema: 'amf.migration-signing-key/v1',
  keyId,
  key: Buffer.alloc(32, byte).toString('base64'),
});

function pauseFixture() {
  const key = keyDocument();
  const roster = {
    schema: 'amf.migration-pause-collector-roster/v1',
    manifestId: 'pause-manifest-gate',
    revision: 4,
    keyId: key.keyId,
    collectors: [COLLECTOR],
  };
  const input = {
    schema: 'amf.migration-pause-checkpoints/v1',
    manifestId: roster.manifestId,
    revision: roster.revision,
    keyId: roster.keyId,
    pause: {
      state: 'paused',
      collectorCursor: checkpoint('collector-cursor-gate', '1'),
      pendingOutbox: checkpoint('pending-outbox-gate', '2'),
      acknowledgements: checkpoint('acknowledgements-gate', '3'),
      deadLetters: checkpoint('dead-letters-gate', '4'),
      sourceCheckpoint: checkpoint('source-checkpoint-gate', '5'),
      nativeTranscriptAuthority: checkpoint('native-authority-gate', '6'),
      evidence: checkpoint(COLLECTOR, '7'),
    },
  };
  const aggregate = aggregatePauseCheckpointInputs([input], roster);
  return { key, manifest: createPauseManifest(aggregate, key) };
}

function rollbackPayload(pauseManifest, restoreTest = 'passed') {
  return {
    schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-gate',
    phase: 'rollback',
    revision: 2,
    rollback: {
      pauseEvidence: {
        manifestId: pauseManifest.manifestId,
        digest: pauseManifest.integrity.payloadDigest,
        signature: pauseManifest.integrity.signature,
      },
      sourceCheckpoint: structuredClone(pauseManifest.pause.sourceCheckpoint),
      targetCheckpoint: checkpoint('target-checkpoint-gate', '8'),
      compatibilityRouteRevision: 'compatibility-route-gate',
      recoveryCopy: checkpoint('recovery-copy-gate', '9'),
      restoreTest,
    },
  };
}

function fixture({ restoreTest = 'passed', rollbackKey = keyDocument('migration-key-rollback', 10) } = {}) {
  const pause = pauseFixture();
  const rollbackManifest = createM4RollbackManifest(rollbackPayload(pause.manifest, restoreTest), rollbackKey);
  return {
    input: {
      runId: 'migration-run-gate',
      phase: 'v2-archive',
      pauseManifest: pause.manifest,
      pauseKeyDocument: pause.key,
      rollbackManifest,
      rollbackKeyDocument: rollbackKey,
    },
    pause,
    rollbackKey,
  };
}

function exactError(operation, code) {
  assert.throws(operation, error => error?.code === code && error.message === code);
}

test('signed pause and rollback evidence produce the exact coordinator gate', async () => {
  const { input } = fixture();
  const gate = verifyM4BackfillGate(input);
  assert.deepEqual(Object.keys(gate).sort(), [
    'pauseEvidence', 'phase', 'rollbackEvidence', 'runId', 'schema',
    'sourceCheckpoint', 'state', 'targetCheckpoint',
  ].sort());
  assert.equal(gate.state, 'approved');
  assert.equal(gate.pauseEvidence.digest, input.pauseManifest.integrity.payloadDigest);
  assert.equal(gate.rollbackEvidence.digest, input.rollbackManifest.integrity.payloadDigest);
  assert.deepEqual(gate.sourceCheckpoint, input.pauseManifest.pause.sourceCheckpoint);
  const plan = await planM4BackfillBatch({
    gateVerifier: createM4BackfillGateVerifier(input),
    maxEvents: 25,
  });
  assert.equal(plan.phase, 'v2-archive');
  assert.match(plan.planDigest, /^sha256:[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify({ gate, plan }), /migration-key|CQkJCQ|CgoKCg/);
});

test('rollback verification authenticates its declarative payload with independent rotation', () => {
  const { input, rollbackKey } = fixture();
  assert.deepEqual(verifyM4RollbackManifest(input.rollbackManifest, rollbackKey), input.rollbackManifest);
  const tampered = structuredClone(input.rollbackManifest);
  tampered.rollback.targetCheckpoint.digest = digest('a');
  exactError(() => verifyM4RollbackManifest(tampered, rollbackKey), 'm4_rollback_digest_mismatch');
  exactError(() => verifyM4RollbackManifest(input.rollbackManifest, keyDocument('migration-key-rollback', 11)),
    'm4_rollback_signature_mismatch');
  exactError(() => verifyM4RollbackManifest(input.rollbackManifest, keyDocument('different-key-id', 10)),
    'm4_rollback_key_id_mismatch');
});

test('gate rejects unready restore state and every pause or checkpoint binding drift', () => {
  exactError(() => verifyM4BackfillGate(fixture({ restoreTest: 'not-run' }).input), 'm4_backfill_gate_restore_required');
  const evidenceDrift = fixture().input;
  evidenceDrift.rollbackManifest.rollback.pauseEvidence.digest = digest('b');
  exactError(() => verifyM4BackfillGate(evidenceDrift), 'm4_backfill_gate_rollback_invalid');

  const resignedEvidenceDrift = fixture();
  const changedPayload = rollbackPayload(resignedEvidenceDrift.pause.manifest);
  changedPayload.rollback.pauseEvidence.digest = digest('c');
  resignedEvidenceDrift.input.rollbackManifest = createM4RollbackManifest(changedPayload, resignedEvidenceDrift.rollbackKey);
  exactError(() => verifyM4BackfillGate(resignedEvidenceDrift.input), 'm4_backfill_gate_evidence_mismatch');

  const resignedCheckpointDrift = fixture();
  const changedCheckpoint = rollbackPayload(resignedCheckpointDrift.pause.manifest);
  changedCheckpoint.rollback.sourceCheckpoint.digest = digest('d');
  resignedCheckpointDrift.input.rollbackManifest = createM4RollbackManifest(changedCheckpoint, resignedCheckpointDrift.rollbackKey);
  exactError(() => verifyM4BackfillGate(resignedCheckpointDrift.input), 'm4_backfill_gate_evidence_mismatch');

  const pauseTamper = fixture().input;
  pauseTamper.pauseManifest.pause.evidence.digest = digest('e');
  exactError(() => verifyM4BackfillGate(pauseTamper), 'm4_backfill_gate_pause_invalid');

  const nonAggregate = fixture().input;
  nonAggregate.pauseManifest.pause.evidence.id = 'pause-evidence-single-collector';
  exactError(() => verifyM4BackfillGate(nonAggregate), 'm4_backfill_gate_pause_invalid');
});

test('gate inputs are strict and a verifier snapshot is mutation isolated', async () => {
  const setup = fixture();
  const verifier = createM4BackfillGateVerifier(setup.input);
  const expected = await verifier();
  setup.input.runId = 'mutated-run';
  setup.input.rollbackManifest.rollback.targetCheckpoint.digest = digest('f');
  setup.input.pauseKeyDocument.key = Buffer.alloc(32, 99).toString('base64');
  const actual = await verifier();
  assert.deepEqual(actual, expected);
  actual.sourceCheckpoint.digest = digest('0');
  assert.deepEqual(await verifier(), expected);

  exactError(() => verifyM4BackfillGate({ ...fixture().input, extra: true }), 'm4_backfill_gate_input_invalid');
  exactError(() => verifyM4BackfillGate({ ...fixture().input, phase: 'cleanup' }), 'm4_backfill_gate_input_invalid');
  exactError(() => createM4RollbackManifest({ ...rollbackPayload(pauseFixture().manifest), command: 'forbidden' }, keyDocument()),
    'm4_rollback_manifest_input_invalid');
});
