import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { M4ProgressStore } from '../src/migration/m4-progress-store.mjs';

const DIGEST = character => `sha256:${character.repeat(64)}`;
const binding = { runId: 'm4-run-001', phase: 'v2-archive', planDigest: DIGEST('a') };
const checkpoint = index => ({ id: `checkpoint-${index}`, digest: DIGEST(index.toString(16)) });
const progress = index => ({
  schema: 'amf.m4-backfill-progress/v1', ...binding, sequence: index, checkpoint: checkpoint(index),
  eventId: `cevt_progress-${String(index).padStart(8, '0')}`, payloadDigest: DIGEST((index + 1).toString(16)),
});

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-progress-'));
  return { root, store: new M4ProgressStore({ rootPath: root, ...binding }) };
}
function cleanup(value) { value.store?.close(); fs.rmSync(value.root, { recursive: true, force: true }); }
function code(action, expected) { return assert.throws(action, error => error?.code === expected && error.message === expected); }
function statePath(root, current = binding) { return path.join(root, `m4-progress-${current.runId}-${current.phase}-${current.planDigest.slice(7)}.json`); }

test('stores exact coordinator-compatible progress durably and restart-safely', () => {
  const value = fixture();
  try {
    assert.equal(value.store.load({ runId: binding.runId, phase: binding.phase }), null);
    const first = progress(1);
    assert.deepEqual(value.store.commit(first), {
      schema: 'amf.m4-backfill-progress-ack/v1', committed: true, runId: binding.runId, phase: binding.phase,
      planDigest: binding.planDigest, sequence: 1, checkpoint: checkpoint(1),
    });
    first.checkpoint.id = 'mutated-checkpoint';
    assert.deepEqual(value.store.load({ runId: binding.runId, phase: binding.phase }), progress(1));
    const second = progress(2);
    value.store.commit(second);
    value.store.close(); value.store = new M4ProgressStore({ rootPath: value.root, ...binding });
    const loaded = value.store.load({ runId: binding.runId, phase: binding.phase });
    assert.deepEqual(loaded, second);
    loaded.checkpoint.id = 'mutated-return';
    assert.deepEqual(value.store.load({ runId: binding.runId, phase: binding.phase }), second);
    assert.equal(fs.statSync(value.root).mode & 0o777, 0o700);
    assert.equal(fs.statSync(statePath(value.root)).mode & 0o777, 0o600);
  } finally { cleanup(value); }
});

test('duplicates are idempotent; rollback, drift, gaps, and checkpoint reuse fail closed', () => {
  const value = fixture();
  try {
    const first = progress(1); const ack = value.store.commit(first);
    assert.deepEqual(value.store.commit(structuredClone(first)), ack);
    code(() => value.store.commit({ ...first, eventId: 'cevt_changed-00000001' }), 'm4_progress_drift');
    code(() => value.store.commit(progress(3)), 'm4_progress_sequence_invalid');
    const reused = progress(2); reused.checkpoint = structuredClone(first.checkpoint);
    code(() => value.store.commit(reused), 'm4_progress_checkpoint_invalid');
    value.store.commit(progress(2));
    code(() => value.store.commit(progress(1)), 'm4_progress_rollback');
  } finally { cleanup(value); }
});

test('strict namespaces, plans, and progress shapes are rejected without state mutation', () => {
  const value = fixture();
  try {
    code(() => value.store.load({ runId: 'other-run-001', phase: binding.phase }), 'm4_progress_namespace_invalid');
    code(() => value.store.load({ runId: binding.runId, phase: 'paused-native' }), 'm4_progress_namespace_invalid');
    code(() => value.store.load({ runId: binding.runId }), 'm4_progress_request_invalid');
    code(() => value.store.commit({ ...progress(1), planDigest: DIGEST('b') }), 'm4_progress_commit_invalid');
    code(() => value.store.commit({ ...progress(1), runId: 'other-run-001' }), 'm4_progress_commit_invalid');
    code(() => value.store.commit({ ...progress(1), phase: 'paused-native' }), 'm4_progress_commit_invalid');
    code(() => value.store.commit({ ...progress(1), extra: true }), 'm4_progress_commit_invalid');
    code(() => value.store.commit({ ...progress(1), sequence: 2 }), 'm4_progress_sequence_invalid');
    assert.equal(value.store.load({ runId: binding.runId, phase: binding.phase }), null);
  } finally { cleanup(value); }
});

test('a target swapped to a symlink before rename is replaced without following it', () => {
  const value = fixture(); const originalRename = fs.renameSync;
  try {
    value.store.commit(progress(1));
    let swapped = false;
    fs.renameSync = function swapBeforeRename(from, to) {
      if (!swapped && String(to).endsWith(path.basename(statePath(value.root)))) {
        swapped = true;
        fs.unlinkSync(statePath(value.root));
        fs.symlinkSync('/dev/null', statePath(value.root));
      }
      return originalRename.call(this, from, to);
    };
    assert.deepEqual(value.store.commit(progress(2)).checkpoint, checkpoint(2));
    assert.equal(swapped, true);
    assert.equal(fs.lstatSync(statePath(value.root)).isSymbolicLink(), false);
  } finally {
    fs.renameSync = originalRename;
    cleanup(value);
  }
});

test('unsafe permissions, symlinks, corrupt state, and oversized state are rejected', () => {
  const unsafeRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-progress-'));
  try {
    fs.chmodSync(unsafeRoot, 0o755);
    code(() => new M4ProgressStore({ rootPath: unsafeRoot, ...binding }), 'm4_progress_storage_unsafe');
  } finally { fs.rmSync(unsafeRoot, { recursive: true, force: true }); }

  const symlinkParent = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-progress-'));
  try {
    const target = path.join(symlinkParent, 'target'); fs.mkdirSync(target, { mode: 0o700 });
    const link = path.join(symlinkParent, 'link'); fs.symlinkSync(target, link);
    code(() => new M4ProgressStore({ rootPath: link, ...binding }), 'm4_progress_storage_unsafe');
  } finally { fs.rmSync(symlinkParent, { recursive: true, force: true }); }

  const normalizedParent = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-progress-'));
  try {
    code(() => new M4ProgressStore({ rootPath: `${normalizedParent}/child/../target`, ...binding }), 'm4_progress_dependency_invalid');
  } finally { fs.rmSync(normalizedParent, { recursive: true, force: true }); }

  const ancestorParent = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-progress-'));
  try {
    const target = path.join(ancestorParent, 'target'); fs.mkdirSync(target, { mode: 0o700 });
    const link = path.join(ancestorParent, 'link'); fs.symlinkSync(target, link);
    code(() => new M4ProgressStore({ rootPath: path.join(link, 'nested'), ...binding }), 'm4_progress_storage_unsafe');
  } finally { fs.rmSync(ancestorParent, { recursive: true, force: true }); }

  const value = fixture();
  try {
    fs.symlinkSync('/dev/null', statePath(value.root));
    code(() => value.store.load({ runId: binding.runId, phase: binding.phase }), 'm4_progress_storage_unsafe');
  } finally { cleanup(value); }

  const corrupt = fixture();
  try {
    fs.writeFileSync(statePath(corrupt.root), '{bad', { mode: 0o600 });
    code(() => corrupt.store.load({ runId: binding.runId, phase: binding.phase }), 'm4_progress_state_invalid');
    fs.writeFileSync(statePath(corrupt.root), 'x'.repeat(4097), { mode: 0o600 });
    code(() => corrupt.store.load({ runId: binding.runId, phase: binding.phase }), 'm4_progress_storage_unsafe');
  } finally { cleanup(corrupt); }
});

test('same-inode mutation during descriptor reads is detected', () => {
  const value = fixture(); const originalRead = fs.readFileSync;
  try {
    value.store.commit(progress(1));
    let mutated = false;
    fs.readFileSync = function mutatePinnedState(target, ...args) {
      if (!mutated && typeof target === 'number') {
        mutated = true;
        const changed = { ...progress(1), eventId: 'cevt_changed-00000001' };
        originalRead.call(this, target, ...args);
        fs.writeFileSync(statePath(value.root), JSON.stringify(changed), { mode: 0o600 });
      }
      return originalRead.call(this, target, ...args);
    };
    code(() => value.store.load({ runId: binding.runId, phase: binding.phase }), 'm4_progress_storage_unsafe');
    assert.equal(mutated, true);
  } finally {
    fs.readFileSync = originalRead;
    cleanup(value);
  }
});

test('recognized torn temporary state is removed safely on restart', () => {
  const value = fixture();
  try {
    value.store.close();
    const temporary = path.join(value.root, `.${path.basename(statePath(value.root))}.12345678-1234-1234-1234-123456789abc.tmp`);
    fs.writeFileSync(temporary, '{torn', { mode: 0o600 });
    value.store = new M4ProgressStore({ rootPath: value.root, ...binding });
    assert.equal(fs.existsSync(temporary), false);
    assert.equal(value.store.load({ runId: binding.runId, phase: binding.phase }), null);
  } finally { cleanup(value); }
});
