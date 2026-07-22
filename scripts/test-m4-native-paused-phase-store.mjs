import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { M4NativePausedPhaseStore } from '../src/migration/m4-native-paused-phase-store.mjs';

const digest = value => `sha256:${crypto.createHash('sha256').update(String(value)).digest('hex')}`;
const binding = {
  runId: 'm4-phase-test-run',
  planDigest: digest('plan'),
  catalogDigest: digest('catalog'),
  shardCount: 2,
};

function checkpoint(ordinal) {
  return { id: `terminal-checkpoint-${ordinal}`, digest: digest(`checkpoint-${ordinal}`) };
}

function receipt(ordinal) {
  return {
    schema: 'amf.m4-native-paused-phase-receipt/v1',
    ordinal,
    runId: `m4-native-shard-${ordinal}`,
    planConfirmationDigest: digest(`plan-${ordinal}`),
    authorityDigest: digest(`authority-${ordinal}`),
    legacyCompletionDigest: digest('legacy'),
    terminalCheckpoint: checkpoint(ordinal),
    resultDigest: digest(`result-${ordinal}`),
    integrity: {
      algorithm: 'hmac-sha256',
      keyId: 'catalog-key-test',
      payloadDigest: digest(`receipt-${ordinal}`),
      signature: Buffer.alloc(32, ordinal + 1).toString('base64url'),
    },
  };
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-phase-store-'));
  return { root, store: new M4NativePausedPhaseStore({ rootPath: root, ...binding }) };
}

function cleanup(value) {
  value.store?.close();
  fs.rmSync(value.root, { recursive: true, force: true });
}

function code(action, expected) {
  assert.throws(action, error => error?.code === expected && error.message === expected);
}

function stateName(root) {
  const name = fs.readdirSync(root).find(item => /^m4-native-phase-[a-f0-9]{64}\.json$/.test(item));
  assert.ok(name);
  return name;
}

function statePath(root) {
  return path.join(root, stateName(root));
}

test('commits exact content-free receipts atomically and resumes after restart', () => {
  const value = fixture();
  try {
    assert.deepEqual(value.store.load(), []);
    const first = receipt(0);
    assert.deepEqual(value.store.commit(first), first);
    first.terminalCheckpoint.id = 'mutated-input';
    assert.deepEqual(value.store.load(), [receipt(0)]);
    value.store.close();
    value.store = new M4NativePausedPhaseStore({ rootPath: value.root, ...binding });
    value.store.commit(receipt(1));
    const loaded = value.store.load();
    assert.deepEqual(loaded, [receipt(0), receipt(1)]);
    loaded[0].runId = 'mutated-output';
    assert.deepEqual(value.store.load(), [receipt(0), receipt(1)]);
    assert.equal(fs.statSync(value.root).mode & 0o777, 0o700);
    assert.equal(fs.statSync(statePath(value.root)).mode & 0o777, 0o600);
    assert.doesNotMatch(fs.readFileSync(statePath(value.root), 'utf8'), /visible content|payload text|private/);
  } finally {
    cleanup(value);
  }
});

test('rejects gaps, substitution, foreign binding, corruption, and closed access', () => {
  const value = fixture();
  try {
    code(() => value.store.commit(receipt(1)), 'm4_native_phase_store_gap');
    value.store.commit(receipt(0));
    assert.deepEqual(value.store.commit(structuredClone(receipt(0))), receipt(0));
    code(() => value.store.commit({ ...receipt(0), resultDigest: digest('changed') }),
      'm4_native_phase_store_substitution');
    code(() => value.store.commit({ ...receipt(1), ordinal: 2 }),
      'm4_native_phase_store_receipt_invalid');

    const file = statePath(value.root);
    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    stored.binding.catalogDigest = digest('foreign');
    fs.writeFileSync(file, JSON.stringify(stored), { mode: 0o600 });
    code(() => value.store.load(), 'm4_native_phase_store_corrupt');
    fs.writeFileSync(file, '{bad', { mode: 0o600 });
    code(() => value.store.load(), 'm4_native_phase_store_corrupt');
    value.store.close();
    code(() => value.store.load(), 'm4_native_phase_store_closed');
  } finally {
    cleanup(value);
  }
});

test('rejects unsafe roots, permissions, symlinks, and oversized state', () => {
  const unsafe = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-phase-store-'));
  try {
    fs.chmodSync(unsafe, 0o755);
    code(() => new M4NativePausedPhaseStore({ rootPath: unsafe, ...binding }),
      'm4_native_phase_store_unsafe');
  } finally {
    fs.rmSync(unsafe, { recursive: true, force: true });
  }

  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-phase-store-'));
  try {
    const target = path.join(parent, 'target');
    fs.mkdirSync(target, { mode: 0o700 });
    const link = path.join(parent, 'link');
    fs.symlinkSync(target, link);
    code(() => new M4NativePausedPhaseStore({ rootPath: link, ...binding }),
      'm4_native_phase_store_unsafe');
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }

  const value = fixture();
  try {
    value.store.commit(receipt(0));
    value.store.close();
    fs.chmodSync(statePath(value.root), 0o644);
    value.store = new M4NativePausedPhaseStore({ rootPath: value.root, ...binding });
    code(() => value.store.load(), 'm4_native_phase_store_unsafe');
    value.store.close();
    fs.chmodSync(statePath(value.root), 0o600);
    fs.writeFileSync(statePath(value.root), 'x'.repeat(2_097_153), { mode: 0o600 });
    value.store = new M4NativePausedPhaseStore({ rootPath: value.root, ...binding });
    code(() => value.store.load(), 'm4_native_phase_store_unsafe');
  } finally {
    cleanup(value);
  }
});

test('pins descriptor reads, replaces a swapped symlink, and recovers torn temporary files', () => {
  const value = fixture();
  const originalRead = fs.readFileSync;
  const originalRename = fs.renameSync;
  try {
    value.store.commit(receipt(0));
    let mutated = false;
    fs.readFileSync = function mutatePinnedState(target, ...args) {
      if (!mutated && typeof target === 'number') {
        mutated = true;
        const stored = JSON.parse(originalRead.call(this, statePath(value.root), 'utf8'));
        stored.receipts[0].resultDigest = digest('changed-during-read');
        fs.writeFileSync(statePath(value.root), JSON.stringify(stored), { mode: 0o600 });
      }
      return originalRead.call(this, target, ...args);
    };
    code(() => value.store.load(), 'm4_native_phase_store_unsafe');
    assert.equal(mutated, true);
    fs.readFileSync = originalRead;

    fs.writeFileSync(statePath(value.root), JSON.stringify({
      schema: 'amf.m4-native-paused-phase-receipts/v1',
      binding: { runId: binding.runId, planDigest: binding.planDigest,
        catalogDigest: binding.catalogDigest },
      receipts: [receipt(0)],
    }), { mode: 0o600 });
    let swapped = false;
    fs.renameSync = function swapBeforeRename(from, to) {
      if (!swapped && String(to).endsWith(stateName(value.root))) {
        swapped = true;
        const target = statePath(value.root);
        fs.unlinkSync(target);
        fs.symlinkSync('/dev/null', target);
      }
      return originalRename.call(this, from, to);
    };
    value.store.commit(receipt(1));
    assert.equal(swapped, true);
    assert.equal(fs.lstatSync(statePath(value.root)).isSymbolicLink(), false);
    fs.renameSync = originalRename;

    value.store.close();
    const temporary = path.join(value.root,
      `.${stateName(value.root)}.12345678-1234-1234-1234-123456789abc.tmp`);
    fs.writeFileSync(temporary, '{torn', { mode: 0o600 });
    value.store = new M4NativePausedPhaseStore({ rootPath: value.root, ...binding });
    assert.equal(fs.existsSync(temporary), false);
    assert.equal(value.store.load().length, 2);
  } finally {
    fs.readFileSync = originalRead;
    fs.renameSync = originalRename;
    cleanup(value);
  }
});
