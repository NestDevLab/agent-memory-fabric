import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { PAM_RUNTIME_PRIVATE_FILES, validatePamRuntimePrivateDir } from '../src/operator/pam-runtime-private-dir.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-pam-private-'));
  const directory = path.join(root, 'runtime');
  fs.mkdirSync(directory, { mode: 0o700 }); fs.chmodSync(directory, 0o700);
  const environment = { AMF_PAM_RUNTIME_PRIVATE_DIR: directory };
  for (const [variable, filename] of Object.entries(PAM_RUNTIME_PRIVATE_FILES)) {
    const target = path.join(directory, filename);
    fs.writeFileSync(target, filename.endsWith('.json') ? '{"schema":"test"}' : 'test-state-key', { mode: 0o600 });
    fs.chmodSync(target, 0o600); environment[variable] = target;
  }
  return { root, directory, environment };
}

test('PAM runtime private directory accepts one service-owned 0700 parent with fixed 0600 files', () => {
  const sample = fixture();
  try {
    assert.deepEqual(validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment }), { ok: true, uid: process.geteuid(), gid: process.getegid(), files: 3 });
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('PAM runtime preflight rejects parent and file GID mismatches', (t) => {
  const sample = fixture();
  try {
    const alternateGid = process.getgroups().find(gid => gid !== process.getegid());
    if (alternateGid === undefined) return t.skip('no supplemental group available for a real GID mismatch');
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment, expectedGid: alternateGid }), /pam_runtime_private_dir_invalid:parent/);
    fs.chownSync(sample.directory, process.geteuid(), alternateGid);
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment, expectedGid: alternateGid }), /pam_runtime_private_dir_invalid:file/);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('PAM runtime preflight rejects a root-owned parent for a non-root service UID', () => {
  const sample = fixture();
  try {
    const simulatedServiceUid = process.geteuid() === 0 ? 1000 : process.geteuid() + 1;
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment, expectedUid: simulatedServiceUid }), /pam_runtime_private_dir_invalid:parent/);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('PAM runtime preflight rejects loose modes, symlinks and stale individual path bindings', () => {
  const sample = fixture();
  try {
    fs.chmodSync(sample.directory, 0o755);
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment }), /pam_runtime_private_dir_invalid:parent/);
    fs.chmodSync(sample.directory, 0o700);
    const routingPath = sample.environment.AMF_PAM_ROUTING_KEY_RING_PATH;
    fs.unlinkSync(routingPath); fs.symlinkSync('/dev/null', routingPath);
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment }), /pam_runtime_private_dir_invalid:file/);
    fs.unlinkSync(routingPath); fs.writeFileSync(routingPath, '{"schema":"test"}', { mode: 0o600 }); fs.chmodSync(routingPath, 0o600);
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: { ...sample.environment, PAM_WORKSPACE_CONFIG: '/run/config/pam-workspace-config.json' } }), /pam_runtime_private_dir_invalid:binding/);
    fs.writeFileSync(path.join(sample.directory, 'unexpected-secret'), 'unexpected', { mode: 0o600 });
    assert.throws(() => validatePamRuntimePrivateDir({ directory: sample.directory, environment: sample.environment }), /pam_runtime_private_dir_invalid:contents/);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('production compose uses one PAM private-directory mount and keeps session routes separate', () => {
  const compose = fs.readFileSync(new URL('../compose.agent-memory-fabric.yml', import.meta.url), 'utf8');
  assert.match(compose, /AMF_PAM_RUNTIME_PRIVATE_DIR: \/run\/amf-pam-private/);
  assert.match(compose, /\$\{AMF_PAM_RUNTIME_PRIVATE_DIR:[^}]+\}:\/run\/amf-pam-private:ro/);
  assert.match(compose, /\$\{AMF_SESSION_ROUTE_DIR:[^}]+\}:\/run\/amf-session-routes:ro/);
  assert.doesNotMatch(compose, /AMF_ROUTING_KEY_RING_SECRET_PATH|PAM_WORKSPACE_CONFIG_PATH|PAM_APPLICATOR_STATE_KEY_SECRET_PATH/);
});
