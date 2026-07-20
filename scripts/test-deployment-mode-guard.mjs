import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { verifyDeploymentRoot } from './amf-verify-deployment-mode.mjs';

test('deployment root guard requires root-owned 0711 traversal mode', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-deploy-root-'));
  try {
    fs.chmodSync(root, 0o711);
    const ownership = { uid: process.getuid(), gid: process.getgid() };
    assert.deepEqual(verifyDeploymentRoot(root, ownership), { ok: true, path: root, mode: '0711' });
    fs.chmodSync(root, 0o700);
    assert.throws(() => verifyDeploymentRoot(root, ownership), /amf_deployment_root_mode_invalid/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
