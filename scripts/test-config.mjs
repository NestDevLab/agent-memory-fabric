import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

test('numeric environment settings fail fast instead of becoming NaN', () => {
  const result = spawnSync(process.execPath, ['src/server.mjs', '--check'], {
    cwd: root,
    env: { ...process.env, PORT: 'not-a-number' },
    encoding: 'utf8'
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /invalid_environment:PORT/);
});

test('the application executable is disabled unless explicitly enabled', () => {
  const result = spawnSync(process.execPath, ['src/server.mjs'], {
    cwd: root,
    env: { ...process.env, AMF_SERVER_ENABLED: 'false' },
    encoding: 'utf8'
  });
  assert.equal(result.status, 78);
  assert.match(result.stderr, /agent-memory-fabric disabled/);
});

test('an enabled application still refuses the example-policy fallback', () => {
  const result = spawnSync(process.execPath, ['src/server.mjs'], {
    cwd: root,
    env: { ...process.env, AMF_SERVER_ENABLED: 'true', AMF_POLICY_PATH: '', MEM0_GATEWAY_POLICY_PATH: '' },
    encoding: 'utf8'
  });
  assert.equal(result.status, 78);
  assert.match(result.stderr, /AMF_POLICY_PATH must reference an explicit production policy/);
});

test('disabled module import does not parse Fabric keys or create catalog/RAW paths', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-disabled-import-'));
  const dataPath = path.join(directory, 'must-not-exist');
  try {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./src/server.mjs')"], {
      cwd: root,
      env: {
        ...process.env,
        AMF_SERVER_ENABLED: 'false',
        MEM0_BACKEND_KIND: 'disabled',
        AMF_RAW_ENCRYPTION_KEY: 'not-a-canonical-key',
        AMF_DATA_PATH: dataPath,
        AMF_CATALOG_KIND: 'sqlite'
      },
      encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(dataPath), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
