import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  authenticateRequest,
  getAuthRegistrySource,
  loadAuthRegistry,
  parseActive,
  parseCsvList
} from '../src/server.mjs';

function requestWithToken(token) {
  return {
    headers: {
      authorization: `Bearer ${token}`,
      host: 'localhost'
    },
    url: '/v1/policies/resolve'
  };
}

test('local auth registry loads rows without network access', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mem0-auth-registry-'));
  const registryPath = path.join(dir, 'auth-registry.json');
  fs.writeFileSync(registryPath, JSON.stringify({
    rows: [
      {
        token: 'placeholder-token-main',
        active: true,
        actor: 'main-openclaw',
        mode: 'allow_all',
        allowedScopes: '*',
        permissions: ['memory:search', 'memory:add']
      },
      {
        token: 'placeholder-token-disabled',
        active: 'false',
        actor: 'disabled',
        mode: 'scoped',
        allowedScopes: 'tirrenia',
        permissions: 'memory:search'
      }
    ]
  }));

  const originalEnv = {
    MEM0_AUTH_REGISTRY_PATH: process.env.MEM0_AUTH_REGISTRY_PATH,
    N8N_API_BASE_URL: process.env.N8N_API_BASE_URL,
    N8N_API_KEY: process.env.N8N_API_KEY,
    N8N_AUTH_TABLE_ID: process.env.N8N_AUTH_TABLE_ID
  };
  const originalFetch = globalThis.fetch;

  try {
    process.env.MEM0_AUTH_REGISTRY_PATH = registryPath;
    process.env.N8N_API_BASE_URL = 'http://127.0.0.1:1';
    process.env.N8N_API_KEY = 'placeholder-n8n-key';
    process.env.N8N_AUTH_TABLE_ID = 'placeholder-table-id';
    globalThis.fetch = () => {
      throw new Error('fetch_should_not_be_called');
    };

    assert.equal(getAuthRegistrySource().kind, 'local-json');
    const rows = await loadAuthRegistry();
    assert.equal(rows.length, 2);

    const auth = await authenticateRequest(requestWithToken('placeholder-token-main'));
    assert.equal(auth.actor, 'main-openclaw');
    assert.deepEqual(auth.policy, {
      mode: 'allow_all',
      allowedScopes: ['*'],
      permissions: ['memory:search', 'memory:add']
    });

    await assert.rejects(
      authenticateRequest(requestWithToken('placeholder-token-disabled')),
      /invalid_token/
    );
  } finally {
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    globalThis.fetch = originalFetch;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('auth registry helpers preserve current CSV policy semantics', () => {
  assert.deepEqual(parseCsvList('alpha, beta,,gamma'), ['alpha', 'beta', 'gamma']);
  assert.deepEqual(parseCsvList('*'), ['*']);
  assert.deepEqual(parseCsvList(['alpha', ' beta ']), ['alpha', 'beta']);
  assert.equal(parseActive(true), true);
  assert.equal(parseActive('true'), true);
  assert.equal(parseActive('1'), true);
  assert.equal(parseActive(false), false);
  assert.equal(parseActive('false'), false);
  assert.equal(parseActive(undefined), false);
});
