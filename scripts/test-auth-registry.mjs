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
  parseCsvList,
  validateContextActorBinding
} from '../src/server.mjs';
import { ContextTokenVerifier } from '../src/context-token.mjs';

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

test('delegated session owners and context key versions are strict, active and non-chainable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-auth-delegation-'));
  const registryPath = path.join(dir, 'auth.json'); const previous = process.env.MEM0_AUTH_REGISTRY_PATH;
  const collector = { token: 'collector-token', active: true, actor: 'ct110-hermes-vitae', mode: 'scoped',
    allowedScopes: ['agent:ct110-hermes-vitae'], permissions: ['raw:ingest'] };
  const consumer = { token: 'consumer-token', active: true, actor: 'agent:vitae', mode: 'read_only_scoped',
    allowedScopes: ['agent:vitae'], permissions: ['sessions:read', 'purpose:conversation_recall'],
    sessionOwnerActors: ['ct110-hermes-vitae'], contextKeyVersions: ['ctx-vitae-v1'] };
  try {
    process.env.MEM0_AUTH_REGISTRY_PATH = registryPath;
    const check = async rows => {
      fs.writeFileSync(registryPath, JSON.stringify({ rows }));
      return loadAuthRegistry({ forceRefresh: true });
    };
    assert.equal((await check([collector, consumer])).length, 2);
    for (const rows of [
      [collector, { ...consumer, sessionOwnerActors: ['missing-owner'] }],
      [{ ...collector, active: false }, consumer],
      [{ ...collector, permissions: ['memory:status'] }, consumer],
      [{ ...collector, sessionOwnerActors: ['raw-root'] },
        { token: 'root-token', active: true, actor: 'raw-root', mode: 'scoped', allowedScopes: ['agent:raw-root'],
          permissions: ['raw:ingest'] }, consumer],
      [collector, { ...consumer, sessionOwnerActors: ['agent:vitae'] }],
      [collector, { ...consumer, contextKeyVersions: ['*'] }],
      [collector, consumer, { token: 'other-consumer-token', active: true, actor: 'agent:other',
        mode: 'read_only_scoped', allowedScopes: ['agent:other'], permissions: ['sessions:read'],
        contextKeyVersions: ['ctx-vitae-v1'] }],
      [collector, { ...consumer, actor: ['agent:vitae'] }]
    ]) await assert.rejects(check(rows), /auth_registry_invalid_row/);
  } finally {
    if (previous === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH;
    else process.env.MEM0_AUTH_REGISTRY_PATH = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('context key versions are bound one-to-one across registry policy and verifier ring', () => {
  const verifier = new ContextTokenVerifier({ keyRing: { currentKeyVersion: 'ctx-vitae-v1',
    keys: { 'ctx-vitae-v1': Buffer.alloc(32, 9).toString('base64') } }, policyRevision: 'test' });
  const policy = { contextKeyVersions: ['ctx-vitae-v1'] };
  const policies = { actors: { 'agent:vitae': { contextKeyVersions: ['ctx-vitae-v1'] } } };
  assert.doesNotThrow(() => validateContextActorBinding('agent:vitae', policy, policies, verifier));
  assert.throws(() => validateContextActorBinding('agent:vitae', policy,
    { actors: { 'agent:vitae': { contextKeyVersions: ['ctx-other-v1'] } } }, verifier),
  /context_actor_binding_invalid/);
  assert.throws(() => validateContextActorBinding('agent:vitae', policy,
    { actors: { 'agent:vitae': { contextKeyVersions: ['ctx-vitae-v1'] },
      'agent:other': { contextKeyVersions: ['ctx-vitae-v1'] } } }, verifier),
  /context_actor_binding_invalid/);
  assert.throws(() => validateContextActorBinding('agent:vitae', { contextKeyVersions: ['ctx-missing-v1'] },
    { actors: { 'agent:vitae': { contextKeyVersions: ['ctx-missing-v1'] } } }, verifier),
  /context_actor_binding_invalid/);
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
