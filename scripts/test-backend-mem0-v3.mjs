import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { createBackendAdapter } from '../src/backend.mjs';

function configuredEnv(overrides = {}) {
  return {
    MEM0_BACKEND_KIND: 'mem0-oss',
    MEM0_EMBEDDER_MODEL: 'test-embedder',
    MEM0_EMBEDDER_BASE_URL: 'http://embedder.invalid',
    MEM0_EMBEDDING_DIMS: '768',
    MEM0_VECTOR_DB_HOST: 'db.invalid',
    MEM0_VECTOR_DB_PORT: '5432',
    MEM0_VECTOR_DB_USER: 'test-user',
    MEM0_VECTOR_DB_PASSWORD: 'test-password',
    MEM0_VECTOR_DB_NAME: 'test-db',
    MEM0_VECTOR_STORE_COLLECTION: 'test-v3-collection',
    MEM0_LLM_MODEL: 'test-llm',
    MEM0_LLM_BASE_URL: 'http://llm.invalid',
    MEM0_BACKEND_TIMEOUT_MS: '1000',
    ...overrides
  };
}

function fakeAdapter(Memory, options = {}) {
  let loads = 0;
  const adapter = createBackendAdapter({
    kind: 'mem0-oss',
    env: configuredEnv(options.env),
    installProcessHooks: false,
    loadMem0Oss: async () => {
      loads += 1;
      return { Memory };
    }
  });
  return { adapter, loads: () => loads };
}

test('disabled and unconfigured backends never load the Mem0 SDK', async () => {
  let loads = 0;
  const loadMem0Oss = async () => {
    loads += 1;
    throw new Error('SDK must stay lazy');
  };
  const disabled = createBackendAdapter({ kind: 'disabled', env: {}, loadMem0Oss });
  await assert.rejects(disabled.search({ backendUserId: 'user-1', query: 'x' }), /backend_not_configured/);

  const unconfigured = createBackendAdapter({
    kind: 'mem0-oss',
    env: {},
    loadMem0Oss,
    installProcessHooks: false
  });
  assert.equal(unconfigured.configured, false);
  await assert.rejects(unconfigured.search({ backendUserId: 'user-1', query: 'x' }), /mem0_oss_backend_unconfigured/);
  assert.equal(loads, 0);
});

test('Mem0 typed settings are strict and bounded before configured state is evaluated', () => {
  for (const [name, value] of [
    ['MEM0_EMBEDDING_DIMS', 'NaN'],
    ['MEM0_EMBEDDING_DIMS', '7'],
    ['MEM0_VECTOR_DB_PORT', '65536'],
    ['MEM0_BACKEND_TIMEOUT_MS', '0'],
    ['MEM0_VECTOR_STORE_HNSW', 'sometimes'],
    ['MEM0_VECTOR_STORE_DISKANN', 'yes']
  ]) {
    assert.throws(
      () => createBackendAdapter({ kind: 'mem0-oss', env: { [name]: value }, installProcessHooks: false }),
      new RegExp(`invalid_environment:${name}`)
    );
  }
});

test('Mem0 v3 search and blank-query getAll use exact filters and normalize identities', async () => {
  const calls = [];
  class FakeMemory {
    async search(query, options) {
      calls.push({ method: 'search', query, options });
      return {
        results: [
          {
            id: 'snake', memory: 'snake memory', metadata: { source: 'v3' }, score: 0,
            user_id: 'user-snake', agent_id: 'agent-snake', run_id: 'run-snake',
            created_at: '2026-07-11T12:00:00Z', updated_at: '2026-07-11T13:00:00Z'
          },
          {
            id: 'camel', memory: 'camel memory',
            userId: 'user-camel', agentId: 'agent-camel', runId: 'run-camel',
            createdAt: '2026-07-11T14:00:00Z', updatedAt: '2026-07-11T15:00:00Z'
          }
        ]
      };
    }

    async getAll(options) {
      calls.push({ method: 'getAll', options });
      return { results: [{ id: 'all', memory: 'all memory', user_id: 'scope-user' }] };
    }
  }

  const { adapter, loads } = fakeAdapter(FakeMemory);
  const searched = await adapter.search({ backendUserId: 'scope-user', query: '  appointment  ' });
  const listed = await adapter.search({ backendUserId: 'scope-user', query: '   ' });

  assert.deepEqual(calls, [
    {
      method: 'search',
      query: 'appointment',
      options: { filters: { user_id: 'scope-user' }, topK: 20, threshold: 0 }
    },
    {
      method: 'getAll',
      options: { filters: { user_id: 'scope-user' }, topK: 20 }
    }
  ]);
  assert.equal(loads(), 1);
  assert.deepEqual(
    searched.items.map(({ id, userId, agentId, runId, createdAt, updatedAt, score }) => ({ id, userId, agentId, runId, createdAt, updatedAt, score })),
    [
      {
        id: 'snake', userId: 'user-snake', agentId: 'agent-snake', runId: 'run-snake',
        createdAt: '2026-07-11T12:00:00Z', updatedAt: '2026-07-11T13:00:00Z', score: 0
      },
      {
        id: 'camel', userId: 'user-camel', agentId: 'agent-camel', runId: 'run-camel',
        createdAt: '2026-07-11T14:00:00Z', updatedAt: '2026-07-11T15:00:00Z', score: undefined
      }
    ]
  );
  assert.equal(searched.items[0].user_id, undefined);
  assert.equal(listed.items[0].userId, 'scope-user');
  assert.equal(searched.source, 'mem0-oss-vector-search');
  assert.equal(listed.source, 'mem0-oss-get-all');
});

test('Mem0 adapter shares one instance and recreates it once for a connection retry', async () => {
  const instances = [];
  const calls = [];
  let closes = 0;
  class FakeMemory {
    constructor(config) {
      this.number = instances.length + 1;
      this.config = config;
      this.vectorStore = { close: async () => { closes += 1; } };
      instances.push(this);
    }

    async search(query, options) {
      calls.push({ instance: this.number, query, options });
      if (this.number === 1 && query === 'retry') throw new Error('ECONNRESET');
      return { results: [{ id: `${this.number}-${query}`, memory: query, user_id: options.filters.user_id }] };
    }
  }

  const { adapter, loads } = fakeAdapter(FakeMemory);
  await adapter.search({ backendUserId: 'shared-user', query: 'first' });
  await adapter.search({ backendUserId: 'shared-user', query: 'second' });
  const retried = await adapter.search({ backendUserId: 'shared-user', query: 'retry' });

  assert.equal(loads(), 1);
  assert.equal(instances.length, 2);
  assert.equal(closes, 1);
  assert.deepEqual(calls.map(({ instance, query }) => ({ instance, query })), [
    { instance: 1, query: 'first' },
    { instance: 1, query: 'second' },
    { instance: 1, query: 'retry' },
    { instance: 2, query: 'retry' }
  ]);
  assert.equal(retried.items[0].id, '2-retry');
});

test('internal Mem0 add never retries a connection failure', async () => {
  const instances = [];
  let addCalls = 0;
  class FakeMemory {
    constructor() { instances.push(this); }
    async add() { addCalls += 1; throw new Error('ECONNRESET'); }
  }
  const { adapter } = fakeAdapter(FakeMemory);
  await assert.rejects(
    adapter.add({ backendUserId: 'scope-user', text: 'must not replay', metadata: {}, infer: false }),
    /ECONNRESET/
  );
  assert.equal(addCalls, 1);
  assert.equal(instances.length, 1);
});

test('installed Mem0 package exposes the pinned public OSS entrypoint', async () => {
  const packageJson = JSON.parse(fs.readFileSync(path.resolve('node_modules/mem0ai/package.json'), 'utf8'));
  assert.equal(packageJson.version, '3.0.13');
  assert.ok(packageJson.exports?.['./oss']);
  const published = await import('mem0ai/oss');
  assert.equal(typeof published.Memory, 'function');
});
