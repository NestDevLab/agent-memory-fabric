import path from 'node:path';

function envInteger(env, name, fallback, { min, max }) {
  const raw = env[name];
  if (raw == null || raw === '') return fallback;
  if (!/^\d+$/.test(String(raw))) throw new Error(`invalid_environment:${name}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`invalid_environment:${name}`);
  return value;
}

function envBoolean(env, name, fallback) {
  const raw = env[name];
  if (raw == null || raw === '') return fallback;
  const normalized = String(raw).trim().toLowerCase();
  if (['true', '1'].includes(normalized)) return true;
  if (['false', '0'].includes(normalized)) return false;
  throw new Error(`invalid_environment:${name}`);
}

async function loadPublicMem0Oss() {
  return import('mem0ai/oss');
}

function buildLegacyOpenmemoryAdapter(env = process.env) {
  const baseUrl = env.LEGACY_OPENMEMORY_BASE_URL;

  async function getJson(url) {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch {}
    if (!res.ok) {
      const err = new Error(`backend_http_${res.status}`);
      err.status = res.status;
      err.body = data ?? text;
      throw err;
    }
    return data;
  }

  return {
    kind: 'legacy-openmemory-http',
    configured: Boolean(baseUrl),
    async search({ backendUserId, query }) {
      if (!baseUrl) throw new Error('legacy_backend_unconfigured');
      const url = new URL('/api/v1/memories/', baseUrl);
      url.searchParams.set('user_id', backendUserId);
      if (query) url.searchParams.set('search_query', query);
      const data = await getJson(url);
      return { items: data?.items || [], total: data?.total || 0, source: 'legacy-openmemory-http' };
    },
    async add() {
      throw new Error('legacy_backend_add_not_supported');
    }
  };
}

function buildMem0OssAdapter({ env = process.env, loadMem0Oss = loadPublicMem0Oss, installProcessHooks = true } = {}) {
  let memoryConstructorPromise = null;
  let sharedMemoryPromise = null;
  let shutdownHookInstalled = false;
  let operationQueue = Promise.resolve();

  // Validate every typed value before deciding whether the adapter is configured.
  // A partially configured backend must not hide malformed production settings.
  const embeddingDims = envInteger(env, 'MEM0_EMBEDDING_DIMS', 768, { min: 8, max: 65536 });
  const vectorDbPort = envInteger(env, 'MEM0_VECTOR_DB_PORT', 5432, { min: 1, max: 65535 });
  const backendTimeoutMs = envInteger(env, 'MEM0_BACKEND_TIMEOUT_MS', 20000, { min: 100, max: 120000 });
  const vectorHnsw = envBoolean(env, 'MEM0_VECTOR_STORE_HNSW', true);
  const vectorDiskann = envBoolean(env, 'MEM0_VECTOR_STORE_DISKANN', false);

  const config = {
    version: 'v1.1',
    embedder: {
      provider: 'ollama',
      config: {
        model: env.MEM0_EMBEDDER_MODEL,
        baseURL: env.MEM0_EMBEDDER_BASE_URL,
        embeddingDims
      }
    },
    vectorStore: {
      provider: 'pgvector',
      config: {
        host: env.MEM0_VECTOR_DB_HOST,
        port: vectorDbPort,
        user: env.MEM0_VECTOR_DB_USER,
        password: env.MEM0_VECTOR_DB_PASSWORD,
        dbname: env.MEM0_VECTOR_DB_NAME,
        collectionName: env.MEM0_VECTOR_STORE_COLLECTION,
        embeddingModelDims: embeddingDims,
        hnsw: vectorHnsw,
        diskann: vectorDiskann
      }
    },
    llm: {
      provider: 'ollama',
      config: {
        model: env.MEM0_LLM_MODEL,
        baseURL: env.MEM0_LLM_BASE_URL
      }
    },
    historyStore: {
      provider: 'sqlite',
      config: {
        historyDbPath: env.MEM0_HISTORY_DB_PATH || path.resolve(process.cwd(), 'var/memory-history.db')
      }
    }
  };

  const configured = Boolean(
    config.embedder.config.model &&
    config.embedder.config.baseURL &&
    config.vectorStore.config.host &&
    config.vectorStore.config.user &&
    config.vectorStore.config.password &&
    config.vectorStore.config.dbname &&
    config.vectorStore.config.collectionName &&
    config.llm.config.model &&
    config.llm.config.baseURL
  );

  function isConnectionScopedError(error) {
    const text = String(error?.message || error || '').toLowerCase();
    return [
      'connection terminated unexpectedly',
      'terminating connection',
      'client has encountered a connection error',
      'connection ended unexpectedly',
      'econnreset',
      'econnrefused',
      '57p01',
      '57p02',
      '08006',
      '08003'
    ].some((needle) => text.includes(needle));
  }

  async function closeMemory(memory) {
    if (!memory) return;
    const closeTargets = [
      memory?.vectorStore,
      memory?.db,
      memory?.historyStore,
      memory?.graphMemory
    ];

    for (const target of closeTargets) {
      if (typeof target?.close !== 'function') continue;
      try {
        await target.close();
      } catch {}
    }
  }

  function installShutdownHook() {
    if (!installProcessHooks || shutdownHookInstalled) return;
    shutdownHookInstalled = true;

    const cleanup = async () => {
      if (!sharedMemoryPromise) return;
      try {
        const memory = await sharedMemoryPromise;
        await closeMemory(memory);
      } catch {}
    };

    process.once('SIGINT', () => {
      cleanup().finally(() => process.exit(130));
    });
    process.once('SIGTERM', () => {
      cleanup().finally(() => process.exit(143));
    });
    process.once('beforeExit', () => {
      void cleanup();
    });
  }

  async function getMemoryConstructor() {
    if (!memoryConstructorPromise) {
      const currentPromise = Promise.resolve()
        .then(() => loadMem0Oss())
        .then((module) => {
          const Memory = module?.Memory ?? module?.default?.Memory ?? module?.default;
          if (typeof Memory !== 'function') throw new Error('mem0_oss_memory_export_missing');
          return Memory;
        });
      memoryConstructorPromise = currentPromise;
      currentPromise.catch(() => {
        if (memoryConstructorPromise === currentPromise) memoryConstructorPromise = null;
      });
    }
    return memoryConstructorPromise;
  }

  async function createMemory() {
    const Memory = await getMemoryConstructor();
    return new Memory(config);
  }

  async function getMemory({ forceRefresh = false } = {}) {
    if (!configured) throw new Error('mem0_oss_backend_unconfigured');
    installShutdownHook();

    if (!sharedMemoryPromise || forceRefresh) {
      const currentPromise = Promise.resolve().then(() => createMemory());
      sharedMemoryPromise = currentPromise;
      currentPromise.catch(() => {
        if (sharedMemoryPromise === currentPromise) sharedMemoryPromise = null;
      });
    }

    return sharedMemoryPromise;
  }

  function queueSharedMemoryOperation(operation) {
    const run = operationQueue.catch(() => {}).then(operation);
    operationQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  async function withSharedMemory(operation, { retryConnection = true } = {}) {
    return queueSharedMemoryOperation(async () => {
      let memory = await getMemory();
      try {
        return await withBackendTimeout(() => operation(memory));
      } catch (error) {
        if (!retryConnection || (!isConnectionScopedError(error) && String(error?.message || '') !== 'backend_timeout')) throw error;
        await closeMemory(memory);
        memory = await getMemory({ forceRefresh: true });
        return await withBackendTimeout(() => operation(memory));
      }
    });
  }

  async function withBackendTimeout(operation) {
    let timer;
    try {
      return await Promise.race([
        operation(),
        new Promise((_, reject) => {
          const err = new Error('backend_timeout');
          err.status = 504;
          timer = setTimeout(() => reject(err), backendTimeoutMs);
          timer.unref?.();
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  function normalizeItems(items = []) {
    return items.map((item) => ({
      id: item.id,
      memory: item.memory,
      hash: item.hash,
      metadata: item.metadata || {},
      score: item.score,
      createdAt: item.createdAt ?? item.created_at,
      updatedAt: item.updatedAt ?? item.updated_at,
      userId: item.userId ?? item.user_id,
      agentId: item.agentId ?? item.agent_id,
      runId: item.runId ?? item.run_id
    }));
  }

  function normalizeResults(data) {
    if (Array.isArray(data)) return normalizeItems(data);
    return normalizeItems(Array.isArray(data?.results) ? data.results : []);
  }

  return {
    kind: 'mem0-oss',
    configured,
    async search({ backendUserId, query }) {
      if (!configured) throw new Error('mem0_oss_backend_unconfigured');
      const normalizedQuery = String(query || '').trim();

      return withSharedMemory(async (memory) => {
        if (normalizedQuery) {
          const data = await memory.search(normalizedQuery, {
            filters: { user_id: backendUserId },
            topK: 20,
            threshold: 0
          });
          const items = normalizeResults(data);
          return {
            items,
            total: items.length,
            source: 'mem0-oss-vector-search'
          };
        }

        const data = await memory.getAll({ filters: { user_id: backendUserId }, topK: 20 });
        const items = normalizeResults(data);
        return {
          items,
          total: items.length,
          source: 'mem0-oss-get-all'
        };
      });
    },
    // Internal compatibility hook only. Canonical writes must use the Fabric proposal queue.
    async add({ backendUserId, text, metadata = {}, infer = false }) {
      if (!configured) throw new Error('mem0_oss_backend_unconfigured');
      if (!text || !String(text).trim()) throw new Error('memory_text_required');
      return withSharedMemory(async (memory) => {
        const result = await memory.add(String(text), {
          userId: backendUserId,
          infer,
          metadata
        });
        return {
          results: result?.results || [],
          relations: result?.relations || [],
          source: 'mem0-oss'
        };
      }, { retryConnection: false });
    }
  };
}

export function createBackendAdapter(options = {}) {
  const env = options.env ?? process.env;
  const kind = options.kind ?? env.MEM0_BACKEND_KIND ?? 'unconfigured';
  if (kind === 'legacy-openmemory-http') return buildLegacyOpenmemoryAdapter(env);
  if (kind === 'mem0-oss') return buildMem0OssAdapter({
    env,
    loadMem0Oss: options.loadMem0Oss ?? loadPublicMem0Oss,
    installProcessHooks: options.installProcessHooks ?? true
  });
  return {
    kind,
    configured: false,
    async search() {
      throw new Error('backend_not_configured');
    }
  };
}

export { buildMem0OssAdapter };
