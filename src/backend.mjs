import path from 'node:path';
import { createRequire } from 'node:module';

function buildLegacyOpenmemoryAdapter() {
  const baseUrl = process.env.LEGACY_OPENMEMORY_BASE_URL;

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

function buildMem0OssAdapter() {
  const require = createRequire(import.meta.url);
  const mem0Path = path.resolve(process.cwd(), 'node_modules/mem0ai/dist/oss/index.js');
  const { Memory } = require(mem0Path);

  const config = {
    version: 'v1.1',
    embedder: {
      provider: 'ollama',
      config: {
        model: process.env.MEM0_EMBEDDER_MODEL,
        baseURL: process.env.MEM0_EMBEDDER_BASE_URL,
        embeddingDims: Number(process.env.MEM0_EMBEDDING_DIMS || '768')
      }
    },
    vectorStore: {
      provider: 'pgvector',
      config: {
        host: process.env.MEM0_VECTOR_DB_HOST,
        port: Number(process.env.MEM0_VECTOR_DB_PORT || '5432'),
        user: process.env.MEM0_VECTOR_DB_USER,
        password: process.env.MEM0_VECTOR_DB_PASSWORD,
        dbname: process.env.MEM0_VECTOR_DB_NAME,
        collectionName: process.env.MEM0_VECTOR_STORE_COLLECTION,
        embeddingModelDims: Number(process.env.MEM0_EMBEDDING_DIMS || '768'),
        hnsw: String(process.env.MEM0_VECTOR_STORE_HNSW || 'true') === 'true',
        diskann: String(process.env.MEM0_VECTOR_STORE_DISKANN || 'false') === 'true'
      }
    },
    llm: {
      provider: 'ollama',
      config: {
        model: process.env.MEM0_LLM_MODEL,
        baseURL: process.env.MEM0_LLM_BASE_URL
      }
    },
    historyStore: {
      provider: 'sqlite',
      config: {
        historyDbPath: process.env.MEM0_HISTORY_DB_PATH || path.resolve(process.cwd(), 'var/memory-history.db')
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

  let memoryInstance = null;
  function getMemory() {
    if (!memoryInstance) memoryInstance = new Memory(config);
    return memoryInstance;
  }

  function normalizeItems(items = []) {
    return items.map((item) => ({
      id: item.id,
      memory: item.memory,
      hash: item.hash,
      metadata: item.metadata || {},
      score: item.score,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      userId: item.userId,
      agentId: item.agentId,
      runId: item.runId
    }));
  }

  return {
    kind: 'mem0-oss',
    configured,
    async search({ backendUserId, query }) {
      if (!configured) throw new Error('mem0_oss_backend_unconfigured');
      const memory = getMemory();
      const normalizedQuery = String(query || '').trim();

      if (normalizedQuery) {
        const data = await memory.search(normalizedQuery, {
          userId: backendUserId,
          limit: 20
        });
        const items = normalizeItems(data?.results || []);
        return {
          items,
          total: items.length,
          source: 'mem0-oss-vector-search'
        };
      }

      const data = await memory.getAll({ userId: backendUserId, limit: 20 });
      const items = normalizeItems(data?.results || []);
      return {
        items,
        total: items.length,
        source: 'mem0-oss-get-all'
      };
    },
    async add({ backendUserId, text, metadata = {}, infer = false }) {
      if (!configured) throw new Error('mem0_oss_backend_unconfigured');
      if (!text || !String(text).trim()) throw new Error('memory_text_required');
      const memory = getMemory();
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
    }
  };
}

export function createBackendAdapter() {
  const kind = process.env.MEM0_BACKEND_KIND || 'unconfigured';
  if (kind === 'legacy-openmemory-http') return buildLegacyOpenmemoryAdapter();
  if (kind === 'mem0-oss') return buildMem0OssAdapter();
  return {
    kind,
    configured: false,
    async search() {
      throw new Error('backend_not_configured');
    }
  };
}
