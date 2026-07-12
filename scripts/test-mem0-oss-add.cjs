const path = require('path');
const { Memory } = require('mem0ai/oss');

async function buildMemory() {
  return new Memory({
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
        historyDbPath: path.resolve(__dirname, '../var/memory-history.db')
      }
    },
    version: 'v1.1'
  });
}

async function main() {
  const text = process.argv[2] || 'test memory add';
  const userId = process.argv[3] || 'openmemory';
  const infer = String(process.argv[4] || 'false') === 'true';
  const memory = await buildMemory();
  const result = await memory.add(text, {
    userId,
    infer,
    metadata: {
      source: 'local-test',
      kind: 'test'
    }
  });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
