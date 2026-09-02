import pg from 'pg';
const { Pool } = pg;

const SCHEMA = 'agent_memory_fabric';
const TABLE = 'document_links_v1';

function error(code, status = 500) {
  const e = new Error(code); e.status = status; return e;
}

export class LinkGraph {
  constructor({ pool, connectionString, ssl, maxDepth = 1, maxExpansion = 20,
    poolFactory = config => new Pool(config), max = 4, queryTimeoutMs = 15000 } = {}) {
    if (!pool && !connectionString) throw error('link_graph_database_url_required');
    this.configured = true;
    this.maxDepth = maxDepth;
    this.maxExpansion = maxExpansion;
    this.pool = pool || poolFactory({ connectionString, ssl, max, query_timeout: queryTimeoutMs, statement_timeout: queryTimeoutMs });
    this.pool.on?.('error', () => {});
  }

  async ensureSchema() {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS ${SCHEMA}.${TABLE} (
      src_document_id text NOT NULL,
      src_vault_id    text NOT NULL,
      src_path        text NOT NULL,
      target_raw      text NOT NULL,
      target_path     text,
      dst_document_id text,
      alias           text,
      updated_at      timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (src_document_id, target_raw)
    )`);
    await this.pool.query(`CREATE INDEX IF NOT EXISTS ${TABLE}_dst_idx ON ${SCHEMA}.${TABLE} (dst_document_id)`);
    await this.pool.query(`CREATE INDEX IF NOT EXISTS ${TABLE}_vault_idx ON ${SCHEMA}.${TABLE} (src_vault_id)`);
  }

  async upsertEdgesForDocument({ srcDocumentId, srcVaultId, srcPath, targetPath, dstDocumentId, targetRaw, alias }) {
    await this.pool.query(
      `INSERT INTO ${SCHEMA}.${TABLE} (src_document_id, src_vault_id, src_path, target_raw, target_path, dst_document_id, alias, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7, now())
       ON CONFLICT (src_document_id, target_raw) DO UPDATE
         SET src_vault_id=EXCLUDED.src_vault_id, src_path=EXCLUDED.src_path,
             target_path=EXCLUDED.target_path, dst_document_id=EXCLUDED.dst_document_id,
             alias=EXCLUDED.alias, updated_at=now()`,
      [srcDocumentId, srcVaultId, srcPath, targetRaw, targetPath ?? null, dstDocumentId ?? null, alias ?? null]
    );
  }

  async replaceDocumentEdges(srcDocumentId, srcVaultId, srcPath, edges) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`DELETE FROM ${SCHEMA}.${TABLE} WHERE src_document_id=$1`, [srcDocumentId]);
      for (const e of edges) {
        await client.query(
          `INSERT INTO ${SCHEMA}.${TABLE} (src_document_id, src_vault_id, src_path, target_raw, target_path, dst_document_id, alias, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7, now())
           ON CONFLICT (src_document_id, target_raw) DO UPDATE
             SET src_vault_id=EXCLUDED.src_vault_id, src_path=EXCLUDED.src_path,
                 target_path=EXCLUDED.target_path, dst_document_id=EXCLUDED.dst_document_id,
                 alias=EXCLUDED.alias, updated_at=now()`,
          [srcDocumentId, srcVaultId, srcPath, e.targetRaw, e.targetPath ?? null, e.dstDocumentId ?? null, e.alias ?? null]
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch {}
      throw err;
    } finally { client.release(); }
  }

  async pruneDocuments(keepDocumentIds) {
    await this.pool.query(`DELETE FROM ${SCHEMA}.${TABLE} WHERE NOT (src_document_id = ANY($1::text[]))`, [keepDocumentIds]);
  }

  async listSrcDocumentIds() {
    const result = await this.pool.query(`SELECT DISTINCT src_document_id FROM ${SCHEMA}.${TABLE} ORDER BY src_document_id`);
    return result.rows.map(r => r.src_document_id);
  }

  async neighbors({ documentId, vaults, depth = this.maxDepth }) {
    const bounded = Math.max(1, Math.min(4, Number(depth) || 1));
    const allowed = [...new Set((Array.isArray(vaults) ? vaults : []).map(String))];
    if (!allowed.length) return [];
    const result = await this.pool.query(
      `WITH RECURSIVE walk(document_id, distance, path) AS (
         SELECT dst_document_id, 1, ARRAY[$1::text, dst_document_id]
           FROM ${SCHEMA}.${TABLE}
          WHERE src_document_id=$1 AND src_vault_id=ANY($2::text[]) AND dst_document_id IS NOT NULL
         UNION ALL
         SELECT e.dst_document_id, w.distance+1, w.path || e.dst_document_id
           FROM ${SCHEMA}.${TABLE} e
           JOIN walk w ON e.src_document_id=w.document_id
          WHERE e.src_vault_id=ANY($2::text[]) AND e.dst_document_id IS NOT NULL
            AND w.distance < $3 AND NOT (e.dst_document_id = ANY(w.path))
       )
       SELECT document_id, MIN(distance) AS distance
         FROM walk WHERE document_id <> $1
        GROUP BY document_id ORDER BY distance, document_id`,
      [documentId, allowed, bounded]
    );
    return result.rows.map(r => ({ documentId: r.document_id, distance: Number(r.distance) }));
  }

  async backlinks({ documentId, vaults }) {
    const allowed = [...new Set((Array.isArray(vaults) ? vaults : []).map(String))];
    if (!allowed.length) return [];
    const result = await this.pool.query(
      `SELECT DISTINCT src_document_id FROM ${SCHEMA}.${TABLE}
        WHERE dst_document_id=$1 AND src_vault_id=ANY($2::text[])
        ORDER BY src_document_id`,
      [documentId, allowed]
    );
    return result.rows.map(r => ({ documentId: r.src_document_id }));
  }

  async related({ documentId, vaults, limit = 10 }) {
    const allowed = [...new Set((Array.isArray(vaults) ? vaults : []).map(String))];
    if (!allowed.length) return [];
    const bounded = Math.max(1, Math.min(100, Number(limit) || 10));
    const result = await this.pool.query(
      `WITH mine AS (
         SELECT dst_document_id FROM ${SCHEMA}.${TABLE}
          WHERE src_document_id=$1 AND src_vault_id=ANY($2::text[]) AND dst_document_id IS NOT NULL
       )
       SELECT e.src_document_id, COUNT(*)::int AS shared
         FROM ${SCHEMA}.${TABLE} e JOIN mine ON e.dst_document_id=mine.dst_document_id
        WHERE e.src_vault_id=ANY($2::text[]) AND e.src_document_id <> $1
        GROUP BY e.src_document_id ORDER BY shared DESC, e.src_document_id LIMIT $3`,
      [documentId, allowed, bounded]
    );
    return result.rows.map(r => ({ documentId: r.src_document_id, shared: r.shared }));
  }

  async shortestPath({ fromId, toId, vaults, maxDepth = 4 }) {
    const allowed = [...new Set((Array.isArray(vaults) ? vaults : []).map(String))];
    if (!allowed.length) return [];
    const bounded = Math.max(1, Math.min(4, Number(maxDepth) || 4));
    const result = await this.pool.query(
      `WITH RECURSIVE undirected(a, b) AS (
         SELECT src_document_id, dst_document_id FROM ${SCHEMA}.${TABLE}
           WHERE src_vault_id=ANY($3::text[]) AND dst_document_id IS NOT NULL
         UNION ALL
         SELECT dst_document_id, src_document_id FROM ${SCHEMA}.${TABLE}
           WHERE src_vault_id=ANY($3::text[]) AND dst_document_id IS NOT NULL
       ),
       bfs(node, path, depth) AS (
         SELECT $1::text, ARRAY[$1::text], 0
         UNION ALL
         SELECT u.b, w.path || u.b, w.depth+1
           FROM undirected u JOIN bfs w ON u.a=w.node
          WHERE w.depth < $4 AND NOT (u.b = ANY(w.path))
       )
       SELECT path FROM bfs WHERE node=$2 ORDER BY depth LIMIT 1`,
      [fromId, toId, allowed, bounded]
    );
    return result.rows[0] ? result.rows[0].path : [];
  }

  async expand({ seedDocumentIds, vaults, limit }) {
    const seeds = [...new Set((Array.isArray(seedDocumentIds) ? seedDocumentIds : []).map(String))];
    if (!seeds.length) return [];
    const cap = Math.max(0, Math.min(Number(limit) || this.maxExpansion, this.maxExpansion));
    if (!cap) return [];
    const seen = new Set(seeds);
    const out = [];
    for (const seed of seeds) {
      const hits = await this.neighbors({ documentId: seed, vaults, depth: this.maxDepth });
      for (const hit of hits) {
        if (seen.has(hit.documentId)) continue;
        seen.add(hit.documentId);
        out.push({ documentId: hit.documentId, source: 'graph', distance: hit.distance, seed });
        if (out.length >= cap) return out;
      }
    }
    return out;
  }

  async close() { if (this._closed) return; this._closed = true; await this.pool.end?.(); }
}

export function createUnconfiguredLinkGraph() {
  return {
    configured: false,
    async neighbors() { return []; },
    async backlinks() { return []; },
    async related() { return []; },
    async shortestPath() { return []; },
    async expand() { return []; },
    async close() {}
  };
}

export function createLinkGraphFromEnv(env = process.env) {
  if (String(env.AMF_LINK_GRAPH_ENABLED || '').trim() !== 'true') return createUnconfiguredLinkGraph();
  if (String(env.AMF_LINK_GRAPH_ENGINE || 'postgres').trim() === 'falkor') return createUnconfiguredLinkGraph();
  const connectionString = String(env.AMF_CATALOG_DATABASE_URL || '').trim();
  if (!connectionString) throw error('link_graph_database_url_required');
  return new LinkGraph({
    connectionString,
    maxDepth: Math.max(1, Math.min(4, Number(env.AMF_LINK_GRAPH_MAX_DEPTH) || 1)),
    maxExpansion: Math.max(1, Math.min(200, Number(env.AMF_LINK_GRAPH_MAX_EXPANSION) || 20))
  });
}
