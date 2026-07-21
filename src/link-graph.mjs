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

  async close() { if (this._closed) return; this._closed = true; await this.pool.end?.(); }
}
