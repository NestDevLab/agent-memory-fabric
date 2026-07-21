#!/usr/bin/env node
import pg from 'pg';
const { Pool } = pg;
import { extractWikilinks } from '../src/link-parser.mjs';
import { LinkGraph } from '../src/link-graph.mjs';

export function resolveTargets({ links, pathToDocId }) {
  return links.map(({ target, alias }) => {
    const direct = pathToDocId.has(target) ? target : (pathToDocId.has(`${target}.md`) ? `${target}.md` : null);
    return {
      targetRaw: target,
      alias: alias ?? null,
      targetPath: direct,
      dstDocumentId: direct ? pathToDocId.get(direct) : null
    };
  });
}

async function main() {
  const connectionString = String(process.env.AMF_CATALOG_DATABASE_URL || '').trim();
  if (!connectionString) { process.stderr.write(`${JSON.stringify({ ok: false, error: 'catalog_database_url_required' })}\n`); process.exitCode = 1; return; }
  const pool = new Pool({ connectionString, max: 4 });
  const graph = new LinkGraph({ pool });
  try {
    await graph.ensureSchema();
    const rows = (await pool.query(`SELECT r.document_id, r.vault_id, r.path, r.text_content
      FROM agent_memory_fabric.document_heads_v1 h
      JOIN agent_memory_fabric.document_revisions_v1 r ON r.document_id=h.document_id AND r.revision=h.revision
      WHERE h.tombstone=false`)).rows;
    const pathToDocId = new Map(rows.map(r => [r.path, r.document_id]));
    let docs = 0, edges = 0, failed = 0;
    const liveIds = [];
    for (const r of rows) {
      liveIds.push(r.document_id);
      try {
        const links = extractWikilinks(r.text_content || '');
        const resolved = resolveTargets({ links, pathToDocId });
        await graph.replaceDocumentEdges(r.document_id, r.vault_id, r.path, resolved);
        docs += 1; edges += resolved.length;
      } catch { failed += 1; }
    }
    await graph.pruneDocuments(liveIds);
    process.stdout.write(`${JSON.stringify({ ok: true, docs, edges, failed })}\n`);
  } finally { await graph.close(); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    const code = String(err?.message || 'graph_reindex_failed');
    process.stderr.write(`${JSON.stringify({ ok: false, error: /^[a-z0-9_]{1,128}$/.test(code) ? code : 'graph_reindex_failed' })}\n`);
    process.exitCode = 1;
  });
}
