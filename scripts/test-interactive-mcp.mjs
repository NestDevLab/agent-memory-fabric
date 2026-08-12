import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildContextRequest } from '../src/access-contract.mjs';
import { ContextTokenVerifier } from '../src/context-token.mjs';
import { createInteractiveMcpBridge, loadInteractiveMcpHandoff } from '../src/operator/interactive-mcp.mjs';
import { INTERACTIVE_MCP_TOOLS, provisionInteractiveMcp } from '../src/operator/interactive-mcp-provisioning.mjs';

const NOW = new Date('2026-08-10T12:00:00.000Z');
const READ_SCOPES = ['*'];
const PROPOSE_SCOPES = ['person:joseph'];
const READ_VAULTS = ['*'];
const WRITE_VAULTS = ['vault:synthetic'];
function privateJson(filePath, value) { fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600); }
function asRoot(operation) { const original = process.geteuid; process.geteuid = () => 0; try { return operation(); } finally { process.geteuid = original; } }
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-interactive-mcp-'));
  const auth = path.join(root, 'auth'); const config = path.join(root, 'config'); const backupRoot = path.join(root, 'backups'); const handoffs = path.join(root, 'handoffs');
  for (const directory of [auth, config, backupRoot, handoffs]) fs.mkdirSync(directory, { mode: 0o700 });
  const authRegistryPath = path.join(auth, 'registry.json'); const policyPath = path.join(config, 'policy.json'); const contextKeyRingPath = path.join(config, 'ring.json');
  privateJson(authRegistryPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'), active: true, actor: 'existing', mode: 'scoped', allowedScopes: ['domain:existing'], permissions: ['memory:search'] }] });
  privateJson(policyPath, { actors: { existing: { mode: 'scoped', allowedScopes: ['domain:existing'] } }, scopes: {
    'domain:existing': { backendUserId: 'existing' }, 'domain:synthetic': { backendUserId: 'synthetic' },
    'person:joseph': { backendUserId: 'joseph' }, 'shared:global': { backendUserId: 'shared' }
  }, vaults: { 'vault:synthetic': { canonicalId: 'vault:synthetic' } } });
  privateJson(contextKeyRingPath, { currentKeyVersion: 'ctx-existing-v1', keys: { 'ctx-existing-v1': crypto.randomBytes(32).toString('base64') } });
  const options = { runtime: 'codex', authRegistryPath, policyPath, contextKeyRingPath, handoffPath: path.join(handoffs, 'codex'), backupRoot, backendUserId: 'unused', serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid, policyRevision: 'policy-v1', endpoint: 'https://amf.example.test/', readScopes: READ_SCOPES, proposeScopes: PROPOSE_SCOPES, readVaults: READ_VAULTS, writeVaults: WRITE_VAULTS, tools: INTERACTIVE_MCP_TOOLS, clock: () => NOW };
  asRoot(() => provisionInteractiveMcp(options));
  return { root, options };
}
async function fakeFabric() {
  const calls = []; const server = http.createServer(async (request, response) => { let raw = ''; for await (const chunk of request) raw += chunk; calls.push({ method: request.method, url: request.url, headers: request.headers, body: raw ? JSON.parse(raw) : null }); response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ ok: true, data: { ok: true } })); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); const { port } = server.address();
  return { calls, fetchImpl: (input, init) => { const url = new URL(String(input)); return fetch(`http://127.0.0.1:${port}${url.pathname}${url.search}`, init); }, close: () => new Promise(resolve => server.close(resolve)) };
}

test('provisions operation-specific MCP grants and keeps legacy fields write-narrow', () => {
  const { root, options } = fixture();
  try {
    const handoff = loadInteractiveMcpHandoff(options.handoffPath);
    assert.equal(handoff.actor, 'client:mcp:codex'); assert.deepEqual(handoff.readScopes, READ_SCOPES); assert.deepEqual(handoff.proposeScopes, PROPOSE_SCOPES);
    assert.deepEqual(handoff.readVaults, READ_VAULTS); assert.deepEqual(handoff.writeVaults, WRITE_VAULTS); assert.deepEqual(handoff.tools, INTERACTIVE_MCP_TOOLS);
    const row = JSON.parse(fs.readFileSync(options.authRegistryPath, 'utf8')).rows.find(item => item.actor === handoff.actor);
    assert.equal(row.mode, 'scoped'); assert.deepEqual(row.allowedScopes, PROPOSE_SCOPES); assert.deepEqual(row.allowedVaults, WRITE_VAULTS);
    assert.deepEqual(row.readScopes, READ_SCOPES); assert.deepEqual(row.proposeScopes, PROPOSE_SCOPES); assert.deepEqual(row.readVaults, READ_VAULTS); assert.deepEqual(row.writeVaults, WRITE_VAULTS);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('rejects wildcard writes, unknown scopes, incomplete grants, and asymmetric tool surfaces before writing', () => {
  const { root, options } = fixture();
  try {
    const next = { ...options, handoffPath: `${options.handoffPath}-other`, dryRun: true };
    assert.throws(() => provisionInteractiveMcp({ ...next, proposeScopes: ['*'] }), /interactive_mcp_propose_scope_invalid/);
    assert.throws(() => provisionInteractiveMcp({ ...next, writeVaults: ['*'] }), /interactive_mcp_write_vault_invalid/);
    assert.throws(() => provisionInteractiveMcp({ ...next, readScopes: ['domain:missing'] }), /recall_consumer_scope_unregistered/);
    assert.throws(() => provisionInteractiveMcp({ ...next, writeVaults: ['vault:missing'] }), /recall_consumer_vault_unregistered/);
    assert.throws(() => provisionInteractiveMcp({ ...next, readVaults: [] }), /interactive_mcp_read_vault_invalid/);
    assert.throws(() => provisionInteractiveMcp({ ...next, tools: INTERACTIVE_MCP_TOOLS.slice(0, -1) }), /interactive_mcp_tool_invalid/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the bridge exposes the complete common MCP surface and forwards only operation grants', async () => {
  const { root, options } = fixture(); const fabric = await fakeFabric();
  try {
    const handoff = loadInteractiveMcpHandoff(options.handoffPath); const bridge = createInteractiveMcpBridge({ handoff, fetchImpl: fabric.fetchImpl, clock: () => NOW.getTime(), randomBytes: size => Buffer.alloc(size, 7) });
    const listed = await bridge.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' }); assert.deepEqual(listed.result.tools.map(tool => tool.name), INTERACTIVE_MCP_TOOLS);
    const memorySearch = await bridge.handleRpc({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'memory_search', arguments: { query: 'synthetic' } } }); assert.equal(memorySearch.error, undefined);
    const search = await bridge.handleRpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'documents_search', arguments: { query: 'synthetic' } } }); assert.equal(search.error, undefined);
    const write = await bridge.handleRpc({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'document_upsert', arguments: { document: { documentId: 'doc:one', vaultId: 'vault:synthetic' }, text: 'synthetic', expectedRevision: 0, idempotencyKey: 'write-1' } } }); assert.equal(write.error, undefined);
    const deniedWrite = await bridge.handleRpc({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'document_upsert', arguments: { document: { documentId: 'doc:two', vaultId: 'vault:other' }, text: 'x', expectedRevision: 0, idempotencyKey: 'write-2' } } }); assert.equal(deniedWrite.error.code, -32602);
    const deniedProposal = await bridge.handleRpc({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'memory_propose', arguments: { record: { scope: { id: 'domain:synthetic' } }, rationale: 'x', idempotencyKey: 'proposal-1' } } }); assert.equal(deniedProposal.error.code, -32602);
    assert.equal(fabric.calls.length, 3); assert.deepEqual(fabric.calls[0].body.scopes, READ_SCOPES); assert.deepEqual(fabric.calls[1].body.vaultIds, READ_VAULTS); assert.equal(fabric.calls[2].url, '/v2/documents/doc:one'); assert.equal(fabric.calls[2].headers['idempotency-key'], 'write-1');
    const verifier = new ContextTokenVerifier({ keyRing: handoff.keyRing, policyRevision: 'policy-v1', clock: () => NOW.getTime() }); const body = fabric.calls[0].body; const context = verifier.verify(body.contextToken, { actor: handoff.actor, purpose: 'conversation_recall', request: buildContextRequest('memory_search', body), contextKeyVersions: ['ctx-mcp-codex-v1'] }); assert.equal(context.canonicalScopes, undefined);
  } finally { await fabric.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
