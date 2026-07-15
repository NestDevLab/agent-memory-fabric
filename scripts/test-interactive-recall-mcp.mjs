import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildContextRequest } from '../src/access-contract.mjs';
import { ContextTokenVerifier } from '../src/context-token.mjs';
import {
  createInteractiveRecallBridge,
  INTERACTIVE_RECALL_HANDOFF_ENV,
  loadInteractiveRecallHandoff
} from '../src/operator/interactive-recall-mcp.mjs';
import { provisionInteractiveRecall } from '../src/operator/interactive-recall-provisioning.mjs';

const FIXED_NOW = new Date('2026-07-15T10:00:00.000Z');

function key() { return crypto.randomBytes(32).toString('base64'); }
function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}

function withEffectiveUid(uid, operation) {
  const original = process.geteuid; process.geteuid = () => uid;
  try { return operation(); } finally { process.geteuid = original; }
}

function fixture(profile = 'codex') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-interactive-mcp-'));
  const authRegistryPath = path.join(root, 'auth-registry.json');
  const policyPath = path.join(root, 'policy.json');
  const contextKeyRingPath = path.join(root, 'context-key-ring.json');
  const backupRoot = path.join(root, 'backups'); const handoffParent = path.join(root, 'handoffs');
  fs.mkdirSync(backupRoot, { mode: 0o700 }); fs.mkdirSync(handoffParent, { mode: 0o700 });
  privateJson(authRegistryPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'),
    active: true, actor: 'existing-actor', mode: 'scoped', allowedScopes: ['domain:existing'], permissions: ['memory:search'] }] });
  privateJson(policyPath, { actors: { 'existing-actor': { mode: 'scoped', allowedScopes: ['domain:existing'] } },
    scopes: { 'domain:existing': { backendUserId: 'existing' } } });
  privateJson(contextKeyRingPath, { currentKeyVersion: 'ctx-existing-v1', keys: { 'ctx-existing-v1': key() } });
  const handoffPath = path.join(handoffParent, profile);
  const options = { profile, authRegistryPath, policyPath, contextKeyRingPath, handoffPath, backupRoot,
    backendUserId: 'openmemory', serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid,
    policyRevision: 'policy-v1', endpoint: 'https://amf.example.test/', clock: () => FIXED_NOW };
  withEffectiveUid(0, () => provisionInteractiveRecall(options));
  return { root, handoffPath };
}

async function fakeFabric() {
  const calls = [];
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    calls.push({ method: request.method, url: request.url, headers: request.headers, body: body ? JSON.parse(body) : null });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ ok: true, data: { path: request.url, method: request.method } }));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  return {
    calls,
    fetchImpl(input, init) {
      const url = new URL(String(input));
      return fetch(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`, init);
    },
    close() { return new Promise(resolve => server.close(resolve)); }
  };
}

function testRandom() {
  let counter = 0;
  return length => Buffer.alloc(length, ++counter);
}

test('the bridge exposes only two tools and forces scope and purpose through the fake Fabric server', async () => {
  const { root, handoffPath } = fixture('codex'); const fabric = await fakeFabric();
  try {
    const handoff = loadInteractiveRecallHandoff(handoffPath);
    const bridge = createInteractiveRecallBridge({ handoff, fetchImpl: fabric.fetchImpl,
      clock: () => FIXED_NOW.getTime(), randomBytes: testRandom() });
    const tools = await bridge.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.deepEqual(tools.result.tools.map(tool => tool.name), ['memory_search', 'memory_read']);
    assert.equal(tools.result.tools.some(tool => /session|proposal|raw|decrypt/.test(tool.name)), false);

    const first = await bridge.handleRpc({ jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'memory_search', arguments: { query: 'today', limit: 3 } } });
    const second = await bridge.handleRpc({ jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'memory_search', arguments: { query: 'today', limit: 3 } } });
    assert.equal(first.error, undefined); assert.equal(second.error, undefined);
    assert.equal(fabric.calls.length, 2);
    for (const call of fabric.calls) {
      assert.equal(call.method, 'POST'); assert.equal(call.url, '/v2/memory/search');
      assert.equal(call.headers.authorization, `Bearer ${handoff.bearer}`);
      assert.deepEqual(call.body.scopes, ['shared:global']); assert.equal(call.body.purpose, 'conversation_recall');
      assert.equal(typeof call.body.contextToken, 'string');
    }
    assert.notEqual(fabric.calls[0].body.contextToken, fabric.calls[1].body.contextToken);
    const verifier = new ContextTokenVerifier({ keyRing: handoff.keyRing, policyRevision: 'policy-v1',
      clock: () => FIXED_NOW.getTime() });
    for (const call of fabric.calls) {
      const request = buildContextRequest('memory_search', call.body);
      const context = verifier.verify(call.body.contextToken, { actor: 'agent:codex',
        purpose: 'conversation_recall', request, contextKeyVersions: ['ctx-codex-v1'] });
      assert.deepEqual(context.canonicalScopes, ['shared:global']);
    }
  } finally { await fabric.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('memory_read uses a header context token and rejected tools never reach Fabric', async () => {
  const { root, handoffPath } = fixture('claude'); const fabric = await fakeFabric();
  try {
    const bridge = createInteractiveRecallBridge({ handoff: loadInteractiveRecallHandoff(handoffPath),
      fetchImpl: fabric.fetchImpl, clock: () => FIXED_NOW.getTime(), randomBytes: testRandom() });
    const rejectedScope = await bridge.handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'memory_search', arguments: { query: 'x', scopes: ['person:joseph'] } } });
    const rejectedTool = await bridge.handleRpc({ jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'memory_propose', arguments: { record: {} } } });
    const rejectedSession = await bridge.handleRpc({ jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'sessions_search', arguments: { query: 'x' } } });
    assert.equal(rejectedScope.error.code, -32602); assert.equal(rejectedTool.error.code, -32601);
    assert.equal(rejectedSession.error.code, -32601); assert.equal(fabric.calls.length, 0);

    const read = await bridge.handleRpc({ jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { name: 'memory_read', arguments: { id: 'memory:1' } } });
    assert.equal(read.error, undefined); assert.equal(fabric.calls.length, 1);
    const call = fabric.calls[0];
    assert.equal(call.method, 'GET'); assert.equal(call.url, '/v2/memory/memory:1?purpose=conversation_recall');
    assert.equal(call.body, null); assert.equal(typeof call.headers['x-amf-context-token'], 'string');
    assert.equal(call.url.includes('contextToken='), false);
  } finally { await fabric.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('the handoff loader requires a private directory and private credential files', () => {
  const { root, handoffPath } = fixture('codex');
  try {
    assert.equal(loadInteractiveRecallHandoff(handoffPath).actor, 'agent:codex');
    fs.chmodSync(path.join(handoffPath, 'bearer.token'), 0o644);
    assert.throws(() => loadInteractiveRecallHandoff(handoffPath), /interactive_recall_handoff_unsafe/);
    fs.chmodSync(path.join(handoffPath, 'bearer.token'), 0o600);
    fs.chmodSync(handoffPath, 0o755);
    assert.throws(() => loadInteractiveRecallHandoff(handoffPath), /interactive_recall_handoff_unsafe/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the stdio launcher accepts only the handoff-directory environment contract', () => {
  const { root, handoffPath } = fixture('codex');
  try {
    const input = `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })}\n`;
    const result = spawnSync(process.execPath, ['scripts/amf-interactive-recall-mcp.mjs'], {
      encoding: 'utf8', input, env: { ...process.env, [INTERACTIVE_RECALL_HANDOFF_ENV]: handoffPath }
    });
    assert.equal(result.status, 0); assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout).result.tools.map(tool => tool.name), ['memory_search', 'memory_read']);
    const rejected = spawnSync(process.execPath, ['scripts/amf-interactive-recall-mcp.mjs', '--handoff', handoffPath], {
      encoding: 'utf8', env: { ...process.env, [INTERACTIVE_RECALL_HANDOFF_ENV]: handoffPath }
    });
    assert.equal(rejected.status, 1); assert.match(rejected.stderr, /interactive_recall_cli_argument_unknown/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
