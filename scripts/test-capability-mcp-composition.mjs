import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createCapabilityMcpComposition } from '../src/capability-mcp-composition.mjs';

const grant = Object.freeze({ actor: Object.freeze({ id: 'actor_synthetic' }) });
const projection = Object.freeze({ actor: 'actor_synthetic', allowedScopes: Object.freeze(['team:synthetic']), documentVaultIds: Object.freeze(['vault_synthetic']), sessionOwnerActors: Object.freeze(['actor_synthetic']), context: Object.freeze({ conversationKind: 'direct', contextTags: Object.freeze({}) }) });
function memory(id, text) { return { id, revision: 1, scope: { id: 'team:synthetic' }, visibility: 'shared', claim: { encoding: 'plain', text }, lifecycle: { status: 'active', validFrom: '2020-01-01T00:00:00Z', validTo: '2099-01-01T00:00:00Z' } }; }
function config(overrides = {}) {
  const calls = []; const values = {
    canonicalStore: { configured: true, routingContext: () => null, async search() { return { items: [memory('mem_synthetic', 'Synthetic memory')], nextCursor: null }; }, async read(request) { calls.push('canonical.read'); return memory(request.id, 'Synthetic memory'); } },
    documentStore: { configured: true, async search() { return []; }, async read() { return null; } },
    conversationReader: { configured: true, async search() { return { items: [{ id: 'conversation_synthetic' }], total: 1, nextCursor: null }; }, async transcript(request) { return { id: request.id, view: 'redacted', items: [{ eventId: 'cevt_synthetic', occurredAt: '2026-01-01T00:00:00Z', role: 'user', content: { redacted: true, contentType: 'text', parts: 1, text: 'Synthetic conversation' } }], nextCursor: null }; } },
    fabricStore: { configured: true, async propose() { calls.push('fabric.propose'); return { id: 'proposal_synthetic', status: 'queued' }; }, async getProposalStatusAuthorized() { calls.push('fabric.proposal_status'); return { status: 'review' }; } },
    resolveGrant: async () => projection,
    authorize: async request => request.scopes.includes('team:outside') ? false : grant,
    opaqueReferenceStore: new MemoryOpaqueReferenceStore(),
    now: () => Date.parse('2030-01-01T00:00:00Z')
  }; return { values: { ...values, ...overrides }, calls };
}
async function rpc(composition, id, method, params) { return composition.handle({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) }); }
const publicResult = reply => JSON.parse(reply.result.content[0].text);

test('composes the real providers into an opaque five-tool JSON-RPC surface', async () => {
  const built = config(); const api = createCapabilityMcpComposition(built.values);
  assert.deepEqual(Object.keys(api).sort(), ['handle', 'tools']); assert.equal(Object.isFrozen(api), true);
  assert.equal((await rpc(api, 1, 'initialize', { protocolVersion: '2024-11-05' })).result.protocolVersion, '2024-11-05');
  const listed = await rpc(api, 2, 'tools/list'); assert.deepEqual(listed.result.tools.map(tool => tool.name), ['search', 'read', 'propose', 'proposal_status', 'status']);
  for (const blocked of ['delete', 'admin', 'apply', 'provider_status']) assert.deepEqual(publicResult(await rpc(api, 3, 'tools/call', { name: blocked, arguments: {} })), { ok: false, outcome: 'invalid_request' });
  const found = publicResult(await rpc(api, 4, 'tools/call', { name: 'search', arguments: { query: 'synthetic', scopes: ['team:synthetic'], purpose: 'memory_recall', limit: 10 } }));
  assert.equal(found.ok, true); assert.equal(JSON.stringify(found).includes('mem_synthetic'), false);
  const read = publicResult(await rpc(api, 5, 'tools/call', { name: 'read', arguments: { id: found.items[0].id, scopes: ['team:synthetic'], purpose: 'memory_recall' } })); assert.equal(read.resource.text, 'Synthetic memory');
  const conversation = publicResult(await rpc(api, 6, 'tools/call', { name: 'search', arguments: { query: 'synthetic', kinds: ['conversation'], scopes: ['team:synthetic'], purpose: 'conversation_recall' } })); assert.equal(conversation.items[0].kind, 'conversation');
  assert.deepEqual(publicResult(await rpc(api, 6, 'tools/call', { name: 'search', arguments: { query: 'synthetic', kinds: ['conversation'], scopes: ['team:synthetic'], purpose: 'memory_recall' } })), { ok: false, outcome: 'forbidden' });
  assert.deepEqual(publicResult(await rpc(api, 7, 'tools/call', { name: 'search', arguments: { query: 'synthetic', kinds: ['conversation'], scopes: ['team:outside'], purpose: 'conversation_recall' } })), { ok: false, outcome: 'forbidden' });
  const proposed = publicResult(await rpc(api, 8, 'tools/call', { name: 'propose', arguments: { scope: 'team:synthetic', claim: 'Synthetic claim', purpose: 'memory_curation', idempotencyKey: 'req_synthetic0001' } }));
  assert.equal(publicResult(await rpc(api, 9, 'tools/call', { name: 'proposal_status', arguments: { id: proposed.id, scopes: ['team:synthetic'], purpose: 'memory_curation' } })).proposal.state, 'review_required');
  assert.equal(publicResult(await rpc(api, 10, 'tools/call', { name: 'status', arguments: {} })).outcome, 'ready');
  const publicText = JSON.stringify([found, read, proposed, listed]); for (const hidden of ['capability_core', 'mem_synthetic', 'proposal_synthetic']) assert.equal(publicText.includes(hidden), false);
});

test('aliases remain unadvertised and construction validates dependencies before serving', async () => {
  const aliasMap = { legacy_search: 'search' };
  const built = config({ aliases: aliasMap }); const api = createCapabilityMcpComposition(built.values);
  aliasMap.legacy_search = 'read';
  assert.equal((await rpc(api, 1, 'tools/list')).result.tools.some(tool => tool.name === 'legacy_search'), false);
  assert.equal(publicResult(await rpc(api, 2, 'tools/call', { name: 'legacy_search', arguments: { query: 'synthetic', scopes: ['team:synthetic'], purpose: 'memory_recall' } })).ok, true);
  for (const bad of [undefined, {}, config({ opaqueReferenceStore: undefined }).values, config({ aliases: { search: 'read' } }).values, config({ cursorTtlMs: 1 }).values]) assert.throws(() => createCapabilityMcpComposition(bad), { code: 'capability_mcp_composition_config_invalid' });
});

test('caller mutation and public failures are isolated and content-free', async () => {
  const built = config(); const api = createCapabilityMcpComposition(built.values);
  built.values.authorize = () => false;
  built.values.canonicalStore.search = () => { throw Error('mutated-source-secret'); };
  built.values.fabricStore.propose = () => { throw Error('mutated-source-secret'); };
  assert.equal(publicResult(await rpc(api, 1, 'tools/call', { name: 'search', arguments: { query: 'synthetic', scopes: ['team:synthetic'], purpose: 'memory_recall' } })).ok, true);
  const output = publicResult(await rpc(api, 1, 'tools/call', { name: 'search', arguments: { query: 'synthetic', scopes: ['team:outside'], purpose: 'memory_recall' } }));
  assert.deepEqual(output, { ok: false, outcome: 'forbidden' }); assert.equal(JSON.stringify(output).includes('actor_synthetic'), false);
  const malformed = await rpc(api, 2, 'tools/call', { name: 'search' }); assert.deepEqual(malformed.error, { code: -32602, message: 'Invalid params' });
  const failing = config(); failing.values.canonicalStore.search = () => { throw Error('private-source-secret'); };
  const failure = await rpc(createCapabilityMcpComposition(failing.values), 3, 'tools/call', { name: 'search', arguments: { query: 'synthetic', scopes: ['team:synthetic'], purpose: 'memory_recall' } });
  assert.deepEqual(failure.error, { code: -32000, message: 'Internal error' });
  assert.equal(JSON.stringify(failure).includes('private-source-secret'), false);
});
