import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { createCapabilityMcpAuthorizationBridge } from '../src/capability-mcp-auth-bridge.mjs';
import { createCapabilityMcpComposition } from '../src/capability-mcp-composition.mjs';
import { createCapabilityMcpHttpServer } from '../src/capability-mcp-http-server.mjs';
import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createCapabilitySearchEquivalenceComparator } from '../src/capability-query-equivalence.mjs';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/capability-mcp-v1.conformance.json', import.meta.url), 'utf8'));
const policy = Object.freeze({ mode: 'allow_all', allowedScopes: ['team:synthetic'], permissions: ['*'], documentVaultIds: ['vault'], sessionOwnerActors: ['actor'], contextKeyVersions: ['ctx-v1'] });
const policies = Object.freeze({ actors: { actor: {} }, scopes: { 'team:synthetic': {} } });
const headers = Object.freeze({ authorization: 'Bearer synthetic', 'content-type': 'application/json' });

function memory(id, text) { return { id, revision: 1, scope: { id: 'team:synthetic' }, visibility: 'shared', claim: { encoding: 'plain', text }, lifecycle: { status: 'active', validFrom: '2020-01-01T00:00:00Z', validTo: '2099-01-01T00:00:00Z' } }; }
function sources(rows = [memory('mem_alpha', 'A synthetic memory result.')]) {
  return {
    canonicalStore: { configured: true, routingContext() { return null; }, async search() { return { items: rows, nextCursor: null }; }, async read({ id }) { return rows.find(row => row.id === id) || null; } },
    documentStore: { configured: true, async search() { return [{ documentId: 'doc_beta', vaultId: 'vault', revision: 1, tombstone: false, text: 'A synthetic document result.' }]; }, async read({ documentId }) { return documentId === 'doc_beta' ? { documentId, vaultId: 'vault', revision: 1, tombstone: false, text: 'A synthetic document result.' } : null; } },
    conversationReader: { configured: true, async search() { return { items: [{ id: 'conversation_gamma' }], total: 1, nextCursor: null }; }, async transcript({ id }) { return id === 'conversation_gamma' ? { id, view: 'redacted', items: [{ eventId: 'event_gamma', occurredAt: '2026-01-01T00:00:00Z', role: 'user', content: { redacted: true, contentType: 'text', parts: 1, text: 'A synthetic visible message.' } }], nextCursor: null } : null; } },
    fabricStore: { configured: true, async propose() { return { id: 'proposal_delta', status: 'queued' }; }, async getProposalStatusAuthorized(id) { return id === 'proposal_delta' ? { status: 'review' } : null; } }
  };
}

const contextVerifier = Object.freeze({ verify(token, { actor, purpose }) { if (token !== 'ctx' || actor !== 'actor') throw Error('invalid context'); return { actor, runtime: 'synthetic', profile: 'synthetic', conversationKind: 'direct', contextTags: {}, purpose, policyRevision: 'synthetic', keyVersion: 'ctx-v1', canonicalScopes: ['team:synthetic'] }; } });
function createComposed({ requestArguments, contextToken, aliases, opaqueReferenceStore, rows }) {
  const bridge = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor', policy }, requestArguments, contextToken, contextVerifier, policies, validateContextActorBinding() {} });
  return createCapabilityMcpComposition({ ...sources(rows), resolveGrant: bridge.resolveGrant, authorize: bridge.authorize, opaqueReferenceStore, ...(aliases === undefined ? {} : { aliases }) });
}
async function listen({ aliases, rows } = {}) {
  const opaqueReferenceStore = new MemoryOpaqueReferenceStore();
  const server = createCapabilityMcpHttpServer({
    authenticate: async () => ({ actor: 'actor', policy }),
    createComposition: async ({ requestArguments, contextToken }) => createComposed({ requestArguments, contextToken, aliases, opaqueReferenceStore, rows })
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}
function rpc(name, args, id = 1) { return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }; }
async function httpCall(base, request, contextToken) {
  const response = await fetch(`${base}/mcp`, { method: 'POST', headers: { ...headers, ...(contextToken ? { 'x-amf-context-token': contextToken } : {}) }, body: JSON.stringify(request) });
  assert.equal(response.status, 200); const body = await response.json(); return body.result ? JSON.parse(body.result.content[0].text) : body;
}
async function sseConnection(base) {
  const response = await fetch(`${base}/sse`, { headers }); assert.equal(response.status, 200);
  const reader = response.body.getReader(); const first = new TextDecoder().decode((await reader.read()).value);
  const id = /connection_id=([A-Za-z0-9_-]+)/.exec(first)?.[1]; assert.ok(id); return { reader, id };
}
async function sseCall(base, stream, request, contextToken) {
  const response = await fetch(`${base}/sse/messages?connection_id=${stream.id}`, { method: 'POST', headers: { ...headers, ...(contextToken ? { 'x-amf-context-token': contextToken } : {}) }, body: JSON.stringify(request) });
  assert.equal(response.status, 202); const event = new TextDecoder().decode((await stream.reader.read()).value);
  const body = JSON.parse(/^event: message\ndata: (.+)\n/m.exec(event)[1]); return JSON.parse(body.result.content[0].text);
}
function expectedShape(expected, actual) {
  assert.equal(actual.ok, expected.ok); assert.equal(actual.outcome, expected.outcome);
  if (expected.items) { assert.deepEqual(actual.items.map(({ kind, text }) => ({ kind, text })), expected.items.map(({ kind, text }) => ({ kind, text }))); assert.equal(actual.items.every(item => /^rid_[A-Za-z0-9_-]{8,128}$/.test(item.id)), true); assert.equal(actual.nextCursor, expected.nextCursor); }
  if (expected.resource) { assert.deepEqual(({ kind: actual.resource.kind, text: actual.resource.text }), ({ kind: expected.resource.kind, text: expected.resource.text })); assert.match(actual.resource.id, /^rid_[A-Za-z0-9_-]{8,128}$/); }
  if (expected.id) assert.match(actual.id, /^rid_[A-Za-z0-9_-]{8,128}$/);
  if (expected.proposal) { assert.equal(actual.proposal.state, expected.proposal.state); assert.match(actual.proposal.id, /^rid_[A-Za-z0-9_-]{8,128}$/); }
  if (expected.capabilities) assert.deepEqual(actual.capabilities, expected.capabilities);
}

test('every non-registry fixture uses the real auth bridge, composition, HTTP and SSE transports', async () => {
  const { server, base } = await listen({ aliases: { legacy_search: 'search' } });
  try {
    const list = await fetch(`${base}/mcp`, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    assert.deepEqual((await list.json()).result.tools.map(tool => tool.name), fixture.advertisedTools);
    for (const scenario of fixture.scenarios.filter(item => !item.registry)) {
      let args = { ...scenario.request.arguments }; const contextToken = args.purpose === 'conversation_recall' ? 'ctx' : undefined;
      if (scenario.id.startsWith('read_')) args.id = (await httpCall(base, rpc('search', fixture.scenarios[0].request.arguments))).items[0].id;
      if (scenario.id === 'proposal_lifecycle') args.id = (await httpCall(base, rpc('propose', fixture.scenarios.find(item => item.id === 'proposal_queued').request.arguments))).id;
      const name = scenario.alias || scenario.request.name; const request = rpc(name, args);
      const fromHttp = await httpCall(base, request, contextToken); const stream = await sseConnection(base);
      try { const fromSse = await sseCall(base, stream, request, contextToken); expectedShape(scenario.expected, fromHttp); assert.deepEqual(fromSse, fromHttp, scenario.id); } finally { await stream.reader.cancel(); }
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

function independentComposition(rows, authPolicy = policy) {
  const requestArguments = { query: 'x', scopes: ['team:synthetic'], purpose: 'memory_recall' };
  const bridge = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor', policy: authPolicy }, requestArguments, contextToken: undefined, contextVerifier, policies, validateContextActorBinding() {} });
  return createCapabilityMcpComposition({ ...sources(rows), resolveGrant: bridge.resolveGrant, authorize: bridge.authorize, opaqueReferenceStore: new MemoryOpaqueReferenceStore() });
}
async function directSearch(api) { const reply = await api.handle(rpc('search', { query: 'x', scopes: ['team:synthetic'], purpose: 'memory_recall' })); return JSON.parse(reply.result.content[0].text); }
test('two independent real compositions compare only aggregate search evidence', async () => {
  const left = await directSearch(independentComposition([memory('mem_one', 'one'), memory('mem_two', 'two'), memory('mem_three', 'three'), memory('mem_four', 'four'), memory('mem_five', 'five')]));
  const right = await directSearch(independentComposition([memory('other_one', 'one'), memory('other_two', 'two'), memory('other_three', 'three'), memory('other_four', 'four'), memory('other_six', 'six')]));
  const report = createCapabilitySearchEquivalenceComparator()(left, right);
  assert.equal(report.comparable, true); assert.equal(JSON.stringify(report).includes('one'), false);
  const denied = independentComposition([], { ...policy, permissions: ['fabric:read', 'purpose:memory_recall'] });
  const deniedResult = await directSearch(denied); assert.deepEqual(deniedResult, { ok: false, outcome: 'forbidden' });
  assert.equal(createCapabilitySearchEquivalenceComparator()(left, deniedResult).comparable, false);
});
