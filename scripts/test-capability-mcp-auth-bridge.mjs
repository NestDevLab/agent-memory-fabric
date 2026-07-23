import assert from 'node:assert/strict';
import test from 'node:test';
import { buildCapabilityContextRequest, createCapabilityMcpAuthorizationBridge } from '../src/capability-mcp-auth-bridge.mjs';
import { createCapabilityMcpComposition } from '../src/capability-mcp-composition.mjs';
import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';

const args = { query: 'synthetic', scopes: ['team:synthetic'], purpose: 'conversation_recall' };
const policy = { mode: 'scoped', allowedScopes: ['team:synthetic'], permissions: ['fabric:search', 'fabric:read', 'fabric:propose', 'fabric:proposal_status', 'fabric:status', 'purpose:conversation_recall', 'purpose:memory_recall', 'purpose:memory_curation'], documentVaultIds: ['vault_synthetic'], sessionOwnerActors: ['owner_synthetic'], contextKeyVersions: ['ctx-v1'] };
const policies = { scopes: { 'team:synthetic': {} }, actors: { actor_synthetic: { contextKeyVersions: ['ctx-v1'] } } };
const clock = Date.parse('2030-01-01T00:00:00.000Z');
const ring = { currentKeyVersion: 'ctx-v1', keys: { 'ctx-v1': 'a'.repeat(64) } };
function signedToken(request, overrides = {}, keyRing = ring) { return issueContextToken({ actor: 'actor_synthetic', runtime: 'runtime', profile: 'profile', conversationKind: 'dm', contextTags: { actor: ['hmac-sha256:tag:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] }, purpose: 'conversation_recall', policyRevision: 'policy-v1', issuedAt: '2030-01-01T00:00:00.000Z', expiresAt: '2030-01-01T00:04:00.000Z', nonce: 'nonce_synthetic0001', requestDigest: requestDigest(request), ...overrides }, keyRing); }
function realVerifier() { return new ContextTokenVerifier({ keyRing: ring, policyRevision: 'policy-v1', clock: () => clock }); }
function bridge(overrides = {}) { return createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments: args, contextToken: 'token', contextVerifier: { verify(token, input) { assert.equal(token, 'token'); assert.deepEqual(input.request, buildCapabilityContextRequest('search', args)); return { actor: 'actor_synthetic', purpose: 'conversation_recall', runtime: 'runtime', conversationKind: 'direct', contextTags: {}, nonce: 'hidden', issuedAt: 'hidden', requestDigest: 'hidden' }; } }, policies, validateContextActorBinding() {}, ...overrides }); }

test('normalizes canonical search context requests and projects a stable private grant', async () => {
  assert.deepEqual(buildCapabilityContextRequest('search', args), { operation: 'capability_search', query: 'synthetic', kinds: ['canonical_memory', 'document'], scopes: ['team:synthetic'], purpose: 'conversation_recall', cursor: null, limit: 20 });
  const value = bridge(); const auth = { capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }; const grant = await value.authorize(auth);
  assert.equal(Object.isFrozen(grant), true); assert.equal(JSON.stringify(grant).includes('token'), false); assert.equal(JSON.stringify(grant).includes('nonce'), false);
  assert.deepEqual(await value.resolveGrant(grant, { capability: 'search', scopes: ['team:synthetic'], purpose: 'conversation_recall' }), { actor: 'actor_synthetic', allowedScopes: ['team:synthetic'], documentVaultIds: ['vault_synthetic'], sessionOwnerActors: ['actor_synthetic', 'owner_synthetic'], context: { actor: 'actor_synthetic', runtime: 'runtime', conversationKind: 'direct', contextTags: {}, purpose: 'conversation_recall' } });
});

test('context requests preserve semantic public kind and scope order', () => {
  const first = buildCapabilityContextRequest('search', { query: 'synthetic', kinds: ['canonical_memory', 'document'], scopes: ['team:synthetic', 'team:second'], purpose: 'memory_recall' });
  const reordered = buildCapabilityContextRequest('search', { query: 'synthetic', kinds: ['document', 'canonical_memory'], scopes: ['team:second', 'team:synthetic'], purpose: 'memory_recall' });
  assert.notDeepEqual(first, reordered); assert.throws(() => buildCapabilityContextRequest('search', { query: 'synthetic', kinds: ['document', 'document'], scopes: ['team:synthetic'], purpose: 'memory_recall' }), { code: 'capability_mcp_auth_bridge_invalid' });
});

test('real context tokens with different nonce and timestamps yield the same stable grant', async () => {
  const verifier = realVerifier(); const readArgs = { id: `rid_${'r'.repeat(16)}`, scopes: ['team:synthetic'], purpose: 'conversation_recall' };
  const first = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments: args, contextToken: signedToken(buildCapabilityContextRequest('search', args)), contextVerifier: verifier, policies, validateContextActorBinding() {} });
  const second = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments: readArgs, contextToken: signedToken(buildCapabilityContextRequest('read', readArgs), { nonce: 'nonce_synthetic0002', issuedAt: '2029-12-31T23:59:59.000Z' }), contextVerifier: verifier, policies, validateContextActorBinding() {} });
  const searchGrant = await first.authorize({ capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }); const readGrant = await second.authorize({ capability: 'read', permission: 'fabric:read', purpose: 'conversation_recall', scopes: ['team:synthetic'] });
  assert.deepEqual(searchGrant, readGrant); assert.equal(JSON.stringify(searchGrant).includes('nonce_synthetic'), false);
});

test('real context verification denies wrong actor, key, digest, expiry, and unassigned keys', async () => {
  const request = buildCapabilityContextRequest('search', args); const authorization = { capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] };
  const wrongRing = { currentKeyVersion: 'ctx-v2', keys: { 'ctx-v2': 'b'.repeat(64) } };
  const candidates = [
    signedToken(request, { actor: 'actor_other0001' }),
    signedToken(request, {}, wrongRing),
    signedToken(request, { requestDigest: '0'.repeat(64) }),
    signedToken(request, { issuedAt: '2029-12-31T23:50:00.000Z', expiresAt: '2029-12-31T23:55:00.000Z' })
  ];
  for (const contextToken of candidates) {
    const value = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments: args, contextToken, contextVerifier: realVerifier(), policies, validateContextActorBinding() {} });
    assert.equal(await value.authorize(authorization), null);
  }
  const unassigned = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy: { ...policy, contextKeyVersions: [] } }, requestArguments: args, contextToken: signedToken(request), contextVerifier: realVerifier(), policies, validateContextActorBinding() {} });
  assert.equal(await unassigned.authorize(authorization), null);
});

test('permission, modes, token verification, and resolve scope widening deny without public leakage', async () => {
  const value = bridge(); assert.equal(await value.authorize({ capability: 'search', permission: 'fabric:read', purpose: 'conversation_recall', scopes: ['team:synthetic'] }), null);
  const noConversationPurpose = bridge({ authContext: { actor: 'actor_synthetic', policy: { ...policy, permissions: policy.permissions.filter(item => item !== 'purpose:conversation_recall') } } }); assert.equal(await noConversationPurpose.authorize({ capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }), null);
  const proposalArgs = { scope: 'team:synthetic', claim: 'x', purpose: 'memory_curation', idempotencyKey: 'req_synthetic0001' }; const noCurationPurpose = bridge({ authContext: { actor: 'actor_synthetic', policy: { ...policy, permissions: policy.permissions.filter(item => item !== 'purpose:memory_curation') } }, requestArguments: proposalArgs, contextToken: undefined }); assert.equal(await noCurationPurpose.authorize({ capability: 'propose', permission: 'fabric:propose', purpose: 'memory_curation', scopes: ['team:synthetic'] }), null);
  assert.equal(await bridge({ authContext: { actor: 'actor_synthetic', policy: { ...policy, mode: 'read_only_scoped' } }, requestArguments: proposalArgs, contextToken: undefined }).authorize({ capability: 'propose', permission: 'fabric:propose', purpose: 'memory_curation', scopes: ['team:synthetic'] }), null);
  const grant = await value.authorize({ capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }); assert.equal(await value.resolveGrant(grant, { capability: 'search', scopes: ['team:outside'], purpose: 'conversation_recall' }), null);
  const denied = bridge({ contextToken: undefined }); assert.equal(await denied.authorize({ capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }), null);
});

test('malformed configuration and hostile requests fail closed', () => {
  assert.throws(() => createCapabilityMcpAuthorizationBridge({}), { code: 'capability_mcp_auth_bridge_invalid' });
  assert.throws(() => buildCapabilityContextRequest('search', { query: 'x', scopes: ['team:synthetic'], purpose: 'memory_recall', contextToken: 'forbidden' }), { code: 'capability_mcp_auth_bridge_invalid' });
  const privateText = 'private-auth-bridge-secret'; const hostilePolicy = {}; Object.defineProperty(hostilePolicy, 'mode', { enumerable: true, get() { throw Error(privateText); } });
  assert.throws(() => createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy: hostilePolicy }, requestArguments: {}, contextToken: undefined, contextVerifier: { verify() {} }, policies, validateContextActorBinding() {} }), error => error.code === 'capability_mcp_auth_bridge_invalid' && !error.message.includes(privateText));
  const hostileScopes = new Proxy({}, { ownKeys() { throw Error(privateText); } }); assert.throws(() => createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments: {}, contextToken: undefined, contextVerifier: { verify() {} }, policies: { scopes: hostileScopes }, validateContextActorBinding() {} }), error => error.code === 'capability_mcp_auth_bridge_invalid' && !error.message.includes(privateText));
});

test('hostile authorization and verifier output deny without throwing or leaking', async () => {
  const privateText = 'private-auth-bridge-secret'; const value = bridge(); const hostileAuthorization = new Proxy({}, { ownKeys() { throw Error(privateText); } }); assert.equal(await value.authorize(hostileAuthorization), null);
  const hostileVerified = {}; Object.defineProperty(hostileVerified, 'actor', { enumerable: true, get() { throw Error(privateText); } }); const hostileVerifier = bridge({ contextVerifier: { verify() { return hostileVerified; } } }); assert.equal(await hostileVerifier.authorize({ capability: 'search', permission: 'fabric:search', purpose: 'conversation_recall', scopes: ['team:synthetic'] }), null);
});

test('real composition resolves stable grants across search and later opaque read', async () => {
  const opaqueReferenceStore = new MemoryOpaqueReferenceStore(); const verifier = realVerifier(); const resolveCalls = [];
  const memory = id => ({ id, revision: 1, scope: { id: 'team:synthetic' }, visibility: 'shared', claim: { encoding: 'plain', text: 'Synthetic text' }, lifecycle: { status: 'active', validFrom: '2020-01-01T00:00:00Z', validTo: '2099-01-01T00:00:00Z' } });
  const sources = { canonicalStore: { configured: true, routingContext: () => null, async search() { return { items: [memory('memory_synthetic')], nextCursor: null }; }, async read(request) { return memory(request.id); } }, documentStore: { configured: true, async search() { return []; }, async read() { return null; } }, conversationReader: { configured: true, async search() { return { items: [], total: 0, nextCursor: null }; }, async transcript() { return null; } }, fabricStore: { configured: true, async propose() { return { id: 'proposal_synthetic' }; }, async getProposalStatusAuthorized() { return { status: 'review' }; } } };
  const make = (requestArguments, contextToken, label) => { const authBridge = createCapabilityMcpAuthorizationBridge({ authContext: { actor: 'actor_synthetic', policy }, requestArguments, contextToken, contextVerifier: verifier, policies, validateContextActorBinding() {} }); return createCapabilityMcpComposition({ ...sources, opaqueReferenceStore, authorize: authBridge.authorize, resolveGrant: async (...input) => { resolveCalls.push(label); return authBridge.resolveGrant(...input); }, now: () => clock }); };
  const call = async (api, id, name, requestArguments) => { const response = await api.handle({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: requestArguments } }); return JSON.parse(response.result.content[0].text); };
  const searchArgs = { ...args, kinds: ['canonical_memory'] }; const search = make(searchArgs, signedToken(buildCapabilityContextRequest('search', searchArgs)), 'search'); const found = await call(search, 1, 'search', searchArgs); assert.equal(found.ok, true);
  const readArgs = { id: found.items[0].id, scopes: ['team:synthetic'], purpose: 'conversation_recall' }; const read = make(readArgs, signedToken(buildCapabilityContextRequest('read', readArgs), { nonce: 'nonce_synthetic0003' }), 'read'); const result = await call(read, 2, 'read', readArgs);
  assert.equal(result.ok, true); assert.equal(result.resource.text, 'Synthetic text'); assert.deepEqual(resolveCalls, ['search', 'read']);
});
