import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, MemoryCatalog, MemoryRawStore } from '../src/fabric-store.mjs';
import { aadSha256For } from '../src/amf-memory-record-validator.mjs';
import { createAgentMemoryFabricServer } from '../src/server.mjs';
import { ContextTokenVerifier, issueContextToken, issueSessionRouteBinding, requestDigest } from '../src/context-token.mjs';
import { buildContextRequest } from '../src/access-contract.mjs';
import { CuratorReceiptCoordinator, MemoryReceiptLedger } from '../src/canonical-memory-bridge.mjs';

const testPolicyPath = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'config', 'policies.example.json');
const CONTEXT_RING = { currentKeyVersion: 'ctx-v1', keys: { 'ctx-v1': Buffer.alloc(32, 7).toString('base64') } };
const CONTEXT_NOW = Date.parse('2026-07-12T12:00:00Z');
const ROOM_A = `hmac-sha256:routing-v1:${'a'.repeat(64)}`;
const ROOM_B = `hmac-sha256:routing-v1:${'b'.repeat(64)}`;
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function contextTokenFor({ actor = 'test-actor', purpose, operation, input, room = ROOM_A,
  conversationKind = 'group', contextTags = null, canonicalScopes = ['room:team'] }) {
  return issueContextToken({ actor, runtime: 'principia', profile: 'test', conversationKind,
    contextTags: contextTags || { conversation: [room], room: [room] }, canonicalScopes,
    purpose, policyRevision: 'policy-test', issuedAt: new Date(CONTEXT_NOW - 1000).toISOString(),
    expiresAt: new Date(CONTEXT_NOW + 60_000).toISOString(), nonce: crypto.randomBytes(16).toString('base64url'),
    requestDigest: requestDigest(buildContextRequest(operation, input)) }, CONTEXT_RING);
}

function makeStore() {
  return new FabricStore({
    rawStore: new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64') }),
    catalog: new MemoryCatalog()
  });
}

function canonicalRecord(text, scope = 'main-lab', revision = 1) {
  const timestamp = '2026-07-11T12:00:00Z';
  const canonicalScope = scope.includes(':') ? scope : `domain:${scope}`;
  const record = {
    schema: 'amf-memory/v1', id: `mem_${crypto.createHash('sha256').update(`${scope}:${text}`).digest('hex').slice(0, 16)}`, revision,
    claimType: 'fact', scope: { type: 'domain', id: canonicalScope }, visibility: 'restricted',
    subjects: [{ identityId: 'agent:test', role: 'owner' }],
    claim: { encoding: 'sealed', alg: 'AES-256-GCM', kekId: 'kek:test-v1', keyRef: 'key:test-record-v1', iv: Buffer.alloc(12, 1).toString('base64'), ciphertext: Buffer.from(text).toString('base64'), tag: Buffer.alloc(16, 2).toString('base64'), aadSha256: '' },
    confidence: { score: 0.9, basis: 'asserted', assessedAt: timestamp },
    provenance: [{ sourceType: 'test', sourceId: 'test-suite', eventId: 'event-stable-0001', contentSha256: crypto.createHash('sha256').update(text).digest('hex'), capturedAt: timestamp }],
    lifecycle: { status: 'active', validFrom: timestamp, validTo: null, supersedes: [], revokedAt: null, revocationReason: null },
    createdAt: timestamp, updatedAt: timestamp
  };
  record.claim.aadSha256 = aadSha256For(record);
  return record;
}

function canonicalProposal(text, scope = 'main-lab', revision = 1) {
  return { record: canonicalRecord(text, scope, revision), rationale: 'test_evidence', expectedRevision: revision - 1 };
}

async function withServer(run, { sessionOptions, clock, configuredSessionReader = true,
  sessionReader: sessionReaderOverride, fabricStore: fabricStoreOverride, backend: backendOverride,
  canonicalStore, contextVerifier, receiptCoordinator, routeManifestSetup } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-server-'));
  const registryPath = path.join(dir, 'auth.json');
  const registry = {
    rows: [
      {
        token: 'test-token',
        active: true,
        actor: 'test-actor',
        mode: 'allow_all',
        allowedScopes: '*',
        permissions: '*'
      },
      {
        token: 'limited-token',
        active: true,
        actor: 'limited-actor',
        mode: 'scoped',
        allowedScopes: 'main-lab,room:team',
        permissions: 'memory:search,memory:read,sessions:read,purpose:continuity_resume,purpose:incident_debug,purpose:operator_review'
      },
      {
        token: 'curator-token',
        active: true,
        actor: 'curator-actor',
        mode: 'scoped',
        allowedScopes: 'domain:main-lab',
        permissions: 'memory:curate'
      },
      {
        token: 'applicator-token',
        active: true,
        actor: 'applicator-actor',
        mode: 'scoped',
        allowedScopes: 'domain:main-lab',
        permissions: 'memory:apply-receipt'
      },
      {
        token: 'curator-two-token', active: true, actor: 'curator-two', mode: 'scoped',
        allowedScopes: 'domain:main-lab', permissions: 'memory:curate'
      },
      {
        tokenSha256: '556510a5888bb3f061617bfec75649cbe0d04f8c5efe6a2807a9ca3ef231f382',
        active: true,
        actor: 'search-only',
        mode: 'scoped',
        allowedScopes: 'main-lab',
        permissions: 'memory:search,purpose:operator_review'
      },
      {
        token: 'tirrenia-token',
        active: true,
        actor: 'tirrenia-actor',
        mode: 'scoped',
        allowedScopes: 'tirrenia',
        permissions: 'memory:read,sessions:read,purpose:operator_review'
      }
    ]
  };
  const writeRegistry = () => fs.writeFileSync(registryPath, JSON.stringify(registry));
  writeRegistry();
  const originalRegistry = process.env.MEM0_AUTH_REGISTRY_PATH;
  process.env.MEM0_AUTH_REGISTRY_PATH = registryPath;
  let backendAdds = 0;
  const backend = backendOverride || {
    kind: 'test-backend',
    configured: true,
    async search({ backendUserId, query }) {
      if (query === 'explode') {
        const error = new Error('/secret/path provider payload');
        error.body = { raw: 'private provider response' };
        throw error;
      }
      return { items: [{ id: 'memory-1', memory: query, userId: backendUserId }], total: 1, source: 'test' };
    },
    async add() {
      backendAdds += 1;
      throw new Error('backend_add_must_not_be_called');
    }
  };
  const fabricStore = fabricStoreOverride || makeStore();
  const sessionReader = sessionReaderOverride || {
    kind: 'test-session-reader',
    configured: true,
    async search({ query }) { return { items: [{ id: 'session-1', title: query, scope: 'main-lab', ownerActor: 'test-actor', conversationKind: 'group', contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }] }; },
    async get({ id }) { return { id, title: 'Session', scope: 'main-lab', ownerActor: 'test-actor', conversationKind: 'group', contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }; },
    async transcript({ id, view }) { return { id, view, items: [], nextCursor: null }; }
  };
  const effectiveContextVerifier = contextVerifier || new ContextTokenVerifier({ keyRing: CONTEXT_RING, policyRevision: 'policy-test', clock: () => CONTEXT_NOW });
  const routeManifestPath = path.join(dir, 'session-routes.json');
  fs.writeFileSync(routeManifestPath, JSON.stringify({ schema: 'amf.session-route-manifest/v1', bindings: [
    issueSessionRouteBinding({ actor: 'test-actor', canonicalScope: 'room:team', conversationKind: 'group',
      contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }, CONTEXT_RING),
    issueSessionRouteBinding({ actor: 'limited-actor', canonicalScope: 'room:team', conversationKind: 'group',
      contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }, CONTEXT_RING),
    issueSessionRouteBinding({ actor: 'tirrenia-actor', canonicalScope: 'tirrenia', conversationKind: 'session',
      contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }, CONTEXT_RING)
  ] }), { mode: 0o600 });
  fs.chmodSync(routeManifestPath, 0o600);
  const effectiveRouteManifestPath = routeManifestSetup
    ? routeManifestSetup({ dir, routeManifestPath }) || routeManifestPath : routeManifestPath;
  const server = createAgentMemoryFabricServer({ backend, fabricStore, canonicalStore,
    contextVerifier: effectiveContextVerifier, routeManifestPath: effectiveRouteManifestPath, receiptCoordinator,
    sessionReader: configuredSessionReader ? sessionReader : undefined, sessionOptions, clock,
    policyPath: testPolicyPath });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const api = async (pathname, options = {}) => {
    const response = await fetch(`${baseUrl}${pathname}`, {
      ...options,
      headers: {
        authorization: 'Bearer test-token',
        'content-type': 'application/json',
        ...(options.headers || {})
      }
    });
    const text = await response.text();
    return { response, body: text ? JSON.parse(text) : null };
  };
  try {
    await run({ api, baseUrl, fabricStore, registry, writeRegistry, routeManifestPath: effectiveRouteManifestPath,
      getBackendAdds: () => backendAdds });
  } finally {
    await new Promise(resolve => server.close(resolve));
    if (originalRegistry === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH;
    else process.env.MEM0_AUTH_REGISTRY_PATH = originalRegistry;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('v2 REST queues idempotently while canonical read never exposes proposal payloads', async () => {
  await withServer(async ({ api, fabricStore, getBackendAdds }) => {
    const request = {
      method: 'POST',
      headers: { 'idempotency-key': 'event-123' },
      body: JSON.stringify(canonicalProposal('Remember the appointment'))
    };
    const first = await api('/v2/memory/proposals', request);
    const duplicate = await api('/v2/memory/proposals', request);

    assert.equal(first.response.status, 202);
    assert.equal(first.body.ok, true);
    assert.equal(first.body.meta.service, 'agent-memory-fabric');
    assert.equal(first.body.data.status, 'queued');
    assert.equal(first.body.data.idempotencyKey, 'event-123');
    assert.equal(duplicate.response.status, 200);
    assert.equal(duplicate.body.data.proposalId, first.body.data.proposalId);
    assert.equal(duplicate.body.data.duplicate, true);
    assert.equal(duplicate.body.data.idempotencyKey, 'event-123');
    assert.equal(getBackendAdds(), 0);

    const status = await api(`/v2/memory/proposals/${first.body.data.proposalId}`);
    assert.equal(status.body.data.status, 'queued');
    assert.equal(status.body.data.record, undefined);
    const read = await api(`/v2/memory/${first.body.data.proposalId}?purpose=operator_review`);
    assert.equal(read.response.status, 503);
    assert.equal(read.body.error.code, 'canonical_store_unconfigured');
    assert.equal(JSON.stringify(read.body).includes('Remember the appointment'), false);
  });
});

test('least-privilege curator polls bounded metadata and reads one digest-bound proposal', async () => {
  await withServer(async ({ api }) => {
    const proposalIds = [];
    for (let index = 0; index < 3; index += 1) {
      const queued = await api('/v2/memory/proposals', {
        method: 'POST', headers: { 'idempotency-key': `curation-poll-${index}` },
        body: JSON.stringify(canonicalProposal(`curation candidate ${index}`))
      });
      proposalIds.push(queued.body.data.proposalId);
    }
    const curatorHeaders = { authorization: 'Bearer curator-token' };
    const first = await api('/v2/internal/curation/proposals?status=queued&limit=2', { headers: curatorHeaders });
    assert.equal(first.response.status, 200);
    assert.equal(first.body.data.items.length, 2);
    assert.equal(typeof first.body.data.nextCursor, 'string');
    assert.equal(JSON.stringify(first.body).includes('curation candidate'), false);
    const crossFilter = await api(`/v2/internal/curation/proposals?status=review&limit=2&cursor=${encodeURIComponent(first.body.data.nextCursor)}`, { headers: curatorHeaders });
    assert.equal(crossFilter.response.status, 400);
    const crossActor = await api(`/v2/internal/curation/proposals?status=queued&limit=2&cursor=${encodeURIComponent(first.body.data.nextCursor)}`, { headers: { authorization: 'Bearer curator-two-token' } });
    assert.equal(crossActor.response.status, 400);
    const tamperedCursor = `${first.body.data.nextCursor.slice(0, -1)}${first.body.data.nextCursor.endsWith('A') ? 'B' : 'A'}`;
    const tampered = await api(`/v2/internal/curation/proposals?status=queued&limit=2&cursor=${encodeURIComponent(tamperedCursor)}`, { headers: curatorHeaders });
    assert.equal(tampered.response.status, 400);
    const decoded = JSON.parse(Buffer.from(first.body.data.nextCursor, 'base64url').toString('utf8'));
    decoded.id = `${decoded.id.slice(0, -1)}${decoded.id.endsWith('0') ? '1' : '0'}`;
    const semanticForgery = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
    const forged = await api(`/v2/internal/curation/proposals?status=queued&limit=2&cursor=${encodeURIComponent(semanticForgery)}`, { headers: curatorHeaders });
    assert.equal(forged.response.status, 400);
    const second = await api(`/v2/internal/curation/proposals?status=queued&limit=2&cursor=${encodeURIComponent(first.body.data.nextCursor)}`, { headers: curatorHeaders });
    assert.equal(second.response.status, 200);
    assert.equal(second.body.data.items.length, 1);
    assert.equal(second.body.data.nextCursor, null);
    assert.deepEqual(new Set([...first.body.data.items, ...second.body.data.items].map(item => item.proposalId)), new Set(proposalIds));

    const selected = await api(`/v2/internal/curation/proposals/${proposalIds[0]}`, { headers: curatorHeaders });
    assert.equal(selected.response.status, 200);
    assert.equal(selected.body.data.proposalId, proposalIds[0]);
    assert.equal(selected.body.data.status, 'queued');
    assert.equal(selected.body.data.proposalDigest, crypto.createHash('sha256').update(canonicalJson(selected.body.data.payload)).digest('hex'));
    assert.equal(selected.body.data.payload.record.claim.encoding, 'sealed');
  });
});

test('receipt actors cannot advance cross-scope or unknown proposals and receive no existence oracle', async () => {
  const store = makeStore();
  const coordinator = new CuratorReceiptCoordinator({
    ledger: new MemoryReceiptLedger(), proposalStore: store,
    canonicalStore: { async read() { throw new Error('must_not_read'); }, async verifyApplyReceipt() { throw new Error('must_not_verify'); } }
  });
  await withServer(async ({ api }) => {
    const queued = await api('/v2/memory/proposals', {
      method: 'POST', headers: { 'idempotency-key': 'cross-scope-receipt-0001' },
      body: JSON.stringify(canonicalProposal('private other domain', 'tirrenia'))
    });
    const persisted = await store.readProposal(queued.body.data.proposalId);
    const digest = value => crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
    const makeReceipt = (proposalId, proposalScope, proposalDigest) => {
      const base = { proposalId, proposalScope, decisionId: 'decision-cross-scope', status: 'approved_pending_apply', proposalDigest, policyDigest: digest('policy') };
      return { kind: 'decision', ...base, decisionDigest: digest(base), timestamp: '2026-07-12T12:00:00Z' };
    };
    let decryptions = 0; const originalGet = store.rawStore.get.bind(store.rawStore);
    store.rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };
    const denied = await api('/v2/internal/curation/receipts', { method: 'POST', headers: { authorization: 'Bearer curator-token' }, body: JSON.stringify(makeReceipt(persisted.id, persisted.scope, persisted.proposalDigest)) });
    const missing = await api('/v2/internal/curation/receipts', { method: 'POST', headers: { authorization: 'Bearer curator-token' }, body: JSON.stringify(makeReceipt('proposal-does-not-exist', persisted.scope, persisted.proposalDigest)) });
    assert.equal(denied.response.status, 404); assert.equal(missing.response.status, 404);
    assert.equal(denied.body.error.code, 'memory_not_found'); assert.equal(missing.body.error.code, 'memory_not_found');
    assert.equal(decryptions, 0);
  }, { fabricStore: store, receiptCoordinator: coordinator });
});

test('curation exact read permits retry states but denies terminal rejected/revoked before decrypt', async () => {
  await withServer(async ({ api, fabricStore }) => {
    const ids = [];
    for (const key of ['review', 'promoted', 'rejected', 'revoked']) {
      const queued = await api('/v2/memory/proposals', { method: 'POST', headers: { 'idempotency-key': `curation-state-${key}` }, body: JSON.stringify(canonicalProposal(`state ${key}`)) });
      ids.push([key, queued.body.data.proposalId]); fabricStore.catalog.proposals.get(queued.body.data.proposalId).status = key;
    }
    let decryptions = 0; const originalGet = fabricStore.rawStore.get.bind(fabricStore.rawStore);
    fabricStore.rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };
    for (const [status, id] of ids) {
      const result = await api(`/v2/internal/curation/proposals/${id}`, { headers: { authorization: 'Bearer curator-token' } });
      assert.equal(result.response.status, ['review', 'promoted'].includes(status) ? 200 : 404);
    }
    assert.equal(decryptions, 2);
  });
});

test('curation payload denial happens before proposal decryption', async () => {
  await withServer(async ({ api, fabricStore }) => {
    const queued = await api('/v2/memory/proposals', {
      method: 'POST', headers: { 'idempotency-key': 'curation-deny-0001' },
      body: JSON.stringify(canonicalProposal('curation deny candidate'))
    });
    let decryptions = 0;
    const originalGet = fabricStore.rawStore.get.bind(fabricStore.rawStore);
    fabricStore.rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };
    const denied = await api(`/v2/internal/curation/proposals/${queued.body.data.proposalId}`, { headers: { authorization: 'Bearer applicator-token' } });
    assert.equal(denied.response.status, 403);
    assert.equal(decryptions, 0);
    const deniedList = await api('/v2/internal/curation/proposals?limit=1', { headers: { authorization: 'Bearer limited-token' } });
    assert.equal(deniedList.response.status, 403);
    assert.equal(decryptions, 0);
  });
});

test('canonical search fails closed across v2 and v1 when PAM is unconfigured', async () => {
  await withServer(async ({ api }) => {
    const input = { query: 'appointment', scopes: ['domain:main-lab'], purpose: 'operator_review' };
    for (const [path, expectedEnvelope] of [['/v2/memory/search', true], ['/v1/memory/search', false]]) {
      const result = await api(path, { method: 'POST', body: JSON.stringify(input) });
      assert.equal(result.response.status, 503);
      assert.equal(expectedEnvelope ? result.body.error.code : result.body.error, 'canonical_store_unconfigured');
    }
  });
});

test('canonical PAM search/read and conversation recall bind the exact signed context', async () => {
  const canonical = canonicalRecord('Shared appointment', 'main-lab');
  canonical.visibility = 'shared';
  canonical.claim.aadSha256 = aadSha256For(canonical);
  const canonicalStore = {
    configured: true, kind: 'test-pam',
    async search() { return { items: [canonical], nextCursor: null }; },
    async read({ id }) { if (id !== canonical.id) throw Object.assign(new Error('memory_not_found'), { status: 404 }); return canonical; }
  };
  const keyRing = CONTEXT_RING;
  const now = Date.now();
  const contextVerifier = new ContextTokenVerifier({ keyRing, policyRevision: 'policy-test', clock: () => now });
  const request = buildContextRequest('memory_search', { query: 'appointment', scopes: ['domain:main-lab'] });
  const contextToken = issueContextToken({
    actor: 'test-actor', runtime: 'principia', profile: 'test', conversationKind: 'group',
    contextTags: { conversation: [ROOM_A], room: [ROOM_A] }, purpose: 'conversation_recall', policyRevision: 'policy-test',
    issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), nonce: 'nonce_1234567890abcdef', requestDigest: requestDigest(request)
  }, keyRing);
  await withServer(async ({ api }) => {
    const missing = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ scopes: ['domain:main-lab'], query: 'appointment', purpose: 'conversation_recall' }) });
    assert.equal(missing.response.status, 403);
    assert.equal(missing.body.error.code, 'context_required');
    const found = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ scopes: ['domain:main-lab'], query: 'appointment', purpose: 'conversation_recall', contextToken }) });
    assert.equal(found.response.status, 200);
    assert.deepEqual(found.body.data.items.map(item => item.id), [canonical.id]);
    const replayChanged = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ scopes: ['domain:main-lab'], query: 'different', purpose: 'conversation_recall', contextToken }) });
    assert.equal(replayChanged.response.status, 403);
    assert.equal(replayChanged.body.error.code, 'context_invalid');
    const read = await api(`/v2/memory/${canonical.id}?purpose=operator_review`);
    assert.equal(read.response.status, 200);
    assert.equal(read.body.data.record.id, canonical.id);
  }, { canonicalStore, contextVerifier });
});

test('room and person canonical recall require exact context intersection across token and PAM index routing', async () => {
  const roomRecord = canonicalRecord('Room appointment', 'main-lab');
  roomRecord.scope = { type: 'room', id: 'room:team' }; roomRecord.visibility = 'shared'; roomRecord.claim.aadSha256 = aadSha256For(roomRecord);
  const canonicalStore = {
    configured: true,
    routingContext() { return { conversation: [ROOM_B], room: [ROOM_B] }; },
    async search() { return { items: [roomRecord], nextCursor: null }; },
    async read() { return roomRecord; }
  };
  await withServer(async ({ api }) => {
    const input = { query: 'appointment', scopes: ['room:team'], purpose: 'conversation_recall' };
    const wrongToken = contextTokenFor({ purpose: input.purpose, operation: 'memory_search', input, room: ROOM_A });
    const wrong = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ ...input, contextToken: wrongToken }) });
    assert.equal(wrong.response.status, 200);
    assert.deepEqual(wrong.body.data.items, [], 'Room-A token must not read a Room-B record');
    const rightToken = contextTokenFor({ purpose: input.purpose, operation: 'memory_search', input, room: ROOM_B });
    const right = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ ...input, contextToken: rightToken }) });
    assert.deepEqual(right.body.data.items.map(item => item.id), [roomRecord.id]);

    const personWithoutContext = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ query: 'appointment', scopes: ['person:alice'], purpose: 'operator_review' }) });
    assert.equal(personWithoutContext.response.status, 403);
    assert.equal(personWithoutContext.body.error.code, 'context_required');
  }, { canonicalStore });
});

test('sensitive PAM routing fails closed for missing, malformed and wrong context across REST, MCP and v1 search/read', async () => {
  const definitions = [
    ['room', 'room:team', 'missing'],
    ['person', 'person:alice', 'malformed'],
    ['relationship', 'relationship:team', 'wrong']
  ];
  const records = definitions.map(([type, scope], index) => {
    const value = canonicalRecord(`Sensitive ${type}`, 'main-lab');
    value.id = `mem_sensitive_${index}0000000`; value.scope = { type, id: scope }; value.visibility = 'shared'; value.claim.aadSha256 = aadSha256For(value);
    return value;
  });
  const routing = new Map([
    [records[0].id, null],
    [records[1].id, { person: ['literal-person'] }],
    [records[2].id, { conversation: [ROOM_B], relationship: [ROOM_B] }]
  ]);
  const canonicalStore = {
    configured: true,
    routingContext(id) { return routing.get(id) || null; },
    async search({ scopes }) { return { items: records.filter(record => scopes.includes(record.scope.id)), nextCursor: null }; },
    async read({ id }) { const value = records.find(record => record.id === id); if (!value) throw Object.assign(new Error('memory_not_found'), { status: 404 }); return value; }
  };
  const tagsFor = (type, value = ROOM_A) => ({ conversation: [value], [type]: [value] });
  await withServer(async ({ api }) => {
    const initialized = await api('/mcp/test-client/sensitive', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }) });
    const mcpSession = initialized.response.headers.get('mcp-session-id');
    const mcpCall = (name, args, id) => api('/mcp/test-client/sensitive', { method: 'POST', headers: { 'mcp-session-id': mcpSession }, body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) });

    const roomSearch = { query: 'sensitive', scopes: ['room:team'], purpose: 'conversation_recall' };
    roomSearch.contextToken = contextTokenFor({ purpose: roomSearch.purpose, operation: 'memory_search', input: roomSearch, contextTags: tagsFor('room') });
    const missingRest = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify(roomSearch) });
    assert.deepEqual(missingRest.body.data.items, []);
    const roomReadToken = contextTokenFor({ purpose: 'conversation_recall', operation: 'memory_read', input: { id: records[0].id }, contextTags: tagsFor('room') });
    assert.equal((await api(`/v2/memory/${records[0].id}?purpose=conversation_recall&contextToken=${encodeURIComponent(roomReadToken)}`)).response.status, 404);

    const personSearch = { query: 'sensitive', scopes: ['person:alice'], purpose: 'conversation_recall' };
    personSearch.contextToken = contextTokenFor({ purpose: personSearch.purpose, operation: 'memory_search', input: personSearch, contextTags: tagsFor('person') });
    const malformedMcp = await mcpCall('memory_search', personSearch, 2);
    assert.deepEqual(JSON.parse(malformedMcp.body.result.content[0].text).items, []);
    const personRead = { id: records[1].id, purpose: 'conversation_recall' };
    personRead.contextToken = contextTokenFor({ purpose: personRead.purpose, operation: 'memory_read', input: personRead, contextTags: tagsFor('person') });
    assert.equal((await mcpCall('memory_read', personRead, 3)).body.error.message, 'memory_not_found');

    const relationshipSearch = { query: 'sensitive', scopes: ['relationship:team'], purpose: 'conversation_recall' };
    relationshipSearch.contextToken = contextTokenFor({ purpose: relationshipSearch.purpose, operation: 'memory_search', input: relationshipSearch, contextTags: tagsFor('relationship') });
    assert.deepEqual((await api('/v1/memory/search', { method: 'POST', body: JSON.stringify(relationshipSearch) })).body.items, []);
    const relationshipRead = { id: records[2].id, purpose: 'conversation_recall' };
    relationshipRead.contextToken = contextTokenFor({ purpose: relationshipRead.purpose, operation: 'memory_read', input: relationshipRead, contextTags: tagsFor('relationship') });
    assert.equal((await api('/v1/memory/read', { method: 'POST', body: JSON.stringify(relationshipRead) })).response.status, 404);

    for (const [index, [type]] of definitions.entries()) routing.set(records[index].id, tagsFor(type));
    const restAllowed = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ ...roomSearch, contextToken: contextTokenFor({ purpose: roomSearch.purpose, operation: 'memory_search', input: roomSearch, contextTags: tagsFor('room') }) }) });
    assert.deepEqual(restAllowed.body.data.items.map(item => item.id), [records[0].id]);
    const mcpAllowed = await mcpCall('memory_read', { ...personRead, contextToken: contextTokenFor({ purpose: personRead.purpose, operation: 'memory_read', input: personRead, contextTags: tagsFor('person') }) }, 4);
    assert.equal(JSON.parse(mcpAllowed.body.result.content[0].text).record.id, records[1].id);
    const v1Allowed = await api('/v1/memory/read', { method: 'POST', body: JSON.stringify({ ...relationshipRead, contextToken: contextTokenFor({ purpose: relationshipRead.purpose, operation: 'memory_read', input: relationshipRead, contextTags: tagsFor('relationship') }) }) });
    assert.equal(v1Allowed.body.record.id, records[2].id);
  }, { canonicalStore });
});

test('session context and purpose permission cannot be bypassed by caller-selected purpose or another room token', async () => {
  const canonicalStore = { configured: true, async search() { return { items: [], nextCursor: null }; }, async read() { throw Object.assign(new Error('memory_not_found'), { status: 404 }); } };
  await withServer(async ({ api }) => {
    const input = { query: 'Session', purpose: 'continuity_resume' };
    const wrongToken = contextTokenFor({ purpose: input.purpose, operation: 'sessions_search', input, room: ROOM_B });
    const wrong = await api('/v2/sessions/search', { method: 'POST', body: JSON.stringify({ ...input, contextToken: wrongToken }) });
    assert.equal(wrong.response.status, 403); assert.equal(wrong.body.error.code, 'scope_forbidden');
    const rightToken = contextTokenFor({ purpose: input.purpose, operation: 'sessions_search', input, room: ROOM_A });
    const right = await api('/v2/sessions/search', { method: 'POST', body: JSON.stringify({ ...input, contextToken: rightToken }) });
    assert.deepEqual(right.body.data.items.map(item => item.id), ['session-1']);
    const missing = await api('/v2/sessions/search', { method: 'POST', body: JSON.stringify(input) });
    assert.equal(missing.response.status, 403); assert.equal(missing.body.error.code, 'context_required');
    const purposeBypass = await api('/v2/memory/search', { method: 'POST', headers: { authorization: 'Bearer limited-token' }, body: JSON.stringify({ query: 'x', scopes: ['main-lab'], purpose: 'memory_curation' }) });
    assert.equal(purposeBypass.response.status, 403); assert.equal(purposeBypass.body.error.code, 'forbidden');
  }, { canonicalStore });
});

test('session route manifest rejects unsafe parents and parent-swap races', async t => {
  const canonicalStore = { configured: true, async search() { return { items: [], nextCursor: null }; },
    async read() { throw Object.assign(new Error('memory_not_found'), { status: 404 }); } };
  const assertRejected = async api => {
    const input = { query: 'Session', purpose: 'continuity_resume' };
    const token = contextTokenFor({ purpose: input.purpose, operation: 'sessions_search', input });
    const result = await api('/v2/sessions/search', { method: 'POST',
      body: JSON.stringify({ ...input, contextToken: token }) });
    assert.equal(result.response.status, 500); assert.equal(result.body.error.code, 'internal_error');
  };
  await t.test('world-writable parent', async () => withServer(async ({ api }) => assertRejected(api), {
    canonicalStore, routeManifestSetup({ dir }) { fs.chmodSync(dir, 0o777); }
  }));
  await t.test('symlink parent', async () => withServer(async ({ api }) => assertRejected(api), {
    canonicalStore, routeManifestSetup({ dir, routeManifestPath }) {
      const real = path.join(dir, 'real-routes'); const link = path.join(dir, 'linked-routes');
      fs.mkdirSync(real, { mode: 0o700 });
      fs.copyFileSync(routeManifestPath, path.join(real, 'session-routes.json'));
      fs.chmodSync(path.join(real, 'session-routes.json'), 0o600); fs.symlinkSync(real, link);
      return path.join(link, 'session-routes.json');
    }
  }));
  await t.test('parent directory swap', async () => withServer(async ({ api, routeManifestPath }) => {
    await api('/v2/status');
    const directory = path.dirname(routeManifestPath); const displaced = `${directory}-displaced`;
    const originalOpen = fs.openSync; let swapped = false;
    fs.openSync = function swappedOpen(filePath, flags, ...args) {
      if (!swapped && path.resolve(String(filePath)) === path.resolve(directory)
        && typeof flags === 'number' && (flags & fs.constants.O_DIRECTORY)) {
        swapped = true; fs.renameSync(directory, displaced); fs.mkdirSync(directory, { mode: 0o700 });
      }
      return originalOpen.call(fs, filePath, flags, ...args);
    };
    try { await assertRejected(api); }
    finally {
      fs.openSync = originalOpen;
      if (swapped) { fs.rmSync(directory, { recursive: true, force: true }); fs.renameSync(displaced, directory); }
    }
  }, { canonicalStore }));
});

test('internal identity and retention APIs enforce the existing auth, ACL and audit envelope', async () => {
  await withServer(async ({ api, fabricStore }) => {
    const evidence = { type: 'operator_attestation', issuer: 'test', observedAt: '2026-07-11T12:00:00.000Z', claims: { ticketId: 'T-1', assertion: 'same person' } };
    const created = await api('/v2/internal/identities', {
      method: 'POST', headers: { 'idempotency-key': 'identity-api-1' },
      body: JSON.stringify({ kind: 'person', externalKey: 'opaque-me', scope: 'main-lab', evidence })
    });
    assert.equal(created.response.status, 201);
    assert.equal(created.body.ok, true);
    assert.equal(created.body.data.revision, 1);
    const denied = await api('/v2/internal/identities', {
      method: 'POST', headers: { authorization: 'Bearer limited-token', 'idempotency-key': 'identity-denied' },
      body: JSON.stringify({ kind: 'person', externalKey: 'denied', scope: 'main-lab', evidence })
    });
    assert.equal(denied.response.status, 403);
    assert.ok(fabricStore.catalog.auditEvents.some(event => event.action === 'identity_create' && event.outcome === 'denied'));
    const injected = await api('/v2/internal/identities', {
      method: 'POST', headers: { 'idempotency-key': 'identity-injected' },
      body: JSON.stringify({ actor: 'forged', kind: 'person', externalKey: 'injected', scope: 'main-lab', evidence })
    });
    assert.equal(injected.response.status, 400);
    const read = await api(`/v2/internal/identities/${created.body.data.id}`);
    assert.equal(read.response.status, 200);
    assert.equal(read.body.data.kind, 'person');

    const proposal = await fabricStore.propose({ actor: 'test-actor', scope: 'main-lab', text: 'old', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' }, idempotencyKey: 'old-api' });
    const plan = await api('/v2/internal/retention/plan', { method: 'POST', body: JSON.stringify({ asOf: new Date().toISOString(), scope: 'main-lab', limit: 10 }) });
    assert.equal(plan.response.status, 200);
    assert.deepEqual(plan.body.data.candidates.map(row => row.contentId), [proposal.contentId]);
    const apply = await api('/v2/internal/retention/apply', { method: 'POST', headers: { 'idempotency-key': 'retention-api-1' }, body: JSON.stringify({ candidateIds: [proposal.contentId], expectedPlanAsOf: plan.body.data.asOf, reason: 'retention_expired' }) });
    assert.equal(apply.response.status, 200);
    assert.equal(apply.body.data.physicalDeletionPerformed, false);
    const applyReplay = await api('/v2/internal/retention/apply', { method: 'POST', headers: { 'idempotency-key': 'retention-api-1' }, body: JSON.stringify({ candidateIds: [proposal.contentId], expectedPlanAsOf: plan.body.data.asOf, reason: 'retention_expired' }) });
    assert.deepEqual(applyReplay.body.data, apply.body.data);
    const deniedRetention = await api('/v2/internal/retention/plan', { method: 'POST', headers: { authorization: 'Bearer limited-token' }, body: JSON.stringify({ asOf: new Date().toISOString(), scope: 'main-lab', limit: 10 }) });
    assert.equal(deniedRetention.response.status, 403);
    assert.ok(fabricStore.catalog.auditEvents.some(event => event.action === 'retention_plan' && event.outcome === 'denied'));
  });
});

test('explicit non-canonical candidate search filters lifecycle state and never masquerades as canonical memory', async () => {
  const fabricStore = makeStore();
  const proposal = await fabricStore.propose({ actor: 'test-actor', scope: 'main-lab', text: 'must disappear', metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z' }, idempotencyKey: 'search-filter-source' });
  await fabricStore.applyRetention({ actor: 'test-actor', idempotencyKey: 'search-filter-revoke', candidateIds: [proposal.contentId], expectedPlanAsOf: new Date().toISOString(), reason: 'revoked' }, { allowedScopes: ['main-lab'] });
  const backend = {
    kind: 'test-backend', configured: true,
    async search() { return { items: [{ id: 'safe', memory: 'safe' }, { id: 'secret', memory: 'must disappear', proposalId: proposal.id }], total: 2, source: 'test' }; }
  };
  await withServer(async ({ api }) => {
    const result = await api('/v2/memory/candidates/search', { method: 'POST', body: JSON.stringify({ scope: 'main-lab', query: 'anything', purpose: 'memory_curation' }) });
    assert.equal(result.response.status, 200);
    assert.equal(result.body.data.canonical, false);
    assert.deepEqual(result.body.data.candidates.map(item => item.id), ['safe']);
    assert.equal(JSON.stringify(result.body).includes('must disappear'), false);
  }, { fabricStore, backend });
});

test('legacy memory add queues instead of writing directly to Mem0', async () => {
  await withServer(async ({ api, getBackendAdds }) => {
    const queued = await api('/v1/memory/add', {
      method: 'POST',
      headers: { 'idempotency-key': 'legacy-event-1' },
      body: JSON.stringify({ scope: 'main-lab', text: 'Legacy client fact' })
    });
    assert.equal(queued.response.status, 200);
    assert.equal(queued.body.ok, true);
    assert.equal(queued.body.accepted, true);
    assert.equal(queued.body.queued, true);
    assert.equal(queued.body.status, 'queued');
    assert.equal(queued.body.state, 'queued');
    assert.equal(queued.body.promoted, false);
    assert.equal(queued.body.proposalId, queued.body.proposal.id);
    assert.deepEqual(queued.body.result, {
      status: 'queued',
      proposalId: queued.body.proposalId,
      canonical: false
    });
    assert.equal(queued.body.actor, 'test-actor');
    assert.equal(queued.body.scope, 'main-lab');
    assert.equal(queued.response.headers.get('deprecation'), 'true');
    assert.match(queued.response.headers.get('cache-control'), /no-store/);
    assert.equal(getBackendAdds(), 0);

    const duplicate = await api('/v1/memory/add', {
      method: 'POST',
      headers: { 'idempotency-key': 'legacy-event-1' },
      body: JSON.stringify({ scope: 'main-lab', text: 'Legacy client fact' })
    });
    assert.equal(duplicate.response.status, 200);
    assert.equal(duplicate.body.proposalId, queued.body.proposalId);
    assert.equal(duplicate.body.proposal.duplicate, true);

    const derivedFirst = await api('/v1/memory/add', { method: 'POST', body: JSON.stringify({ scope: 'main-lab', text: 'Stable legacy retry' }) });
    const derivedRetry = await api('/v1/memory/add', { method: 'POST', body: JSON.stringify({ scope: 'main-lab', text: 'Stable legacy retry' }) });
    assert.equal(derivedRetry.body.proposalId, derivedFirst.body.proposalId);
    assert.equal(derivedRetry.body.proposal.duplicate, true);
  });
});

test('legacy v1 search and MCP SSE endpoint remain available', async () => {
  const canonical = canonicalRecord('appointment', 'main-lab'); canonical.visibility = 'shared'; canonical.claim.aadSha256 = aadSha256For(canonical);
  const canonicalStore = { configured: true, async search() { return { items: [canonical], nextCursor: null }; }, async read() { return canonical; } };
  await withServer(async ({ api, baseUrl }) => {
    const search = await api('/v1/memory/search', {
      method: 'POST',
      body: JSON.stringify({ scope: 'domain:main-lab', query: 'appointment', purpose: 'operator_review' })
    });
    assert.equal(search.response.status, 200);
    assert.equal(search.body.items[0].id, canonical.id);

    const controller = new AbortController();
    const response = await fetch(`${baseUrl}/mcp/test-client/sse/test-identity`, {
      headers: { authorization: 'Bearer test-token' },
      signal: controller.signal
    });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^text\/event-stream/);
    const { value } = await response.body.getReader().read();
    const firstEvent = new TextDecoder().decode(value);
    assert.match(firstEvent, /event: endpoint/);
    assert.match(firstEvent, /\/mcp\/messages\/\?session_id=/);
    controller.abort();
  }, { canonicalStore });
});

test('REST, MCP and v1 canonical search share scopes, pagination shape and durable audit semantics', async () => {
  const canonical = canonicalRecord('Cross transport', 'main-lab'); canonical.visibility = 'shared'; canonical.claim.aadSha256 = aadSha256For(canonical);
  const canonicalStore = { configured: true, async search() { return { items: [canonical], nextCursor: null }; }, async read() { return canonical; } };
  await withServer(async ({ api, fabricStore }) => {
    const input = { query: 'cross', scopes: ['domain:main-lab'], purpose: 'operator_review', limit: 20, cursor: null, from: null, to: null };
    const rest = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify(input) });
    const legacy = await api('/v1/memory/search', { method: 'POST', body: JSON.stringify(input) });
    const initialized = await api('/mcp/test-client/cross', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }) });
    const mcp = await api('/mcp/test-client/cross', { method: 'POST', headers: { 'mcp-session-id': initialized.response.headers.get('mcp-session-id') }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'memory_search', arguments: input } }) });
    const mcpData = JSON.parse(mcp.body.result.content[0].text);
    assert.deepEqual(rest.body.data.items.map(item => item.id), [canonical.id]);
    assert.deepEqual(legacy.body.items.map(item => item.id), [canonical.id]);
    assert.deepEqual(mcpData.items.map(item => item.id), [canonical.id]);
    assert.deepEqual(rest.body.data.scopes, legacy.body.scopes);
    assert.deepEqual(rest.body.data.scopes, mcpData.scopes);
    assert.equal(rest.body.data.nextCursor, null); assert.equal(legacy.body.nextCursor, null); assert.equal(mcpData.nextCursor, null);
    assert.ok(fabricStore.catalog.auditEvents.filter(event => event.action === 'memory_search').length >= 2);
  }, { canonicalStore });
});

test('v2 validates idempotency and query limits with stable error envelopes', async () => {
  await withServer(async ({ api }) => {
    const missingKey = await api('/v2/memory/proposals', {
      method: 'POST',
      body: JSON.stringify(canonicalProposal('No key'))
    });
    assert.equal(missingKey.response.status, 400);
    assert.equal(missingKey.body.ok, false);
    assert.equal(missingKey.body.error.code, 'idempotency_key_required');

    const nonCanonicalBody = await api('/v2/memory/proposals', {
      method: 'POST',
      headers: { 'idempotency-key': 'unexpected-body-key' },
      body: JSON.stringify({ ...canonicalProposal('Unexpected field'), idempotencyKey: 'must-be-a-header' })
    });
    assert.equal(nonCanonicalBody.response.status, 400);
    assert.equal(nonCanonicalBody.body.error.code, 'invalid_request');

    const invalidRecords = [];
    const missingConfidence = canonicalRecord('Missing confidence');
    delete missingConfidence.confidence;
    invalidRecords.push(['missing-confidence', missingConfidence]);
    const nanConfidence = canonicalRecord('NaN confidence');
    nanConfidence.confidence.score = Number.NaN;
    invalidRecords.push(['nan-confidence', nanConfidence]);
    const outOfRangeConfidence = canonicalRecord('Out of range confidence');
    outOfRangeConfidence.confidence.score = 1.1;
    invalidRecords.push(['range-confidence', outOfRangeConfidence]);
    const unknownConfidence = canonicalRecord('Unknown confidence field');
    unknownConfidence.confidence.legacy = true;
    invalidRecords.push(['unknown-confidence', unknownConfidence]);
    const restrictedPlain = canonicalRecord('Restricted plaintext');
    restrictedPlain.claim = { encoding: 'plain', text: 'must be sealed' };
    invalidRecords.push(['restricted-plain', restrictedPlain]);
    for (const [idempotencyKey, record] of invalidRecords) {
      const rejected = await api('/v2/memory/proposals', {
        method: 'POST', headers: { 'idempotency-key': idempotencyKey },
        body: JSON.stringify({ record, rationale: 'invalid_contract_regression', expectedRevision: 0 })
      });
      assert.equal(rejected.response.status, 400, `${idempotencyKey} was accepted`);
      assert.equal(rejected.body.error.code, 'canonical_record_invalid');
    }

    const forbidden = await api('/v2/memory/proposals', {
      method: 'POST',
      headers: { authorization: 'Bearer limited-token', 'idempotency-key': 'limited-event-1' },
      body: JSON.stringify(canonicalProposal('Cannot propose without permission'))
    });
    assert.equal(forbidden.response.status, 403);
    assert.equal(forbidden.body.error.code, 'scope_forbidden');

    const tooLarge = await api('/v2/memory/search', {
      method: 'POST',
      body: JSON.stringify({ scope: 'main-lab', query: 'x'.repeat(4097), purpose: 'operator_review' })
    });
    assert.equal(tooLarge.response.status, 413);
    assert.equal(tooLarge.body.error.code, 'query_too_large');
  });
});

test('MCP v2 advertises the full tool contract while preserving streamable HTTP', async () => {
  await withServer(async ({ api }) => {
    const listed = await api('/mcp/test-client/test-identity', {
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    });
    assert.equal(listed.response.status, 200);
    assert.match(listed.response.headers.get('cache-control'), /no-store/);
    assert.ok(listed.response.headers.get('mcp-session-id'));
    const names = listed.body.result.tools.map(tool => tool.name);
    for (const name of ['memory_search', 'memory_read', 'memory_propose', 'memory_proposal_status', 'sessions_search', 'session_get', 'session_transcript', 'memory_status']) {
      assert.ok(names.includes(name), `${name} missing from MCP tools`);
    }
    assert.ok(names.includes('list_scopes'));
    assert.ok(names.includes('gateway_health'));

    const proposed = await api('/mcp/test-client/test-identity', {
      method: 'POST',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'memory_propose',
          arguments: { ...canonicalProposal('MCP proposal'), idempotencyKey: 'mcp-event-1' }
        }
      })
    });
    assert.equal(proposed.response.status, 200);
    assert.equal(proposed.body.result.content[0].type, 'text');
    const proposedAck = JSON.parse(proposed.body.result.content[0].text);
    assert.equal(proposedAck.status, 'queued');
    assert.equal(proposedAck.idempotencyKey, 'mcp-event-1');

    const derivedRequest = {
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'memory_propose', arguments: canonicalProposal('MCP derived retry') } })
    };
    const derived = await api('/mcp/test-client/test-identity', derivedRequest);
    const derivedRetry = await api('/mcp/test-client/test-identity', derivedRequest);
    const derivedAck = JSON.parse(derived.body.result.content[0].text);
    const derivedRetryAck = JSON.parse(derivedRetry.body.result.content[0].text);
    assert.match(derivedAck.idempotencyKey, /^mcp-[a-f0-9]{64}$/);
    assert.equal(derivedRetryAck.idempotencyKey, derivedAck.idempotencyKey);
    assert.equal(derivedRetryAck.proposalId, derivedAck.proposalId);
    assert.equal(derivedRetryAck.duplicate, true);
  });
});

test('MCP sessions enforce caps, TTL, and token revocation with policy revalidation', async () => {
  await withServer(async ({ api, registry, writeRegistry }) => {
    const opened = await api('/mcp/test-client/test-identity', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    registry.rows[0].permissions = 'memory:search';
    writeRegistry();
    const rechecked = await api('/mcp/test-client/test-identity', {
      method: 'POST', headers: { 'mcp-session-id': opened.response.headers.get('mcp-session-id') },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'memory_status', arguments: {} } })
    });
    assert.equal(rechecked.response.status, 200);
    assert.equal(rechecked.body.error.message, 'forbidden');
  });

  await withServer(async ({ api, registry, writeRegistry }) => {
    const opened = await api('/mcp/test-client/test-identity', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    const sessionId = opened.response.headers.get('mcp-session-id');
    registry.rows[0].active = false;
    writeRegistry();
    const revoked = await api('/mcp/test-client/test-identity', { method: 'POST', headers: { 'mcp-session-id': sessionId }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(revoked.response.status, 401);
    assert.equal(revoked.body.error, 'session_revoked');
    assert.match(revoked.response.headers.get('cache-control'), /no-store/);
  });

  await withServer(async ({ api }) => {
    const first = await api('/mcp/test-client/one', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    assert.equal(first.response.status, 200);
    const capped = await api('/mcp/test-client/two', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(capped.response.status, 429);
    assert.equal(capped.body.error, 'session_capacity_exceeded');
  }, { sessionOptions: { ttlMs: 60000, maxGlobal: 1, maxPerActor: 5 } });

  await withServer(async ({ api }) => {
    await api('/mcp/test-client/one', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    const actorCapped = await api('/mcp/test-client/two', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(actorCapped.response.status, 429);
    assert.equal(actorCapped.body.error, 'session_capacity_exceeded');
  }, { sessionOptions: { ttlMs: 60000, maxGlobal: 5, maxPerActor: 1 } });

  let now = 1000;
  await withServer(async ({ api }) => {
    const opened = await api('/mcp/test-client/test-identity', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    now += 11;
    const expired = await api('/mcp/test-client/test-identity', { method: 'POST', headers: { 'mcp-session-id': opened.response.headers.get('mcp-session-id') }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
    assert.equal(expired.response.status, 401);
    assert.equal(expired.body.error, 'session_expired');
  }, { sessionOptions: { ttlMs: 10, maxGlobal: 5, maxPerActor: 5 }, clock: () => now });
});

test('session reader capability is explicit and unconfigured access returns 503', async () => {
  await withServer(async ({ api }) => {
    const initialized = await api('/mcp/test-client/test-identity', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }) });
    assert.equal(initialized.body.result.capabilities.experimental.sessionReader, false);
    const input = { query: 'x', purpose: 'continuity_resume' };
    const contextToken = contextTokenFor({ purpose: input.purpose, operation: 'sessions_search', input });
    const unavailable = await api('/v2/sessions/search', { method: 'POST', body: JSON.stringify({ ...input, contextToken }) });
    assert.equal(unavailable.response.status, 503);
    assert.equal(unavailable.body.error.code, 'session_reader_unconfigured');
  }, { configuredSessionReader: false });
});

test('session transcript defaults redacted and requires raw decrypt permission for original', async () => {
  await withServer(async ({ api }) => {
    const redactedToken = contextTokenFor({ purpose: 'continuity_resume', operation: 'session_transcript', input: { sessionId: 'session-1', view: 'redacted' } });
    const transcript = await api(`/v2/sessions/session-1/transcript?purpose=continuity_resume&contextToken=${encodeURIComponent(redactedToken)}`);
    assert.equal(transcript.response.status, 200);
    assert.equal(transcript.body.data.view, 'redacted');
    assert.match(transcript.response.headers.get('cache-control'), /no-store/);

    const limitedToken = contextTokenFor({ actor: 'limited-actor', purpose: 'incident_debug', operation: 'session_transcript', input: { sessionId: 'session-1', view: 'original' } });
    const forbidden = await api(`/v2/sessions/session-1/transcript?view=original&purpose=incident_debug&contextToken=${encodeURIComponent(limitedToken)}`, {
      headers: { authorization: 'Bearer limited-token' }
    });
    assert.equal(forbidden.response.status, 403);
    assert.equal(forbidden.body.error.code, 'raw_decrypt_forbidden');

    const tirreniaContext = contextTokenFor({ actor: 'tirrenia-actor', purpose: 'operator_review', operation: 'session_get',
      input: { sessionId: 'session-1' }, conversationKind: 'session', canonicalScopes: ['tirrenia'] });
    const hidden = await api(`/v2/sessions/session-1?purpose=operator_review&contextToken=${encodeURIComponent(tirreniaContext)}`, {
      headers: { authorization: 'Bearer tirrenia-token' }
    });
    assert.equal(hidden.response.status, 404);
    assert.equal(hidden.body.error.code, 'session_not_found');

    const missingPurpose = await api('/v2/sessions/session-1');
    assert.equal(missingPurpose.response.status, 400);
    assert.equal(missingPurpose.body.error.code, 'purpose_required');
  });
});

test('durable decrypt-intent audit failure prevents the session reader from decrypting RAW', async () => {
  const fabricStore = makeStore();
  const originalAudit = fabricStore.audit.bind(fabricStore);
  fabricStore.audit = async event => { if (event.action === 'raw_decrypt_intent') throw new Error('audit offline'); return originalAudit(event); };
  let transcriptCalls = 0;
  const sessionReader = {
    configured: true, kind: 'decrypt-spy',
    async search() { return { items: [] }; },
    async get({ id }) { return { id, scope: 'main-lab', ownerActor: 'test-actor', conversationKind: 'group', contextTags: { conversation: [ROOM_A], room: [ROOM_A] } }; },
    async transcript() { transcriptCalls += 1; return { id: 'session-1', view: 'original', items: [], nextCursor: null }; }
  };
  await withServer(async ({ api }) => {
    const contextToken = contextTokenFor({ purpose: 'incident_debug', operation: 'session_transcript', input: { sessionId: 'session-1', view: 'original' } });
    const result = await api(`/v2/sessions/session-1/transcript?view=original&purpose=incident_debug&contextToken=${encodeURIComponent(contextToken)}`);
    assert.equal(result.response.status, 503); assert.equal(result.body.error.code, 'audit_unavailable'); assert.equal(transcriptCalls, 0);
  }, { fabricStore, sessionReader });
});

test('v2 authentication failures and unknown routes retain the v2 envelope', async () => {
  await withServer(async ({ api }) => {
    const unauthorized = await api('/v2/status', { headers: { authorization: 'Bearer wrong-token' } });
    assert.equal(unauthorized.response.status, 401);
    assert.equal(unauthorized.body.ok, false);
    assert.equal(unauthorized.body.error.code, 'invalid_token');

    const missing = await api('/v2/unknown');
    assert.equal(missing.response.status, 404);
    assert.equal(missing.body.ok, false);
    assert.equal(missing.body.error.code, 'not_found');
    assert.equal(JSON.stringify(missing.body).includes('/v2/unknown'), false);

    const providerFailure = await api('/v2/memory/candidates/search', { method: 'POST', body: JSON.stringify({ scope: 'main-lab', query: 'explode', purpose: 'memory_curation' }) });
    assert.equal(providerFailure.response.status, 500);
    assert.equal(providerFailure.body.error.code, 'internal_error');
    assert.equal(JSON.stringify(providerFailure.body).includes('/secret/path'), false);
    assert.equal(JSON.stringify(providerFailure.body).includes('private provider response'), false);
  });
});

test('audit and catalog outages return controlled 503 responses for auth, search, and status', async () => {
  const auditDown = makeStore();
  auditDown.audit = async () => { throw new Error('database offline'); };
  await withServer(async ({ api }) => {
    const auth = await api('/v2/status', { headers: { authorization: 'Bearer wrong-token' } });
    assert.equal(auth.response.status, 503);
    assert.equal(auth.body.error.code, 'audit_unavailable');

    const search = await api('/v2/memory/candidates/search', {
      method: 'POST',
      body: JSON.stringify({ scope: 'main-lab', query: 'appointment', purpose: 'memory_curation' })
    });
    assert.equal(search.response.status, 503);
    assert.equal(search.body.error.code, 'audit_unavailable');
  }, { fabricStore: auditDown });

  const catalogDown = makeStore();
  catalogDown.health = async () => { throw new Error('pool exhausted'); };
  await withServer(async ({ api }) => {
    const status = await api('/v2/status');
    assert.equal(status.response.status, 503);
    assert.equal(status.body.error.code, 'catalog_unavailable');
  }, { fabricStore: catalogDown });
});

test('memory read and proposal status apply current policy before ownership without an existence oracle', async () => {
  await withServer(async ({ api, fabricStore, registry, writeRegistry }) => {
    const proposed = await api('/v2/memory/proposals', {
      method: 'POST',
      headers: { 'idempotency-key': 'oracle-event-1' },
      body: JSON.stringify(canonicalProposal('Secret proposal'))
    });
    const id = proposed.body.data.proposalId;
    let decryptions = 0;
    const originalGet = fabricStore.rawStore.get.bind(fabricStore.rawStore);
    fabricStore.rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };

    const deniedExisting = await api(`/v2/memory/proposals/${id}`, { headers: { authorization: 'Bearer search-token' } });
    const deniedMissing = await api('/v2/memory/proposals/00000000-0000-0000-0000-000000000000', { headers: { authorization: 'Bearer search-token' } });
    const deniedScope = await api(`/v2/memory/proposals/${id}`, { headers: { authorization: 'Bearer tirrenia-token' } });
    assert.equal(deniedExisting.response.status, 404);
    assert.equal(deniedMissing.response.status, 404);
    assert.equal(deniedScope.response.status, 404);
    assert.equal(deniedExisting.body.error.code, 'memory_not_found');
    assert.equal(deniedMissing.body.error.code, 'memory_not_found');
    assert.equal(deniedScope.body.error.code, 'memory_not_found');
    assert.equal(decryptions, 0);
    assert.match(deniedExisting.response.headers.get('cache-control'), /no-store/);

    const ownerPolicy = registry.rows.find(row => row.token === 'test-token');
    const assertHiddenByCurrentPolicy = async () => {
      const paths = [
        `/v2/memory/proposals/${id}`,
        '/v2/memory/proposals/00000000-0000-0000-0000-000000000000',
        `/v2/memory/${id}?purpose=operator_review`,
        '/v2/memory/00000000-0000-0000-0000-000000000000?purpose=operator_review'
      ];
      const results = await Promise.all(paths.map(pathname => api(pathname)));
      for (const result of results) {
        assert.equal(result.response.status, 404);
        assert.equal(result.body.error.code, 'memory_not_found');
        assert.deepEqual(result.body.error, results[0].body.error);
      }
    };

    ownerPolicy.mode = 'scoped';
    ownerPolicy.allowedScopes = 'tirrenia';
    writeRegistry();
    await assertHiddenByCurrentPolicy();
    assert.equal(decryptions, 0, 'scope revocation must deny before decrypting RAW');

    ownerPolicy.mode = 'deny';
    ownerPolicy.allowedScopes = 'main-lab';
    writeRegistry();
    await assertHiddenByCurrentPolicy();
    assert.equal(decryptions, 0, 'deny mode must deny before decrypting RAW');
  }, { canonicalStore: { configured: true, async read() { throw Object.assign(new Error('memory_not_found'), { status: 404 }); }, async search() { return { items: [], nextCursor: null }; } } });
});

test('v2 rejects unregistered scopes and malformed or oversized JSON with envelopes', async () => {
  await withServer(async ({ api }) => {
    const unknownScope = await api('/v2/memory/proposals', {
      method: 'POST',
      headers: { 'idempotency-key': 'unknown-scope-1' },
      body: JSON.stringify(canonicalProposal('No routing target', 'not-registered'))
    });
    assert.equal(unknownScope.response.status, 400);
    assert.equal(unknownScope.body.error.code, 'scope_unregistered');

    const invalid = await api('/v2/memory/proposals', {
      method: 'POST',
      body: '{bad json'
    });
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.body.error.code, 'invalid_json');

    const oversized = await api('/v2/memory/proposals', {
      method: 'POST',
      body: JSON.stringify({ scope: 'main-lab', text: 'x'.repeat(270000) })
    });
    assert.equal(oversized.response.status, 413);
    assert.equal(oversized.body.error.code, 'body_too_large');
  });
});

test('health is minimal, status is privileged, and query tokens work only on legacy SSE', async () => {
  await withServer(async ({ api, baseUrl }) => {
    const healthResponse = await fetch(`${baseUrl}/health`);
    const health = await healthResponse.json();
    assert.deepEqual(Object.keys(health).sort(), ['ok', 'service', 'version']);

    const status = await api('/v2/status');
    assert.equal(status.response.status, 200);
    assert.equal(status.body.data.fabricStore.configured, true);
    const statusDenied = await api('/v2/status', { headers: { authorization: 'Bearer limited-token' } });
    assert.equal(statusDenied.response.status, 403);

    const queryRejected = await fetch(`${baseUrl}/v2/status?access_token=test-token`);
    assert.equal(queryRejected.status, 401);

    const controller = new AbortController();
    const legacy = await fetch(`${baseUrl}/mcp/test-client/sse/test-identity?access_token=test-token`, { signal: controller.signal });
    assert.equal(legacy.status, 200);
    await legacy.body.cancel();
    controller.abort();

    const streamableGet = await fetch(`${baseUrl}/mcp/test-client/test-identity`, { headers: { authorization: 'Bearer test-token' } });
    assert.equal(streamableGet.status, 405);
    assert.equal(streamableGet.headers.get('allow'), 'POST, DELETE');
  });
});
