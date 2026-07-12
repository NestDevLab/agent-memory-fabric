import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FabricStore, MemoryCatalog, MemoryRawStore } from '../src/fabric-store.mjs';
import { aadSha256For } from '../src/amf-memory-record-validator.mjs';
import { createAgentMemoryFabricServer } from '../src/server.mjs';

const testPolicyPath = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'config', 'policies.example.json');

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

async function withServer(run, { sessionOptions, clock, configuredSessionReader = true, fabricStore: fabricStoreOverride, backend: backendOverride } = {}) {
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
        allowedScopes: 'main-lab',
        permissions: 'memory:search,memory:read,sessions:read'
      },
      {
        tokenSha256: '556510a5888bb3f061617bfec75649cbe0d04f8c5efe6a2807a9ca3ef231f382',
        active: true,
        actor: 'search-only',
        mode: 'scoped',
        allowedScopes: 'main-lab',
        permissions: 'memory:search'
      },
      {
        token: 'tirrenia-token',
        active: true,
        actor: 'tirrenia-actor',
        mode: 'scoped',
        allowedScopes: 'tirrenia',
        permissions: 'memory:read,sessions:read'
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
  const sessionReader = {
    kind: 'test-session-reader',
    configured: true,
    async search({ query }) { return { items: [{ id: 'session-1', title: query, scope: 'main-lab', ownerActor: 'test-actor' }] }; },
    async get({ id }) { return { id, title: 'Session', scope: 'main-lab', ownerActor: 'test-actor' }; },
    async transcript({ id, view }) { return { id, view, messages: [] }; }
  };
  const server = createAgentMemoryFabricServer({ backend, fabricStore, sessionReader: configuredSessionReader ? sessionReader : undefined, sessionOptions, clock, policyPath: testPolicyPath });
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
    await run({ api, baseUrl, fabricStore, registry, writeRegistry, getBackendAdds: () => backendAdds });
  } finally {
    await new Promise(resolve => server.close(resolve));
    if (originalRegistry === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH;
    else process.env.MEM0_AUTH_REGISTRY_PATH = originalRegistry;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('v2 REST uses envelopes, queues idempotently and reads encrypted proposals', async () => {
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
    const read = await api(`/v2/memory/${first.body.data.proposalId}`);
    assert.equal(read.response.status, 200);
    assert.equal(Buffer.from(read.body.data.record.claim.ciphertext, 'base64').toString('utf8'), 'Remember the appointment');
    assert.equal(read.body.data.rationale, 'test_evidence');
    assert.ok(fabricStore.catalog.auditEvents.some(event => event.action === 'memory_read'));
  });
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
  await withServer(async ({ api, baseUrl }) => {
    const search = await api('/v1/memory/search', {
      method: 'POST',
      body: JSON.stringify({ scope: 'main-lab', query: 'appointment' })
    });
    assert.equal(search.response.status, 200);
    assert.equal(search.body.result.items[0].memory, 'appointment');

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
  });
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
      body: JSON.stringify({ scope: 'main-lab', query: 'x'.repeat(4097) })
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
    const unavailable = await api('/v2/sessions/search', { method: 'POST', body: JSON.stringify({ query: 'x', purpose: 'conversation_recall' }) });
    assert.equal(unavailable.response.status, 503);
    assert.equal(unavailable.body.error.code, 'session_reader_unconfigured');
  }, { configuredSessionReader: false });
});

test('session transcript defaults redacted and requires raw decrypt permission for original', async () => {
  await withServer(async ({ api }) => {
    const transcript = await api('/v2/sessions/session-1/transcript?purpose=conversation_recall');
    assert.equal(transcript.response.status, 200);
    assert.equal(transcript.body.data.view, 'redacted');
    assert.match(transcript.response.headers.get('cache-control'), /no-store/);

    const forbidden = await api('/v2/sessions/session-1/transcript?view=original&purpose=incident_debug', {
      headers: { authorization: 'Bearer limited-token' }
    });
    assert.equal(forbidden.response.status, 403);
    assert.equal(forbidden.body.error.code, 'raw_decrypt_forbidden');

    const hidden = await api('/v2/sessions/session-1?purpose=conversation_recall', {
      headers: { authorization: 'Bearer tirrenia-token' }
    });
    assert.equal(hidden.response.status, 404);
    assert.equal(hidden.body.error.code, 'session_not_found');

    const missingPurpose = await api('/v2/sessions/session-1');
    assert.equal(missingPurpose.response.status, 400);
    assert.equal(missingPurpose.body.error.code, 'purpose_required');
  });
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

    const providerFailure = await api('/v2/memory/search', { method: 'POST', body: JSON.stringify({ scope: 'main-lab', query: 'explode' }) });
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

    const search = await api('/v2/memory/search', {
      method: 'POST',
      body: JSON.stringify({ scope: 'main-lab', query: 'appointment' })
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
        `/v2/memory/${id}`,
        '/v2/memory/00000000-0000-0000-0000-000000000000'
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
  });
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
