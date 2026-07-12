import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildContextRequest } from '../src/access-contract.mjs';
import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';
import { FabricStore, MemoryCatalog, MemoryRawStore } from '../src/fabric-store.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import {
  OBSERVATION_NORMALIZATION_VERSION,
  deriveEventIdV2,
  deriveLogicalMessageIds,
  deriveSessionIdV2,
  opaqueContextTag
} from '../src/ingest/raw-projection-v2.mjs';
import {
  provisionRecallConsumer,
  RECALL_CONSUMER_ACTOR,
  RECALL_CONSUMER_CONTEXT_KEY_VERSION,
  RECALL_CONSUMER_SESSION_OWNER_ACTORS
} from '../src/operator/recall-consumer-provisioning.mjs';
import { provisionSessionRoutes } from '../src/operator/session-route-provisioning.mjs';
import { createAgentMemoryFabricServer } from '../src/server.mjs';

const COLLECTOR = RECALL_CONSUMER_SESSION_OWNER_ACTORS[0];
const SOURCE = 'ct110-hermes-vitae';
const INGEST_KEY = Buffer.alloc(32, 41).toString('base64');
const LOGICAL_KEY = Buffer.alloc(32, 42).toString('base64');
const ROUTING_KEY = Buffer.alloc(32, 43).toString('base64');
const COLLECTOR_TOKEN = 'synthetic-collector-token';
const POLICY_REVISION = 'vitae-recall-e2e-v1';
const GROUP_SCOPES = ['room:vitae:synthetic-group-topic', 'person:synthetic-member',
  'relationship:vitae:synthetic-member'];
const KEY_RING = {
  keys: { 'ct110-hermes-vitae-v1': INGEST_KEY }, digestKey: INGEST_KEY,
  authorizations: { 'ct110-hermes-vitae-v1': { actors: [COLLECTOR], sourceInstances: [SOURCE] } },
  logicalMessageKeys: { currentKeyVersion: 'logical-v1', keys: { 'logical-v1': LOGICAL_KEY } }
};
const DIGEST_KEY = normalizeIngestKeyRing(KEY_RING).digestKey;
const LOGICAL_RING = KEY_RING.logicalMessageKeys;

function tag(namespace, literal) { return opaqueContextTag(namespace, literal, ROUTING_KEY, 'routing-v1'); }
const CONTEXT_TAGS = { conversation: [tag('conversation', 'telegram:joseph-dm')], room: [tag('room', 'telegram:joseph-dm')] };
const EXTRA_CONVERSATIONS = Array.from({ length: 70 }, (_, index) => ({
  nativeId: `candidate-${index}`, tag: tag('conversation', `telegram:candidate-${index}`) }));
const TOKEN_CONTEXT_TAGS = { conversation: [CONTEXT_TAGS.conversation[0],
  ...EXTRA_CONVERSATIONS.map(item => item.tag)].sort(), room: CONTEXT_TAGS.room };

function observation({ sequence, role = 'user', contentType = 'text', value, partCount = 1,
  nativeMessageId = `message-${sequence}`, nativeRevision = 1, authoritativeDeletion = false,
  contextTags = CONTEXT_TAGS, nativeConversationId = 'joseph-dm' }) {
  const sender = role === 'assistant' ? 'agent:vitae' : role === 'user' ? 'person:joseph' : `internal:${role}`;
  const senderTag = tag('sender', sender); const direction = role === 'assistant' ? 'outbound' : 'inbound';
  const logical = { canonicalSenderIdentity: sender, senderTag, conversationTag: contextTags.conversation[0],
    direction, nativePlatform: 'telegram', nativeConversationId, nativeMessageId };
  const derivedLogical = deriveLogicalMessageIds(logical, LOGICAL_RING);
  const normalized = { role, contentType, value };
  const rawBytes = Buffer.from(JSON.stringify({ sequence, privateRaw: `RAW_MUST_NOT_LEAK_${sequence}` }));
  const sessionId = deriveSessionIdV2({ sourceKind: 'hermes', conversationTag: contextTags.conversation[0] });
  const eventId = deriveEventIdV2({ sourceKind: 'hermes', observationClass: 'native', rawBytes });
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId,
    occurredAt: new Date(Date.parse('2026-07-12T20:00:00Z') + (sequence * 1000)).toISOString(),
    source: { runtime: 'hermes', subtype: 'message' }, logical, normalized,
    raw: { encoding: 'base64', line: rawBytes.toString('base64'), lineEnding: 'none' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId,
    logicalMessageId: derivedLogical.logicalMessageId, logicalMessageAliases: derivedLogical.aliases,
    derivationVersion: 'amf-logical-message/v1', keyVersion: derivedLogical.keyVersion,
    sourceKind: 'hermes', observationClass: 'native', direction, conversationKind: 'group',
    contextTags: { sender: [senderTag], ...contextTags }, subtype: 'message', occurredAt: event.occurredAt,
    editedAt: nativeRevision > 1 ? event.occurredAt : null, nativeRevision, sourceSequence: sequence,
    authoritativeDeletion,
    role, contentType, contentParts: partCount, hasContent: partCount > 0,
    normalizationVersion: OBSERVATION_NORMALIZATION_VERSION,
    normalizedPayloadDigest: normalizedObservationDigest({ event }, DIGEST_KEY) };
  return { event, projection };
}

function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}

function asRoot(operation) {
  const original = process.geteuid; process.geteuid = () => 0;
  try { return operation(); } finally { process.geteuid = original; }
}

test('collector-owned Hermes RAW is recalled by Vitae through exact delegation and bounded redacted text', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-vitae-recall-e2e-'));
  const authPath = path.join(root, 'auth.json'); const policyPath = path.join(root, 'policy.json');
  const contextPath = path.join(root, 'context.json'); const routeManifestPath = path.join(root, 'session-routes.json');
  const backups = path.join(root, 'backups');
  const handoffs = path.join(root, 'handoffs'); const outboxRoot = path.join(root, 'outbox');
  fs.mkdirSync(backups, { mode: 0o700 }); fs.mkdirSync(handoffs, { mode: 0o700 });
  privateJson(authPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update(COLLECTOR_TOKEN).digest('hex'),
    active: true, actor: COLLECTOR, mode: 'scoped', allowedScopes: [`agent:${COLLECTOR}`],
    permissions: ['memory:status', 'raw:ingest'] }] });
  privateJson(policyPath, { actors: { [COLLECTOR]: { mode: 'scoped', allowedScopes: [`agent:${COLLECTOR}`] } },
    scopes: { [`agent:${COLLECTOR}`]: { backendUserId: COLLECTOR } } });
  const oldContextRing = { currentKeyVersion: 'ctx-existing-v1',
    keys: { 'ctx-existing-v1': Buffer.alloc(32, 44).toString('base64') } };
  privateJson(contextPath, oldContextRing);
  const handoffPath = path.join(handoffs, 'vitae');
  const previousRegistry = process.env.MEM0_AUTH_REGISTRY_PATH;
  let server;
  try {
    const serviceOwnerUid = process.geteuid();
    asRoot(() => provisionRecallConsumer({ authRegistryPath: authPath, policyPath, contextKeyRingPath: contextPath,
      handoffPath, backupRoot: backups, backendUserId: 'openmemory', serviceOwnerUid,
      additionalScopes: GROUP_SCOPES }));
    const bearer = fs.readFileSync(path.join(handoffPath, 'bearer.token'), 'utf8').trim();
    const consumerRing = JSON.parse(fs.readFileSync(path.join(handoffPath, 'context-key-ring.json'), 'utf8'));
    const serverRing = JSON.parse(fs.readFileSync(contextPath, 'utf8'));
    process.env.MEM0_AUTH_REGISTRY_PATH = authPath;
    const catalog = new MemoryCatalog(); let tick = Date.parse('2026-07-12T20:00:00Z');
    const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 45).toString('base64') }),
      catalog, ingestKeyRing: KEY_RING, legacyV1Writes: false, clock: () => new Date(tick += 1) });
    const verifier = new ContextTokenVerifier({ keyRing: serverRing, policyRevision: POLICY_REVISION,
      clock: () => Date.parse('2026-07-12T20:05:00Z') });
    const routeInputPath = path.join(root, 'session-routes.input.json');
    privateJson(routeInputPath, { schema: 'amf.session-route-input/v2', bindings: [{
      actor: RECALL_CONSUMER_ACTOR, canonicalScope: 'room:vitae:synthetic-group-topic',
      conversationKind: 'group', contextTags: TOKEN_CONTEXT_TAGS,
      keyVersion: RECALL_CONSUMER_CONTEXT_KEY_VERSION
    }] });
    asRoot(() => provisionSessionRoutes({ inputPath: routeInputPath, contextKeyRingPath: contextPath,
      manifestPath: routeManifestPath, serviceOwnerUid }));
    const canonicalStore = { configured: true, kind: 'synthetic-canonical',
      async search({ scopes }) { return { items: [], nextCursor: null, scopes }; },
      async read() { throw Object.assign(new Error('memory_not_found'), { status: 404 }); },
      routingContext() { return null; } };
    server = createAgentMemoryFabricServer({ fabricStore: store, canonicalStore, contextVerifier: verifier,
      policyPath, routeManifestPath });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = async (pathname, token, options = {}) => {
      const response = await fetch(`${base}${pathname}`, { ...options,
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(options.headers || {}) } });
      const text = await response.text(); return { response, body: text ? JSON.parse(text) : null };
    };
    const outbox = new EncryptedOutbox({ rootPath: outboxRoot, encryptionKey: INGEST_KEY, digestKey: INGEST_KEY,
      sourceInstanceId: SOURCE, actorId: COLLECTOR, keyId: 'ct110-hermes-vitae-v1' });
    const observations = [
      observation({ sequence: 1, role: 'user', value: 'Appuntamento alle 17:00.' }),
      observation({ sequence: 2, role: 'assistant', value: [{ type: 'output_text', text: 'Sto arrivando.' }] }),
      observation({ sequence: 3, role: 'system', value: 'SYSTEM_PRIVATE' }),
      observation({ sequence: 4, role: 'tool', contentType: 'tool', value: 'TOOL_PRIVATE' }),
      observation({ sequence: 5, role: 'user', contentType: 'structured', value: { text: 'STRUCTURED_PRIVATE' } }),
      observation({ sequence: 6, role: 'user', value: [{ type: 'audio', text: 'AUDIO_PRIVATE', path: '/private/audio' }] }),
      observation({ sequence: 7, role: 'user', value: '😀'.repeat(3000) }),
      ...Array.from({ length: 263 }, (_, index) => observation({ sequence: index + 8,
        role: index % 2 ? 'assistant' : 'user', value: index === 252
          ? `Conversazione contestata oltre i primi dodici eventi ${'x'.repeat(5000)}`
          : index === 260 ? 'Riconfermo l’appuntamento recente alle 17:00.'
            : `bounded-${index}-${'x'.repeat(5000)}` })),
      observation({ sequence: 271, nativeMessageId: 'edited-message', nativeRevision: 1,
        value: 'canonical-version-preferred' }),
      observation({ sequence: 272, nativeMessageId: 'edited-message', nativeRevision: 2,
        value: 'canonical-version-preferred' }),
      observation({ sequence: 273, nativeMessageId: 'deleted-message', authoritativeDeletion: true,
        value: 'canonical-deleted-private' }),
      observation({ sequence: 274, nativeMessageId: 'conflicted-message', value: 'canonical-conflict-a' }),
      observation({ sequence: 275, nativeMessageId: 'conflicted-message', value: 'canonical-conflict-b' }),
      ...EXTRA_CONVERSATIONS.map((conversation, index) => observation({ sequence: 300 + index,
        nativeConversationId: conversation.nativeId, nativeMessageId: `candidate-message-${index}`,
        contextTags: { conversation: [conversation.tag], room: CONTEXT_TAGS.room },
        value: `candidate-match-${index}` })),
      observation({ sequence: 400, value: 'Appuntamento recentissimo confermato.' })
    ];
    for (const [index, item] of observations.entries()) {
      const envelope = outbox.encrypt(item);
      if (index === 0) {
        const result = await call('/v2/ingest/raw-events', COLLECTOR_TOKEN, { method: 'POST',
          body: JSON.stringify({ sourceInstanceId: SOURCE, projection: item.projection, envelope }) });
        assert.equal(result.response.status, 201, JSON.stringify(result.body));
      } else {
        const result = await store.ingestRawEvent({ actor: COLLECTOR, sourceInstanceId: SOURCE,
          projection: item.projection, envelope });
        assert.equal(result.status, 'stored');
      }
    }
    assert.equal((await catalog.getSession(observations[0].projection.sessionId)).eventCount, 276);
    const sessionId = observations[0].projection.sessionId;
    const reader = store.createSessionReader();
    assert.equal((await reader.search({ actor: RECALL_CONSUMER_ACTOR,
      ownerActors: [RECALL_CONSUMER_ACTOR], query: '', limit: 20,
      context: { contextTags: CONTEXT_TAGS } })).items.length, 0);
    assert.equal((await reader.search({ actor: RECALL_CONSUMER_ACTOR,
      ownerActors: [RECALL_CONSUMER_ACTOR, COLLECTOR], query: '', limit: 20,
      context: { contextTags: CONTEXT_TAGS } })).items.length, 1);
    const boundedReader = store.createSessionReader({ textScanMaxCiphertextBytes: 32 * 1024 });
    let boundedCursor = null; let boundedCalls = 0; let boundedFound = false;
    do {
      const page = await boundedReader.search({ actor: RECALL_CONSUMER_ACTOR,
        ownerActors: [RECALL_CONSUMER_ACTOR, COLLECTOR], query: 'contestata', cursor: boundedCursor,
        limit: 1, context: { contextTags: TOKEN_CONTEXT_TAGS } });
      boundedCalls += 1;
      boundedFound ||= page.items.some(item => item.id === sessionId);
      boundedCursor = page.nextCursor;
    } while (!boundedFound && boundedCursor && boundedCalls < 300);
    assert.equal(boundedFound, true, 'budget continuation must eventually scan the older session suffix');
    assert.ok(boundedCalls > 1, 'fixture must cross at least one ciphertext budget boundary');
    const originalObservationIds = new Set(); let originalCursor = null;
    do {
      const page = await reader.transcript({ actor: COLLECTOR, ownerActors: [COLLECTOR], id: sessionId,
        view: 'original', cursor: originalCursor, limit: 100 });
      for (const item of page.items) originalObservationIds.add(item.eventId);
      originalCursor = page.nextCursor;
    } while (originalCursor);
    for (const sequence of [271, 272, 273, 274, 275]) {
      const eventId = observations.find(item => item.projection.sourceSequence === sequence).projection.eventId;
      assert.equal(originalObservationIds.has(eventId), true,
        `original transcript must retain observation ${sequence}`);
    }

    let nonce = 0;
    const contextToken = (operation, input, ring = consumerRing) => issueContextToken({ actor: RECALL_CONSUMER_ACTOR,
      runtime: 'principia', profile: 'vitae', conversationKind: 'group', contextTags: TOKEN_CONTEXT_TAGS,
      canonicalScopes: GROUP_SCOPES,
      purpose: 'conversation_recall', policyRevision: POLICY_REVISION,
      issuedAt: '2026-07-12T20:04:00Z', expiresAt: '2026-07-12T20:06:00Z',
      nonce: `vitae_e2e_nonce_${String(++nonce).padStart(4, '0')}`, requestDigest: requestDigest(buildContextRequest(operation, input)) }, ring);
    const getWithContext = (pathname, operation, input, ring = consumerRing) => {
      assert.equal(pathname.includes('contextToken'), false);
      for (const scope of GROUP_SCOPES) assert.equal(pathname.includes(scope), false);
      return call(pathname, bearer, { headers: { 'x-amf-context-token': contextToken(operation, input, ring) } });
    };
    const searchInput = { query: 'appuntament', limit: 20, purpose: 'conversation_recall' };
    const search = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({ ...searchInput,
      contextToken: contextToken('sessions_search', searchInput) }) });
    assert.equal(search.response.status, 200, JSON.stringify(search.body));
    assert.deepEqual(search.body.data.items.map(item => item.id), [sessionId]);
    const candidateIds = []; let candidateCursor = null;
    do {
      const candidateInput = { query: 'candidate-match', limit: 20, cursor: candidateCursor,
        purpose: 'conversation_recall' };
      const candidatePage = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({
        ...candidateInput, contextToken: contextToken('sessions_search', candidateInput) }) });
      assert.equal(candidatePage.response.status, 200, JSON.stringify(candidatePage.body));
      candidateIds.push(...candidatePage.body.data.items.map(item => item.id));
      candidateCursor = candidatePage.body.data.nextCursor;
    } while (candidateCursor);
    assert.equal(candidateIds.length, 70); assert.equal(new Set(candidateIds).size, 70);
    const provisionedAuth = JSON.parse(fs.readFileSync(authPath, 'utf8'));
    const provisionedPolicy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
    const baseOnlyAuth = structuredClone(provisionedAuth);
    baseOnlyAuth.rows.find(row => row.actor === RECALL_CONSUMER_ACTOR).allowedScopes =
      baseOnlyAuth.rows.find(row => row.actor === RECALL_CONSUMER_ACTOR).allowedScopes
        .filter(scope => !GROUP_SCOPES.includes(scope));
    const baseOnlyPolicy = structuredClone(provisionedPolicy);
    baseOnlyPolicy.actors[RECALL_CONSUMER_ACTOR].allowedScopes =
      baseOnlyPolicy.actors[RECALL_CONSUMER_ACTOR].allowedScopes.filter(scope => !GROUP_SCOPES.includes(scope));
    for (const scope of GROUP_SCOPES) delete baseOnlyPolicy.scopes[scope];
    privateJson(authPath, baseOnlyAuth); privateJson(policyPath, baseOnlyPolicy);
    const unscopedGroup = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({
      ...searchInput, contextToken: contextToken('sessions_search', searchInput) }) });
    assert.equal(unscopedGroup.response.status, 403);
    assert.equal(unscopedGroup.body.error.code, 'scope_forbidden');
    privateJson(authPath, provisionedAuth); privateJson(policyPath, provisionedPolicy);
    const historicalInput = { query: 'Appuntamento alle 17', limit: 20, from: null,
      to: '2026-07-12T20:00:10.000Z', purpose: 'conversation_recall' };
    const historical = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({
      ...historicalInput, contextToken: contextToken('sessions_search', historicalInput) }) });
    assert.equal(historical.response.status, 200, JSON.stringify(historical.body));
    assert.deepEqual(historical.body.data.items.map(item => item.id), [sessionId]);
    const memoryInput = { query: 'appuntamento', scopes: GROUP_SCOPES, purpose: 'conversation_recall' };
    const memory = await call('/v2/memory/search', bearer, { method: 'POST', body: JSON.stringify({ ...memoryInput,
      contextToken: contextToken('memory_search', memoryInput) }) });
    assert.equal(memory.response.status, 200, JSON.stringify(memory.body));
    assert.deepEqual(memory.body.data.scopes, GROUP_SCOPES);
    const outsideInput = { query: 'appuntamento', scopes: ['room:vitae:outside'], purpose: 'conversation_recall' };
    const outside = await call('/v2/memory/search', bearer, { method: 'POST', body: JSON.stringify({ ...outsideInput,
      contextToken: contextToken('memory_search', outsideInput) }) });
    assert.equal(outside.response.status, 403); assert.equal(outside.body.error.code, 'scope_forbidden');

    const wrongTags = { conversation: [tag('conversation', 'telegram:other-group')],
      room: [tag('room', 'telegram:other-group')] };
    const wrongRoomToken = issueContextToken({ actor: RECALL_CONSUMER_ACTOR, runtime: 'principia', profile: 'vitae',
      conversationKind: 'group', contextTags: wrongTags, purpose: 'conversation_recall',
      canonicalScopes: GROUP_SCOPES,
      policyRevision: POLICY_REVISION, issuedAt: '2026-07-12T20:04:00Z', expiresAt: '2026-07-12T20:06:00Z',
      nonce: `vitae_e2e_nonce_${String(++nonce).padStart(4, '0')}`,
      requestDigest: requestDigest(buildContextRequest('sessions_search', searchInput)) }, consumerRing);
    const wrongRoom = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({ ...searchInput,
      contextToken: wrongRoomToken }) });
    assert.equal(wrongRoom.response.status, 403); assert.equal(wrongRoom.body.error.code, 'scope_forbidden');

    const transcriptInput = { sessionId, view: 'redacted', query: 'contestata', cursor: null, limit: 12,
      from: null, to: null };
    const transcript = await getWithContext(`/v2/sessions/${sessionId}/transcript?query=contestata&limit=12&purpose=conversation_recall`, 'session_transcript', transcriptInput);
    assert.equal(transcript.response.status, 200, JSON.stringify(transcript.body));
    const serialized = JSON.stringify(transcript.body.data);
    assert.equal(serialized.includes('Conversazione contestata oltre i primi dodici eventi'), true);
    const canonicalInput = { sessionId, view: 'redacted', query: 'canonical-version', cursor: null,
      limit: 12, from: null, to: null };
    const canonicalTranscript = await getWithContext(`/v2/sessions/${sessionId}/transcript?query=canonical-version&limit=12&purpose=conversation_recall`, 'session_transcript', canonicalInput);
    assert.equal(canonicalTranscript.response.status, 200, JSON.stringify(canonicalTranscript.body));
    const canonicalSerialized = JSON.stringify(canonicalTranscript.body.data);
    assert.equal(canonicalSerialized.includes('canonical-version-preferred'), true);
    assert.equal(canonicalTranscript.body.data.items.filter(item =>
      item.content.text.includes('canonical-version-preferred')).length, 1);
    for (const hiddenQuery of ['canonical-deleted-private', 'canonical-conflict']) {
      const hiddenInput = { query: hiddenQuery, limit: 20, purpose: 'conversation_recall' };
      const hidden = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({
        ...hiddenInput, contextToken: contextToken('sessions_search', hiddenInput) }) });
      assert.equal(hidden.response.status, 200, JSON.stringify(hidden.body));
      assert.deepEqual(hidden.body.data.items, []);
    }
    const pagedInput = { sessionId, view: 'redacted', query: 'bounded', cursor: null, limit: 1,
      from: null, to: null };
    const paged = await getWithContext(`/v2/sessions/${sessionId}/transcript?query=bounded&limit=1&purpose=conversation_recall`, 'session_transcript', pagedInput);
    assert.equal(paged.response.status, 200, JSON.stringify(paged.body));
    assert.equal(typeof paged.body.data.nextCursor, 'string');
    const changedQueryInput = { ...transcriptInput, limit: 1, cursor: paged.body.data.nextCursor };
    const changedQuery = await getWithContext(`/v2/sessions/${sessionId}/transcript?query=contestata&limit=1&cursor=${encodeURIComponent(paged.body.data.nextCursor)}&purpose=conversation_recall`, 'session_transcript', changedQueryInput);
    assert.equal(changedQuery.response.status, 400);
    assert.equal(changedQuery.body.error.code, 'invalid_request');
    const fullInput = { sessionId, view: 'redacted', query: '', cursor: null, limit: 100, from: null, to: null };
    const full = await getWithContext(`/v2/sessions/${sessionId}/transcript?limit=100&purpose=conversation_recall`, 'session_transcript', fullInput);
    assert.equal(full.response.status, 200, JSON.stringify(full.body));
    const fullSerialized = JSON.stringify(full.body.data);
    assert.equal(fullSerialized.includes('Appuntamento alle 17:00.'), true);
    assert.equal(fullSerialized.includes('Sto arrivando.'), true);
    for (const forbidden of ['RAW_MUST_NOT_LEAK', 'SYSTEM_PRIVATE', 'TOOL_PRIVATE', 'STRUCTURED_PRIVATE',
      'AUDIO_PRIVATE', '/private/audio']) assert.equal(fullSerialized.includes(forbidden), false, forbidden);
    const texts = full.body.data.items.map(item => item.content.text);
    assert.equal(texts.every(text => Buffer.byteLength(text, 'utf8') <= 4096), true);
    assert.equal(texts.reduce((sum, text) => sum + Buffer.byteLength(text, 'utf8'), 0) <= 65536, true);
    assert.equal(texts.some(text => text.includes('\ufffd')), false);
    assert.equal(catalog.auditEvents.some(event => event.action === 'raw_redacted_decrypt_intent'
      && event.outcome === 'authorized'), true);
    assert.equal(catalog.auditEvents.some(event => event.action === 'raw_session_search_decrypt_intent'
      && event.outcome === 'authorized'), true);

    const wrongKey = contextToken('sessions_search', searchInput, oldContextRing);
    const rejectedKey = await call('/v2/sessions/search', bearer, { method: 'POST', body: JSON.stringify({ ...searchInput,
      contextToken: wrongKey }) });
    assert.equal(rejectedKey.response.status, 403);
    const rejectedQueryTransport = await call(`/v2/sessions/${sessionId}?purpose=conversation_recall&contextToken=legacy-query-token`, bearer);
    assert.equal(rejectedQueryTransport.response.status, 400);
    assert.equal(rejectedQueryTransport.body.error.code, 'context_transport_invalid');
    const originalInput = { sessionId, view: 'original', query: '', cursor: null, limit: null, from: null, to: null };
    const original = await getWithContext(`/v2/sessions/${sessionId}/transcript?view=original&purpose=conversation_recall`, 'session_transcript', originalInput);
    assert.equal(original.response.status, 403); assert.equal(original.body.error.code, 'raw_decrypt_forbidden');
    const originalQueryInput = { ...originalInput, query: 'appuntamento' };
    const originalQuery = await getWithContext(`/v2/sessions/${sessionId}/transcript?view=original&query=appuntamento&purpose=conversation_recall`, 'session_transcript', originalQueryInput);
    assert.equal(originalQuery.response.status, 400); assert.equal(originalQuery.body.error.code, 'invalid_request');
    assert.equal(serverRing.keys[RECALL_CONSUMER_CONTEXT_KEY_VERSION],
      consumerRing.keys[RECALL_CONSUMER_CONTEXT_KEY_VERSION]);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    if (previousRegistry === undefined) delete process.env.MEM0_AUTH_REGISTRY_PATH;
    else process.env.MEM0_AUTH_REGISTRY_PATH = previousRegistry;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
