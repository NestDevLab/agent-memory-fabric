import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { CanonicalPamBridge, CuratorReceiptCoordinator, FabricReceiptLedger, MemoryReceiptLedger, validateCuratorReceipt } from '../src/canonical-memory-bridge.mjs';
import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';
import { FabricStore, MemoryCatalog, MemoryRawStore, SqliteCatalog } from '../src/fabric-store.mjs';

const timestamp = '2026-07-12T10:00:00Z';
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function sha(value) { return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex'); }
function record(overrides = {}) {
  return {
    schema: 'amf-memory/v1', id: 'mem_11111111-1111-4111-8111-111111111111', revision: 2,
    claimType: 'decision', scope: { type: 'shared', id: 'shared:global' }, visibility: 'shared',
    subjects: [{ identityId: 'agent:22222222-2222-4222-8222-222222222222', role: 'owner' }],
    claim: { encoding: 'plain', text: 'Canonical PAM record.' },
    confidence: { score: 0.95, basis: 'reviewed', assessedAt: timestamp },
    lifecycle: { status: 'active', validFrom: timestamp, validTo: null, supersedes: [], revokedAt: null, revocationReason: null },
    provenance: [{ sourceType: 'test-session', sourceId: 'session-stable-0001', eventId: 'event-stable-0001', contentSha256: sha('source'), capturedAt: timestamp }],
    createdAt: timestamp, updatedAt: timestamp, ...overrides
  };
}

test('context tokens bind actor, purpose, policy, room context and exact request digest', () => {
  const ring = { currentKeyVersion: 'ctx-v1', keys: { 'ctx-v1': Buffer.alloc(32, 3).toString('base64') } };
  const now = Date.parse(timestamp);
  const request = { operation: 'memory_search', query: 'appointment', scope: 'shared:global', scopes: [] };
  const payload = {
    actor: 'vitae', runtime: 'principia', profile: 'production', conversationKind: 'group',
    contextTags: { room: [`hmac-sha256:routing-v1:${'a'.repeat(64)}`], person: [`hmac-sha256:routing-v1:${'b'.repeat(64)}`] },
    canonicalScopes: ['room:vitae:team'],
    purpose: 'conversation_recall', policyRevision: 'policy-7', issuedAt: timestamp,
    expiresAt: new Date(now + 60_000).toISOString(), nonce: 'nonce_1234567890abcdef', requestDigest: requestDigest(request)
  };
  const token = issueContextToken(payload, ring);
  const verifier = new ContextTokenVerifier({ keyRing: ring, policyRevision: 'policy-7', clock: () => now });
  const verified = verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request,
    contextKeyVersions: ['ctx-v1'] });
  assert.equal(verified.conversationKind, 'group');
  assert.deepEqual(verified.canonicalScopes, ['room:vitae:team']);
  assert.throws(() => verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request,
    contextKeyVersions: ['ctx-other'] }), /context_invalid/);
  assert.equal(verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request }).nonce, payload.nonce, 'exact retries remain idempotent');
  assert.throws(() => verifier.verify(token, { actor: 'other', purpose: 'conversation_recall', request }), /context_invalid/);
  assert.throws(() => verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request: { ...request, query: 'different' } }), /context_invalid/);
  const alteredContext = issueContextToken({ ...payload, contextTags: { room: [`hmac-sha256:routing-v1:${'c'.repeat(64)}`] } }, ring);
  assert.throws(() => verifier.verify(alteredContext, { actor: 'vitae', purpose: 'conversation_recall', request }), /context_invalid/);
  const stalePolicy = new ContextTokenVerifier({ keyRing: ring, policyRevision: 'policy-8', clock: () => now });
  assert.throws(() => stalePolicy.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request }), /context_invalid/);
  const duplicateTags = issueContextToken({ ...payload, contextTags: { room: [payload.contextTags.room[0], payload.contextTags.room[0]] } }, ring);
  assert.throws(() => verifier.verify(duplicateTags, { actor: 'vitae', purpose: 'conversation_recall', request }), /context_invalid/);
});

test('canonical PAM bridge returns only indexed, valid, active records', async () => {
  const canonical = record();
  const calls = [];
  const bridge = new CanonicalPamBridge({
    index: { records: { [canonical.id]: { path: 'memory/records/shared.json', scope: 'shared:global' } } },
    async callTool(name, args) {
      calls.push({ name, args });
      if (name === 'memory_search') return { results: [{ path: 'memory/records/shared.json', line: 1 }] };
      if (name === 'memory_record_validate') return { status: 'valid', metadata: canonical };
      throw new Error('unexpected_tool');
    }
  });
  assert.deepEqual(await bridge.read({ id: canonical.id }), canonical);
  assert.deepEqual((await bridge.search({ query: 'Canonical', scopes: ['shared:global'] })).items, [canonical]);
  assert.equal(calls.some(call => call.name === 'memory_search'), true);
  await assert.rejects(bridge.read({ id: 'mem_00000000-0000-4000-8000-000000000000' }), /memory_not_found/);
});

test('PAM record index hot-reloads atomically and derives sensitive routing tags server-side', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-record-index-'));
  const indexPath = path.join(dir, 'record-index.json');
  const id = 'mem_context_00000001'; const literal = 'room:vitae:joseph-dm'; const key = Buffer.alloc(32, 9);
  fs.writeFileSync(indexPath, JSON.stringify({ schema: 'amf-record-index/v1', records: { [id]: { path: `memory/amf/records/${id}.md`, scope: literal, contextRefs: { conversation: [literal], room: [literal] } } } }), { mode: 0o600 });
  const bridge = new CanonicalPamBridge({ callTool: async () => ({}), index: JSON.parse(fs.readFileSync(indexPath)), indexPath, routingKeys: { currentKeyVersion: 'routing-v1', keys: new Map([['routing-v1', key]]) } });
  const expected = namespace => `hmac-sha256:routing-v1:${crypto.createHmac('sha256', key).update(canonicalJson([namespace, literal])).digest('hex')}`;
  assert.deepEqual(bridge.routingContext(id), { conversation: [expected('conversation')], room: [expected('room')] });
  const second = 'mem_context_00000002'; const temporary = path.join(dir, '.record-index.tmp');
  fs.writeFileSync(temporary, JSON.stringify({ schema: 'amf-record-index/v1', records: { [second]: { path: `memory/amf/records/${second}.md`, scope: 'shared:global' } } }), { mode: 0o600 });
  fs.renameSync(temporary, indexPath);
  assert.equal(bridge.routingContext(id), null);
  assert.equal(bridge.refreshIndex().records[second].scope, 'shared:global');
  fs.writeFileSync(temporary, '{"records":{"bad":{"path":"../escape","scope":"room:x"}}}', { mode: 0o600 }); fs.renameSync(temporary, indexPath);
  assert.throws(() => bridge.routingContext(second), /pam_record_index_invalid/);
  const forged = { records: { [id]: { path: `memory/amf/records/${id}.md`, scope: literal, contextTags: { room: [`hmac-sha256:routing-v1:${'f'.repeat(64)}`] } } } };
  assert.throws(() => new CanonicalPamBridge({ callTool: async () => ({}), index: forged, routingKeys: { currentKeyVersion: 'routing-v1', keys: new Map([['routing-v1', key]]) } }), /legacy_context_tags_forbidden/);
  assert.equal(new CanonicalPamBridge({ callTool: async () => ({}), index: forged, routingKeys: { currentKeyVersion: 'routing-v1', keys: new Map([['routing-v1', key]]) }, allowLegacyContextTags: true }).routingContext(id).room.length, 1);
});

test('decision and apply receipts are strict, monotonic, idempotent and verify canonical persistence', async () => {
  const canonical = record();
  const ledger = new MemoryReceiptLedger();
  const coordinator = new CuratorReceiptCoordinator({
    ledger,
    proposalStore: { async readProposalForReceiptAuthorized(receipt) { if (receipt.proposalId === 'unknown') throw new Error('memory_not_found'); return { payload: 'proposal', scope: 'shared:global' }; }, async assertPromotionEligible() { return true; } },
    canonicalStore: {
      async read({ id }) { if (id !== canonical.id) throw new Error('missing'); return canonical; },
      async verifyApplyReceipt(receipt) { return { verified: true, archiveDigest: receipt.archiveDigest, targetDigest: receipt.targetDigest, revision: receipt.revision }; }
    }
  });
  const proposalDigest = sha('proposal'); const policyDigest = sha('policy');
  const authorization = { actor: 'curator', allowAll: true, allowedScopes: [] };
  const decisionBase = { proposalId: 'proposal-1', proposalScope: 'shared:global', decisionId: 'decision-1', status: 'approved_pending_apply', proposalDigest, policyDigest };
  const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
  assert.equal((await coordinator.record(decision, { authorization })).status, 'approved_pending_apply');
  assert.equal((await coordinator.record(decision, { authorization })).duplicate, true);
  assert.throws(() => validateCuratorReceipt({ ...decision, canonicalRecordId: canonical.id }), /receipt_invalid/);
  const apply = {
    kind: 'apply', proposalId: decision.proposalId, proposalScope: decision.proposalScope, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest,
    policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision,
    canonicalLifecycleAtDecision: 'active', proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp
  };
  assert.equal((await coordinator.record(apply, { authorization })).status, 'promoted');
  assert.equal((await coordinator.record(apply, { authorization })).duplicate, true);
  assert.deepEqual(await coordinator.reconcile({ authorization }), { ok: true, findings: [], scanned: 1, complete: true, nextOffset: null });
  await assert.rejects(coordinator.record({ ...apply, proposalId: 'unknown' }, { authorization }), /memory_not_found/);
  await assert.rejects(coordinator.record({ ...apply, revision: 3 }, { authorization }), /canonical_apply_unverified|receipt_conflict/);
});

test('receipt reconciliation is authorization-scoped, bounded and fail-closed', async () => {
  const ledger = new MemoryReceiptLedger();
  const makeDecision = (proposalId, proposalScope) => {
    const base = { proposalId, proposalScope, decisionId: `decision-${proposalId}`, status: 'approved_pending_apply', proposalDigest: sha(`payload-${proposalId}`), policyDigest: sha(`policy-${proposalId}`) };
    return { kind: 'decision', ...base, decisionDigest: sha(base), timestamp };
  };
  for (const [id, scope] of [['allowed-a', 'room:allowed'], ['denied', 'person:private'], ['allowed-b', 'room:allowed']]) ledger.recordDecision(makeDecision(id, scope));
  const coordinator = new CuratorReceiptCoordinator({ ledger, canonicalStore: { async read() { throw new Error('not_used'); } } });
  await assert.rejects(coordinator.reconcile(), /invalid_request/);
  const scoped = { actor: 'applicator', allowAll: false, allowedScopes: ['room:allowed'] };
  const first = await coordinator.reconcile({ authorization: scoped, limit: 1 });
  assert.deepEqual(first.findings, [{ proposalId: 'allowed-a', code: 'apply_receipt_pending' }]);
  assert.equal(first.scanned, 1); assert.equal(first.complete, false); assert.equal(first.nextOffset, 1);
  const second = await coordinator.reconcile({ authorization: scoped, offset: first.nextOffset, limit: 1 });
  assert.deepEqual(second.findings, [{ proposalId: 'allowed-b', code: 'apply_receipt_pending' }]);
  assert.equal(second.complete, true); assert.equal(second.nextOffset, null);
  assert.doesNotMatch(JSON.stringify([first, second]), /denied|person:private/);
  const all = await coordinator.reconcile({ authorization: { actor: 'admin', allowAll: true, allowedScopes: [] }, limit: 100 });
  assert.deepEqual(all.findings.map(item => item.proposalId), ['allowed-a', 'allowed-b', 'denied']);
  await assert.rejects(coordinator.reconcile({ authorization: scoped, limit: 101 }), /invalid_request/);

  ledger.records.set('corrupt-private-id', { proposalId: 'corrupt-private-id', status: 'approved_pending_apply', decision: { proposalScope: 'person:private' }, apply: null });
  const corruptScoped = await coordinator.reconcile({ authorization: scoped, limit: 100 });
  assert.doesNotMatch(JSON.stringify(corruptScoped), /corrupt-private-id|person:private/);
  const corruptAll = await coordinator.reconcile({ authorization: { actor: 'admin', allowAll: true, allowedScopes: [] }, limit: 100 });
  assert.ok(corruptAll.findings.some(item => item.code === 'receipt_binding_invalid' && item.count === 1));
  assert.doesNotMatch(JSON.stringify(corruptAll.findings), /corrupt-private-id|person:private/);
});

test('Fabric receipt reconciliation applies scope filtering before pagination in memory and SQLite catalogs', async () => {
  for (const kind of ['memory', 'sqlite']) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `amf-reconcile-${kind}-`));
    const catalog = kind === 'memory' ? new MemoryCatalog() : new SqliteCatalog({ databasePath: path.join(root, 'fabric.sqlite') });
    const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 19).toString('base64') }), catalog });
    const coordinator = new CuratorReceiptCoordinator({ ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store, canonicalStore: { async read() { throw new Error('not_used'); } } });
    const admin = { actor: 'admin', allowAll: true, allowedScopes: [] };
    try {
      for (const [scope, suffix] of [['room:allowed', 'allowed'], ['person:private', 'private']]) {
        const canonical = record({ id: `mem_${suffix.padEnd(8, '0')}-1111-4111-8111-111111111111`, scope: { type: scope.split(':')[0], id: scope } });
        const proposal = await store.propose({ actor: 'curator', scope, record: canonical, rationale: 'scope filter', expectedRevision: canonical.revision - 1, idempotencyKey: `${kind}-${suffix}-reconcile` });
        const persisted = await store.readProposal(proposal.id);
        const base = { proposalId: proposal.id, proposalScope: scope, decisionId: `decision-${kind}-${suffix}`, status: 'approved_pending_apply', proposalDigest: sha(persisted.payload), policyDigest: sha(`${kind}-${suffix}-policy`) };
        await coordinator.record({ kind: 'decision', ...base, decisionDigest: sha(base), timestamp }, { actor: 'admin', requestId: `request-${suffix}`, authorization: admin });
      }
      const scoped = await coordinator.reconcile({ authorization: { actor: 'applicator', allowAll: false, allowedScopes: ['room:allowed'] }, limit: 1 });
      assert.equal(scoped.scanned, 1); assert.equal(scoped.nextOffset, null);
      assert.equal(scoped.findings.length, 1); assert.equal(scoped.findings[0].code, 'apply_receipt_pending');
      assert.doesNotMatch(JSON.stringify(scoped), /person:private/);
      const all = await coordinator.reconcile({ authorization: admin, limit: 1 });
      assert.equal(all.scanned, 1); assert.equal(all.nextOffset, 1, `${kind} allow_all page must remain bounded`);
    } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('Fabric receipt transaction advances ledger, proposal and audit together and rolls back on audit outage', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-fabric-receipts-'));
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 4).toString('base64') }), catalog: new SqliteCatalog({ databasePath: path.join(root, 'fabric.sqlite') }) });
  try {
    const canonical = record();
    const proposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'verified', expectedRevision: 1, idempotencyKey: 'receipt-atomic-1' });
    const persisted = await store.readProposal(proposal.id);
    const policyDigest = sha('policy');
    const authorization = { actor: 'curator', allowAll: true, allowedScopes: [] };
    const decisionBase = { proposalId: proposal.id, proposalScope: proposal.scope, decisionId: 'decision-atomic', status: 'approved_pending_apply', proposalDigest: sha(persisted.payload), policyDigest };
    const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
    const coordinator = new CuratorReceiptCoordinator({
      ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store,
      canonicalStore: { async read() { return canonical; }, async verifyApplyReceipt(receipt) { return { verified: true, archiveDigest: receipt.archiveDigest, targetDigest: receipt.targetDigest, revision: receipt.revision }; } }
    });
    assert.equal((await coordinator.record(decision, { actor: 'curator', requestId: 'req-decision', authorization })).status, 'approved_pending_apply');
    assert.equal((await store.getProposalStatusAuthorized(proposal.id, { actor: 'curator', allowAll: true })).status, 'review');
    const apply = { kind: 'apply', proposalId: proposal.id, proposalScope: proposal.scope, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest, policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision, canonicalLifecycleAtDecision: canonical.lifecycle.status, proposalDigest: decision.proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp };
    assert.equal((await coordinator.record(apply, { actor: 'curator', requestId: 'req-apply', authorization })).status, 'promoted');
    assert.equal((await store.getProposalStatusAuthorized(proposal.id, { actor: 'curator', allowAll: true })).status, 'promoted');

    const rejectedProposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'reject', expectedRevision: 1, idempotencyKey: 'receipt-atomic-rejected' });
    const rejectedPayload = await store.readProposal(rejectedProposal.id);
    const rejectedBase = { proposalId: rejectedProposal.id, proposalScope: rejectedProposal.scope, decisionId: 'decision-rejected', status: 'rejected', proposalDigest: sha(rejectedPayload.payload), policyDigest };
    const rejectedDecision = { kind: 'decision', ...rejectedBase, decisionDigest: sha(rejectedBase), timestamp };
    assert.equal((await coordinator.record(rejectedDecision, { actor: 'curator', requestId: 'req-rejected', authorization })).status, 'rejected');
    assert.equal((await coordinator.record(rejectedDecision, { actor: 'curator', requestId: 'req-rejected-retry', authorization })).duplicate, true);

    const rollbackProposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'rollback', expectedRevision: 1, idempotencyKey: 'receipt-atomic-rollback' });
    const rollbackPayload = await store.readProposal(rollbackProposal.id);
    store.idFactory = () => 'forced-audit-id';
    await store.audit({ actor: 'curator', action: 'preexisting', outcome: 'recorded' });
    const rollbackBase = { proposalId: rollbackProposal.id, proposalScope: rollbackProposal.scope, decisionId: 'decision-rollback', status: 'rejected', proposalDigest: sha(rollbackPayload.payload), policyDigest };
    const rollbackDecision = { kind: 'decision', ...rollbackBase, decisionDigest: sha(rollbackBase), timestamp };
    await assert.rejects(coordinator.record(rollbackDecision, { actor: 'curator', requestId: 'req-rollback', authorization }), /catalog_unavailable/);
    assert.equal(await store.getCuratorReceipt(rollbackProposal.id), null);
    assert.equal((await store.getProposalStatusAuthorized(rollbackProposal.id, { actor: 'curator', allowAll: true })).status, 'queued');
  } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('Memory and SQLite refuse late decisions on terminal proposals but replay an identical persisted decision without decrypt', async () => {
  for (const kind of ['memory', 'sqlite']) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `amf-terminal-${kind}-`));
    const catalog = kind === 'memory' ? new MemoryCatalog() : new SqliteCatalog({ databasePath: path.join(root, 'fabric.sqlite') });
    const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 12).toString('base64') }), catalog });
    const authorization = { actor: 'curator', allowAll: true, allowedScopes: [] };
    const coordinator = new CuratorReceiptCoordinator({ ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store, canonicalStore: { async read() { throw new Error('must_not_read'); }, async verifyApplyReceipt() { throw new Error('must_not_verify'); } } });
    const setStatus = (id, status) => kind === 'memory'
      ? (catalog.proposals.get(id).status = status)
      : catalog.db.prepare('UPDATE fabric_proposals SET status=? WHERE id=?').run(status, id);
    const makeDecision = (proposal, payload, status, suffix) => {
      const base = { proposalId: proposal.id, proposalScope: proposal.scope, decisionId: `decision-${kind}-${suffix}`, status, proposalDigest: sha(payload), policyDigest: sha(`policy-${suffix}`) };
      return { kind: 'decision', ...base, decisionDigest: sha(base), timestamp };
    };
    try {
      for (const terminal of ['revoked', 'rejected']) {
        const direct = await store.propose({ actor: 'curator', scope: 'shared:global', record: record(), rationale: `direct ${terminal}`, expectedRevision: 1, idempotencyKey: `${kind}-direct-${terminal}` });
        const directPayload = await store.readProposal(direct.id); const late = makeDecision(direct, directPayload.payload, 'review_required', `direct-${terminal}`);
        setStatus(direct.id, terminal);
        await assert.rejects(store.recordCuratorReceiptAtomic(late, { actor: 'curator', requestId: `direct-${terminal}` }), /receipt_transition_invalid/);

        const guarded = await store.propose({ actor: 'curator', scope: 'shared:global', record: record(), rationale: `guarded ${terminal}`, expectedRevision: 1, idempotencyKey: `${kind}-guarded-${terminal}` });
        const guardedPayload = await store.readProposal(guarded.id); const guardedLate = makeDecision(guarded, guardedPayload.payload, 'review_required', `guarded-${terminal}`);
        setStatus(guarded.id, terminal);
        let decryptions = 0; const originalGet = store.rawStore.get.bind(store.rawStore);
        store.rawStore.get = async (...args) => { decryptions += 1; return originalGet(...args); };
        await assert.rejects(coordinator.record(guardedLate, { actor: 'curator', authorization }), /receipt_transition_invalid/);
        assert.equal(decryptions, 0, `${kind}/${terminal} terminal check must precede RAW decrypt`);
        store.rawStore.get = originalGet;
      }

      const replayProposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: record(), rationale: 'replay', expectedRevision: 1, idempotencyKey: `${kind}-replay-terminal` });
      const replayPayload = await store.readProposal(replayProposal.id); const rejected = makeDecision(replayProposal, replayPayload.payload, 'rejected', 'replay');
      assert.equal((await coordinator.record(rejected, { actor: 'curator', authorization })).status, 'rejected');
      setStatus(replayProposal.id, 'revoked');
      let replayDecryptions = 0; const originalGet = store.rawStore.get.bind(store.rawStore);
      store.rawStore.get = async (...args) => { replayDecryptions += 1; return originalGet(...args); };
      assert.equal((await coordinator.record(rejected, { actor: 'curator', authorization })).duplicate, true);
      assert.equal(replayDecryptions, 0, `${kind} identical terminal replay must not decrypt`);
    } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('raw reconciliation conflict is audited and blocks canonical promotion', async () => {
  const catalog = new MemoryCatalog();
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 5).toString('base64') }), catalog });
  const eventId = `evt_${'a'.repeat(64)}`; const logicalMessageId = `lmsg_${'b'.repeat(64)}`;
  catalog.rawEventsV2.set(eventId, { eventId, logicalMessageId });
  catalog.logicalMessages.set(logicalMessageId, { logicalMessageId, payloadConflict: true, tombstoned: false });
  const canonical = record({ provenance: [{ sourceType: 'test-session', sourceId: 'session-stable-0001', eventId, contentSha256: sha('source'), capturedAt: timestamp }] });
  const proposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'conflict', expectedRevision: 1, idempotencyKey: 'reconcile-conflict' });
  const persisted = await store.readProposal(proposal.id); const policyDigest = sha('policy');
  const authorization = { actor: 'curator', allowAll: true, allowedScopes: [] };
  const decisionBase = { proposalId: proposal.id, proposalScope: proposal.scope, decisionId: 'decision-conflict', status: 'approved_pending_apply', proposalDigest: sha(persisted.payload), policyDigest };
  const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
  const coordinator = new CuratorReceiptCoordinator({ ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store, canonicalStore: { async read() { return canonical; }, async verifyApplyReceipt() { throw new Error('must_not_apply'); } } });
  await coordinator.record(decision, { actor: 'curator', authorization });
  const apply = { kind: 'apply', proposalId: proposal.id, proposalScope: proposal.scope, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest, policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision, canonicalLifecycleAtDecision: canonical.lifecycle.status, proposalDigest: decision.proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp };
  await assert.rejects(coordinator.record(apply, { actor: 'curator', authorization }), /raw_reconcile_required/);
  assert.equal((await store.getCuratorReceipt(proposal.id)).status, 'approved_pending_apply');
  assert.ok(catalog.auditEvents.some(event => event.action === 'raw_reconcile' && event.outcome === 'blocked'));
});
