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
      if (name === 'memory_read') return { content: JSON.stringify(canonical) };
      throw new Error('unexpected_tool');
    }
  });
  assert.deepEqual(await bridge.read({ id: canonical.id }), canonical);
  assert.deepEqual((await bridge.search({ query: 'Canonical', scopes: ['shared:global'] })).items, [canonical]);
  assert.equal(calls.some(call => call.name === 'memory_search'), true);
  await assert.rejects(bridge.read({ id: 'mem_00000000-0000-4000-8000-000000000000' }), /memory_not_found/);
});

test('decision and apply receipts are strict, monotonic, idempotent and verify canonical persistence', async () => {
  const canonical = record();
  const ledger = new MemoryReceiptLedger();
  const coordinator = new CuratorReceiptCoordinator({
    ledger,
    proposalStore: { async readProposal() { return { payload: 'proposal' }; }, async assertPromotionEligible() { return true; } },
    canonicalStore: {
      async read({ id }) { if (id !== canonical.id) throw new Error('missing'); return canonical; },
      async verifyApplyReceipt(receipt) { return { verified: true, archiveDigest: receipt.archiveDigest, targetDigest: receipt.targetDigest, revision: receipt.revision }; }
    }
  });
  const proposalDigest = sha('proposal'); const policyDigest = sha('policy');
  const decisionBase = { proposalId: 'proposal-1', decisionId: 'decision-1', status: 'approved_pending_apply', proposalDigest, policyDigest };
  const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
  assert.equal((await coordinator.record(decision)).status, 'approved_pending_apply');
  assert.equal((await coordinator.record(decision)).duplicate, true);
  assert.throws(() => validateCuratorReceipt({ ...decision, canonicalRecordId: canonical.id }), /receipt_invalid/);
  const apply = {
    kind: 'apply', proposalId: decision.proposalId, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest,
    policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision,
    canonicalLifecycleAtDecision: 'active', proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp
  };
  assert.equal((await coordinator.record(apply)).status, 'promoted');
  assert.equal((await coordinator.record(apply)).duplicate, true);
  assert.deepEqual(await coordinator.reconcile(), { ok: true, findings: [] });
  await assert.rejects(coordinator.record({ ...apply, proposalId: 'unknown' }), /receipt_transition_invalid/);
  await assert.rejects(coordinator.record({ ...apply, revision: 3 }), /canonical_apply_unverified|receipt_conflict/);
});

test('Fabric receipt transaction advances ledger, proposal and audit together and rolls back on audit outage', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-fabric-receipts-'));
  const store = new FabricStore({ rawStore: new MemoryRawStore({ encryptionKey: Buffer.alloc(32, 4).toString('base64') }), catalog: new SqliteCatalog({ databasePath: path.join(root, 'fabric.sqlite') }) });
  try {
    const canonical = record();
    const proposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'verified', expectedRevision: 1, idempotencyKey: 'receipt-atomic-1' });
    const persisted = await store.readProposal(proposal.id);
    const policyDigest = sha('policy');
    const decisionBase = { proposalId: proposal.id, decisionId: 'decision-atomic', status: 'approved_pending_apply', proposalDigest: sha(persisted.payload), policyDigest };
    const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
    const coordinator = new CuratorReceiptCoordinator({
      ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store,
      canonicalStore: { async read() { return canonical; }, async verifyApplyReceipt(receipt) { return { verified: true, archiveDigest: receipt.archiveDigest, targetDigest: receipt.targetDigest, revision: receipt.revision }; } }
    });
    assert.equal((await coordinator.record(decision, { actor: 'curator', requestId: 'req-decision' })).status, 'approved_pending_apply');
    assert.equal((await store.getProposalStatusAuthorized(proposal.id, { actor: 'curator', allowAll: true })).status, 'review');
    const apply = { kind: 'apply', proposalId: proposal.id, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest, policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision, canonicalLifecycleAtDecision: canonical.lifecycle.status, proposalDigest: decision.proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp };
    assert.equal((await coordinator.record(apply, { actor: 'curator', requestId: 'req-apply' })).status, 'promoted');
    assert.equal((await store.getProposalStatusAuthorized(proposal.id, { actor: 'curator', allowAll: true })).status, 'promoted');

    const rollbackProposal = await store.propose({ actor: 'curator', scope: 'shared:global', record: canonical, rationale: 'rollback', expectedRevision: 1, idempotencyKey: 'receipt-atomic-rollback' });
    const rollbackPayload = await store.readProposal(rollbackProposal.id);
    store.idFactory = () => 'forced-audit-id';
    await store.audit({ actor: 'curator', action: 'preexisting', outcome: 'recorded' });
    const rollbackBase = { proposalId: rollbackProposal.id, decisionId: 'decision-rollback', status: 'rejected', proposalDigest: sha(rollbackPayload.payload), policyDigest };
    const rollbackDecision = { kind: 'decision', ...rollbackBase, decisionDigest: sha(rollbackBase), timestamp };
    await assert.rejects(coordinator.record(rollbackDecision, { actor: 'curator', requestId: 'req-rollback' }), /catalog_unavailable/);
    assert.equal(await store.getCuratorReceipt(rollbackProposal.id), null);
    assert.equal((await store.getProposalStatusAuthorized(rollbackProposal.id, { actor: 'curator', allowAll: true })).status, 'queued');
  } finally { await store.close(); fs.rmSync(root, { recursive: true, force: true }); }
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
  const decisionBase = { proposalId: proposal.id, decisionId: 'decision-conflict', status: 'approved_pending_apply', proposalDigest: sha(persisted.payload), policyDigest };
  const decision = { kind: 'decision', ...decisionBase, decisionDigest: sha(decisionBase), timestamp };
  const coordinator = new CuratorReceiptCoordinator({ ledger: new FabricReceiptLedger({ fabricStore: store }), proposalStore: store, canonicalStore: { async read() { return canonical; }, async verifyApplyReceipt() { throw new Error('must_not_apply'); } } });
  await coordinator.record(decision, { actor: 'curator' });
  const apply = { kind: 'apply', proposalId: proposal.id, decisionId: decision.decisionId, decisionDigest: decision.decisionDigest, policyDigestAtApply: policyDigest, canonicalRecordId: canonical.id, revision: canonical.revision, canonicalLifecycleAtDecision: canonical.lifecycle.status, proposalDigest: decision.proposalDigest, archiveDigest: sha('archive'), targetDigest: sha(canonical), timestamp };
  await assert.rejects(coordinator.record(apply, { actor: 'curator' }), /raw_reconcile_required/);
  assert.equal((await store.getCuratorReceipt(proposal.id)).status, 'approved_pending_apply');
  assert.ok(catalog.auditEvents.some(event => event.action === 'raw_reconcile' && event.outcome === 'blocked'));
});
