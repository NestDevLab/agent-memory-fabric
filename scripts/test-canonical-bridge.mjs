import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { CanonicalPamBridge, CuratorReceiptCoordinator, MemoryReceiptLedger, SqliteReceiptLedger, validateCuratorReceipt } from '../src/canonical-memory-bridge.mjs';
import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';

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
    purpose: 'conversation_recall', policyRevision: 'policy-7', issuedAt: timestamp,
    expiresAt: new Date(now + 60_000).toISOString(), nonce: 'nonce_1234567890abcdef', requestDigest: requestDigest(request)
  };
  const token = issueContextToken(payload, ring);
  const verifier = new ContextTokenVerifier({ keyRing: ring, policyRevision: 'policy-7', clock: () => now });
  assert.equal(verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request }).conversationKind, 'group');
  assert.equal(verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request }).nonce, payload.nonce, 'exact retries remain idempotent');
  assert.throws(() => verifier.verify(token, { actor: 'other', purpose: 'conversation_recall', request }), /context_invalid/);
  assert.throws(() => verifier.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request: { ...request, query: 'different' } }), /context_invalid/);
  const alteredContext = issueContextToken({ ...payload, contextTags: { room: [`hmac-sha256:routing-v1:${'c'.repeat(64)}`] } }, ring);
  assert.throws(() => verifier.verify(alteredContext, { actor: 'vitae', purpose: 'conversation_recall', request }), /context_invalid/);
  const stalePolicy = new ContextTokenVerifier({ keyRing: ring, policyRevision: 'policy-8', clock: () => now });
  assert.throws(() => stalePolicy.verify(token, { actor: 'vitae', purpose: 'conversation_recall', request }), /context_invalid/);
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
  const coordinator = new CuratorReceiptCoordinator({ ledger, canonicalStore: { async read({ id }) { if (id !== canonical.id) throw new Error('missing'); return canonical; } } });
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

test('receipt ledger survives restart and reports approved decisions awaiting apply', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-receipts-'));
  const databasePath = path.join(root, 'receipts.sqlite');
  const proposalDigest = sha('proposal'); const policyDigest = sha('policy');
  const base = { proposalId: 'proposal-durable', decisionId: 'decision-durable', status: 'approved_pending_apply', proposalDigest, policyDigest };
  const receipt = { kind: 'decision', ...base, decisionDigest: sha(base), timestamp };
  let ledger = new SqliteReceiptLedger({ databasePath });
  ledger.recordDecision(validateCuratorReceipt(receipt));
  ledger.close();
  ledger = new SqliteReceiptLedger({ databasePath });
  const coordinator = new CuratorReceiptCoordinator({ ledger, canonicalStore: { async read() { throw new Error('not_applied'); } } });
  assert.deepEqual(await coordinator.reconcile(), { ok: false, findings: [{ proposalId: 'proposal-durable', code: 'apply_receipt_pending' }] });
  assert.equal(ledger.recordDecision(receipt).duplicate, true);
  ledger.close();
  fs.rmSync(root, { recursive: true, force: true });
});
