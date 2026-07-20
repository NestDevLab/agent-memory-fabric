import assert from 'node:assert/strict';
import test from 'node:test';

import { buildMemoryRecord, createExtractorState, duplicateCanonicalClaim, normalizeState, proposalIdempotencyKey, reserveModelBudget, settleModelBudget, triageConversation, validateClaims } from '../src/raw-memory-extractor.mjs';

const durable = [{ role: 'user', text: 'We decided to keep the extractor slow and cost bounded.' }, { role: 'assistant', text: 'Agreed: one conversation per tick and a daily ceiling.' }];

test('free triage passes durable language but rejects operational chatter', () => {
  assert.equal(triageConversation(durable).pass, true);
  assert.deepEqual(triageConversation([{ role: 'user', text: 'The deploy failed with an error and latency is high.'.repeat(4) }]), { pass: false, reason: 'operational_content' });
});

test('daily reservation is conservative and settles actual usage', () => {
  const state = createExtractorState(); const config = { dailyInputTokens: 1000, dailyOutputTokens: 100, maxInputTokensPerConversation: 800, maxOutputTokensPerConversation: 80 };
  const first = reserveModelBudget(state, config, '2026-07-20T01:00:00Z'); assert.equal(first.reserved, true);
  assert.equal(reserveModelBudget(state, config, '2026-07-20T01:01:00Z').reserved, false);
  settleModelBudget(state, first, { inputTokens: 300, outputTokens: 20 });
  assert.equal(reserveModelBudget(state, config, '2026-07-20T01:02:00Z').reserved, false, 'daily ceiling includes prior actual usage');
  assert.equal(normalizeState(state).days['2026-07-20'].usedInputTokens, 300);
});

test('claims exclude operational material and records use shared global plus deterministic retry key', () => {
  const [claim] = validateClaims([{ claimType: 'decision', claim: 'Keep the extractor slow and cost bounded.', confidence: 0.8 }]);
  assert.throws(() => validateClaims([{ claimType: 'decision', claim: 'The deployment failed because of an error.', confidence: 0.8 }]), /extractor_claim_invalid/);
  const record = buildMemoryRecord({ sessionId: 'ses_123', transcript: 'decrypted transcript', claim, now: '2026-07-20T12:00:00Z' });
  assert.equal(record.scope.id, 'shared:global'); assert.equal(record.visibility, 'shared');
  assert.equal(proposalIdempotencyKey({ sessionId: 'ses_123', claim: claim.claim }), proposalIdempotencyKey({ sessionId: 'ses_123', claim: claim.claim }));
});

test('dedup compares normalized decrypted claim content, not encrypted storage bytes', () => {
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: ' keep THE extractor slow. ' }, ciphertext: 'different' } }]), true);
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: 'Another decision.' }, ciphertext: 'same' } }]), false);
});
