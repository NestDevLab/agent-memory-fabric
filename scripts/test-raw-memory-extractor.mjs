import assert from 'node:assert/strict';
import test from 'node:test';

import { buildMemoryRecord, createExtractorState, duplicateCanonicalClaim, normalizeState, proposalIdempotencyKey, reserveModelBudget, settleModelBudget, sharedDurableClaim, triageConversation, truncateUtf8ToTokenUpperBound, utf8TokenUpperBound, validateClaims } from '../src/raw-memory-extractor.mjs';
import { buildBoundedModelInput, evaluatePlanUsage } from './amf-raw-memory-extractor.mjs';

const durable = [{ role: 'user', text: 'We decided to keep the extractor slow and cost bounded.' }, { role: 'assistant', text: 'Agreed: one conversation per tick and a daily ceiling.' }];

test('free triage passes durable language but rejects operational chatter', () => {
  assert.equal(triageConversation(durable).pass, true);
  assert.equal(triageConversation(durable.map(item => ({ role: item.role, content: { text: item.text } }))).pass, true, 'Fabric redacted session shape is nested under content.text');
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

test('settlement records actual provider usage even when it exceeds the reservation', () => {
  const state = createExtractorState(); const config = { dailyInputTokens: 1000, dailyOutputTokens: 100, maxInputTokensPerConversation: 800, maxOutputTokensPerConversation: 80 };
  const reservation = reserveModelBudget(state, config, '2026-07-20T01:00:00Z');
  settleModelBudget(state, reservation, { inputTokens: 18000, outputTokens: 90 });
  const current = state.days['2026-07-20'];
  assert.equal(current.usedInputTokens, 18000);
  assert.equal(current.usedOutputTokens, 90);
  assert.equal(current.reservedInputTokens, 0);
});

test('UTF-8 byte bound never treats character count as a token cap or splits Unicode', () => {
  const text = 'alpha € beta';
  assert.equal(utf8TokenUpperBound(text), Buffer.byteLength(text, 'utf8'));
  const bounded = truncateUtf8ToTokenUpperBound(text, 8);
  assert.equal(bounded, 'alpha ');
  assert.ok(utf8TokenUpperBound(bounded) <= 8);
});

test('stage-2 cap reserves instruction, output schema, and Codex envelope before clipping transcript', () => {
  const config = { maxClaimsPerConversation: 2, maxInputTokensPerConversation: 2500 };
  const bounded = buildBoundedModelInput('€'.repeat(4000), config);
  assert.ok(bounded.inputTokenUpperBound <= 2500);
  assert.ok(utf8TokenUpperBound(bounded.transcript) < utf8TokenUpperBound('€'.repeat(4000)));
});

test('plan usage pauses only below the configured remaining threshold or on a reported limit', () => {
  const config = { planMinRemainingPercent: 25 };
  const atThreshold = evaluatePlanUsage({ rateLimits: { primary: { usedPercent: 75, resetsAt: 10 } } }, config, '2026-07-20T00:00:00Z');
  assert.equal(atThreshold.constrained, false);
  const belowThreshold = evaluatePlanUsage({ rateLimits: { primary: { usedPercent: 76, resetsAt: 10 }, secondary: { usedPercent: 10, resetsAt: 20 } } }, config, '2026-07-20T00:00:00Z');
  assert.equal(belowThreshold.constrained, true);
  assert.equal(belowThreshold.pauseUntil, '1970-01-01T00:00:10.000Z');
  assert.equal(evaluatePlanUsage({ rateLimits: { primary: { usedPercent: 0, resetsAt: 30 }, rateLimitReachedType: 'primary' } }, config).constrained, true);
});

test('claims exclude operational material and records use shared global plus deterministic retry key', () => {
  const [claim] = validateClaims([{ claimType: 'decision', claim: 'Keep the extractor slow and cost bounded.', confidence: 0.8 }]);
  assert.throws(() => validateClaims([{ claimType: 'decision', claim: 'The deployment failed because of an error.', confidence: 0.8 }]), /extractor_claim_invalid/);
  const record = buildMemoryRecord({ sessionId: 'ses_123', transcript: 'decrypted transcript', claim, now: '2026-07-20T12:00:00Z' });
  assert.equal(record.scope.id, 'shared:global'); assert.equal(record.visibility, 'shared');
  assert.equal(proposalIdempotencyKey({ sessionId: 'ses_123', claim: claim.claim }), proposalIdempotencyKey({ sessionId: 'ses_123', claim: claim.claim }));
});

test('shared global extraction drops explicitly project-scoped claims', () => {
  assert.equal(sharedDurableClaim('Project-specific agent guidance should describe this project.'), false);
  assert.equal(sharedDurableClaim('Prefer reusable policy over a one-off integration.'), true);
});

test('dedup compares normalized decrypted claim content, not encrypted storage bytes', () => {
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: ' keep THE extractor slow. ' }, ciphertext: 'different' } }]), true);
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: 'Another decision.' }, ciphertext: 'same' } }]), false);
});
