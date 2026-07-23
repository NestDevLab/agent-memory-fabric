import assert from 'node:assert/strict';
import test from 'node:test';

import { assertExtractorStateRunnable, buildMemoryRecord, createExtractorState, duplicateCanonicalClaim, migrateExtractorStateToConversationV3, normalizeConversationExtractorState, normalizeState, proposalIdempotencyKey, reserveModelBudget, resumeExtractorInFlight, settleModelBudget, sharedDurableClaim, triageConversation, truncateUtf8ToTokenUpperBound, utf8TokenUpperBound, validateClaims } from '../src/raw-memory-extractor.mjs';
import { buildBoundedModelInput, evaluatePlanUsage, loadExtractorState } from './amf-raw-memory-extractor.mjs';

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

test('conversation reader state migrates only at a legacy cycle boundary without mutating rollback state', () => {
  const legacy = createExtractorState();
  legacy.days['2026-07-20'] = { reservedInputTokens: 0, reservedOutputTokens: 0, usedInputTokens: 12, usedOutputTokens: 3 };
  legacy.planUsage = { checkedAt: '2026-07-20T12:00:00Z', constrained: false };
  const before = structuredClone(legacy);
  const migrated = migrateExtractorStateToConversationV3(legacy);
  assert.deepEqual(legacy, before);
  assert.equal(migrated.schema, 'amf.raw-memory-extractor-state/v2');
  assert.equal(migrated.readerGeneration, 'conversation-v3');
  assert.deepEqual(migrated.days, legacy.days);
  assert.deepEqual(migrated.planUsage, legacy.planUsage);
  assert.match(migrated.legacyBoundary.stateDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(normalizeConversationExtractorState(migrated), migrated);
  for (const field of ['cursor', 'inFlight']) {
    const unsafe = structuredClone(legacy);
    unsafe[field] = field === 'cursor' ? 'legacy-cursor' : { stage: 'model_done' };
    assert.throws(() => migrateExtractorStateToConversationV3(unsafe), /extractor_state_migration_not_at_boundary/);
  }
});

test('conversation reader state loader preserves the legacy file and resumes the new state independently', async t => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-extractor-state-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const legacyStateFile = path.join(directory, 'legacy.json');
  const stateFile = path.join(directory, 'conversation-v3.json');
  const legacy = createExtractorState();
  fs.writeFileSync(legacyStateFile, JSON.stringify(legacy));
  const config = { readerGeneration: 'conversation-v3', legacyStateFile, stateFile };
  const migrated = loadExtractorState(config);
  assert.deepEqual(JSON.parse(fs.readFileSync(legacyStateFile, 'utf8')), legacy);
  assert.equal(JSON.parse(fs.readFileSync(stateFile, 'utf8')).readerGeneration, 'conversation-v3');
  migrated.cursor = 'v3-cursor';
  fs.writeFileSync(stateFile, JSON.stringify(migrated));
  assert.equal(loadExtractorState(config).cursor, 'v3-cursor');
  assert.equal(loadExtractorState(config, { dryRun: true }).cursor, null);
});

test('v3 route identity preserves legacy proposal and provenance identity', () => {
  const claim = { claimType: 'decision', claim: 'Keep the extractor transition identity stable.', confidence: 0.9 };
  const legacyId = `ses_${'a'.repeat(64)}`;
  const legacy = buildMemoryRecord({ sessionId: legacyId, transcript: 'redacted', claim, now: '2026-07-20T12:00:00Z' });
  const v3 = buildMemoryRecord({ sessionId: 'ccon_example123', extractionIdentity: legacyId, transcript: 'redacted', claim, now: '2026-07-20T12:00:00Z' });
  assert.deepEqual(v3, legacy);
  assert.equal(proposalIdempotencyKey({ sessionId: legacyId, claim: claim.claim }),
    proposalIdempotencyKey({ sessionId: 'ccon_example123', extractionIdentity: legacyId, claim: claim.claim }));
});

test('v3 visible revision digest makes proposal and record identity revision-aware without changing legacy keys', () => {
  const claim = { claimType: 'decision', claim: 'Keep the visible conversation revision in the proposal identity.', confidence: 0.9 };
  const sessionId = 'ccon_revisionexample1'; const extractionIdentity = `ses_${'c'.repeat(64)}`;
  const firstDigest = `sha256:${'a'.repeat(64)}`; const revisedDigest = `sha256:${'b'.repeat(64)}`;
  const stableFirst = proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest: firstDigest, claim: claim.claim });
  assert.equal(stableFirst, proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest: firstDigest, claim: claim.claim }));
  assert.notEqual(stableFirst, proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest: revisedDigest, claim: claim.claim }));
  const firstRecord = buildMemoryRecord({ sessionId, extractionIdentity, visibleRevisionDigest: firstDigest, transcript: 'redacted', claim, now: '2026-07-20T12:00:00Z' });
  const revisedRecord = buildMemoryRecord({ sessionId, extractionIdentity, visibleRevisionDigest: revisedDigest, transcript: 'redacted', claim, now: '2026-07-20T12:00:00Z' });
  assert.notEqual(firstRecord.id, revisedRecord.id);
  assert.equal(firstRecord.provenance[0].sourceId, extractionIdentity, 'revision only affects record and proposal identity');
  assert.throws(() => proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest: 'not-a-digest', claim: claim.claim }), /extractor_visible_revision_invalid/);
});

test('conversation-v3 in-flight state fails closed when its visible revision digest is absent or invalid', () => {
  const state = createExtractorState({ readerGeneration: 'conversation-v3' });
  state.inFlight = { sessionId: 'ccon_revisionexample1', extractionIdentity: `ses_${'c'.repeat(64)}`, visibleRevisionDigest: `sha256:${'a'.repeat(64)}`, stage: 'model_done' };
  assert.equal(normalizeConversationExtractorState(state), state);
  for (const visibleRevisionDigest of [undefined, 'sha256:not-valid']) {
    const invalid = structuredClone(state);
    if (visibleRevisionDigest === undefined) delete invalid.inFlight.visibleRevisionDigest;
    else invalid.inFlight.visibleRevisionDigest = visibleRevisionDigest;
    assert.throws(() => normalizeConversationExtractorState(invalid), /extractor_state_invalid/);
  }
});

test('matching model_pending reservations require explicit recovery and never retry automatically', () => {
  const sessionId = 'ccon_revisionexample1'; const extractionIdentity = `ses_${'c'.repeat(64)}`; const visibleRevisionDigest = `sha256:${'a'.repeat(64)}`;
  const inFlight = { sessionId, extractionIdentity, visibleRevisionDigest, stage: 'model_pending', reservation: { reserved: true, day: '2026-07-23', inputTokens: 12, outputTokens: 3 } };
  const state = createExtractorState({ readerGeneration: 'conversation-v3' }); state.inFlight = inFlight;
  state.days['2026-07-23'] = { reservedInputTokens: 12, reservedOutputTokens: 3, usedInputTokens: 0, usedOutputTokens: 0 };
  assert.equal(normalizeConversationExtractorState(state), state);
  assert.throws(() => assertExtractorStateRunnable(state), /extractor_model_pending_recovery_required/);
  assert.doesNotThrow(() => assertExtractorStateRunnable({ ...state, inFlight: { ...inFlight, stage: 'model_done' } }));
  assert.throws(() => resumeExtractorInFlight({ inFlight, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_model_pending_recovery_required/);
  assert.throws(() => resumeExtractorInFlight({ inFlight, sessionId, extractionIdentity, visibleRevisionDigest: `sha256:${'b'.repeat(64)}`, readerGeneration: 'conversation-v3' }), /extractor_model_pending_recovery_required/);
  assert.throws(() => resumeExtractorInFlight({ inFlight, sessionId: 'ccon_otherexample1', extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_model_pending_recovery_required/);
  const incomplete = { ...inFlight, reservation: { reserved: true, day: '2026-07-23', inputTokens: 12 } };
  const invalid = createExtractorState({ readerGeneration: 'conversation-v3' }); invalid.inFlight = incomplete;
  assert.throws(() => normalizeConversationExtractorState(invalid), /extractor_state_invalid/);
  assert.throws(() => resumeExtractorInFlight({ inFlight: incomplete, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_inflight_invalid/);
  for (const day of ['2026-02-30', '2026-13-01']) {
    const impossible = { ...inFlight, reservation: { ...inFlight.reservation, day } };
    assert.throws(() => resumeExtractorInFlight({ inFlight: impossible, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_inflight_invalid/);
  }
  const unbacked = structuredClone(state); unbacked.days['2026-07-23'].reservedInputTokens = 11;
  assert.throws(() => normalizeConversationExtractorState(unbacked), /extractor_state_invalid/);
});

test('matching proposing state replays persisted records and keys byte-for-byte without model work', () => {
  const [claim] = validateClaims([{ claimType: 'decision', claim: 'Persist an exact proposal body before retrying delivery.', confidence: 0.8 }]);
  const sessionId = 'ccon_revisionexample1'; const extractionIdentity = `ses_${'c'.repeat(64)}`; const visibleRevisionDigest = `sha256:${'a'.repeat(64)}`;
  const record = buildMemoryRecord({ sessionId, extractionIdentity, visibleRevisionDigest, transcript: 'redacted transcript', claim, now: '2026-07-20T12:00:00Z' });
  const proposalKey = proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest, claim: claim.claim });
  const inFlight = { sessionId, extractionIdentity, visibleRevisionDigest, stage: 'proposing', claims: [claim], usage: { inputTokens: 12, outputTokens: 3 }, proposalKeys: [proposalKey], proposalRecords: [record] };
  const resumed = resumeExtractorInFlight({ inFlight, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' });
  assert.equal(resumed.stage, 'proposing'); assert.deepEqual(resumed.proposalKeys, [proposalKey]); assert.deepEqual(resumed.proposalRecords, [record]);
  const body = value => ({ record: value, rationale: `Conversation extractor durable claim from ${sessionId}; automatic curator and receipt applicator perform canonical plaintext deduplication.` });
  assert.equal(JSON.stringify(body(resumed.proposalRecords[0])), JSON.stringify(body(record)), 'retry body is exactly the staged body');
  assert.equal(resumeExtractorInFlight({ inFlight, sessionId, extractionIdentity, visibleRevisionDigest: `sha256:${'b'.repeat(64)}`, readerGeneration: 'conversation-v3' }), null);
  assert.equal(resumeExtractorInFlight({ inFlight: { ...inFlight, stage: 'model_done' }, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }).stage, 'model_done');
  assert.throws(() => resumeExtractorInFlight({ inFlight: { ...inFlight, proposalRecords: [{ ...record, id: 'mem_extract_invalid' }] }, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_inflight_invalid/);
  assert.throws(() => resumeExtractorInFlight({ inFlight: { ...inFlight, proposalRecords: [{ ...record, scope: { type: 'agent', id: 'agent:mutated-scope' } }] }, sessionId, extractionIdentity, visibleRevisionDigest, readerGeneration: 'conversation-v3' }), /extractor_inflight_invalid/);
});

test('shared global extraction drops explicitly project-scoped claims', () => {
  assert.equal(sharedDurableClaim('Project-specific agent guidance should describe this project.'), false);
  assert.equal(sharedDurableClaim('Prefer reusable policy over a one-off integration.'), true);
});

test('dedup compares normalized decrypted claim content, not encrypted storage bytes', () => {
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: ' keep THE extractor slow. ' }, ciphertext: 'different' } }]), true);
  assert.equal(duplicateCanonicalClaim('Keep the extractor slow.', [{ record: { claim: { text: 'Another decision.' }, ciphertext: 'same' } }]), false);
});
