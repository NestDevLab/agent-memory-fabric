import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createM4ConversationExtractorAliases,
  createM4ConversationExtractorIdentityResolver,
  verifyM4ConversationExtractorAliases,
} from '../src/migration/m4-conversation-extractor-aliases.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId } from '../src/migration/m4-v2-conversation-projector.mjs';

const key = Buffer.alloc(32, 41);
const legacy = `ses_${'a'.repeat(64)}`;
const mapped = deriveM4V3ConversationIdFromLegacySessionId(legacy);
const native = `ccon_native${'b'.repeat(20)}`;

function manifest() {
  return createM4ConversationExtractorAliases({ coveredThrough: '2026-07-22T10:00:00Z', aliases: [
    { conversationId: mapped, extractionIdentity: legacy },
    { conversationId: native, extractionIdentity: native },
  ].sort((left, right) => left.conversationId.localeCompare(right.conversationId)) }, key);
}

test('signed aliases bind deterministic legacy and native extraction identities', () => {
  const value = manifest(); const verified = verifyM4ConversationExtractorAliases(value, key);
  assert.equal(verified.archiveBinding.conversationCount, 2);
  assert.match(verified.archiveBinding.conversationDigest, /^sha256:[a-f0-9]{64}$/);
  const resolver = createM4ConversationExtractorIdentityResolver(value, key);
  assert.deepEqual({ count: resolver.coverageBinding.conversationCount, digest: resolver.coverageBinding.conversationDigest },
    { count: 2, digest: verified.archiveBinding.conversationDigest });
  assert.equal(resolver.resolve({ conversationId: mapped, firstOccurredAt: '2026-01-01T00:00:00Z', lastOccurredAt: '2026-01-02T00:00:00Z' }), legacy);
  assert.equal(resolver.resolve({ conversationId: native, firstOccurredAt: '2026-01-01T00:00:00Z', lastOccurredAt: '2026-01-02T00:00:00Z' }), native);
});

test('uncovered old conversations fail closed while new conversations use their v3 identity', () => {
  const resolver = createM4ConversationExtractorIdentityResolver(manifest(), key);
  const unknown = `ccon_unknown${'c'.repeat(20)}`;
  assert.throws(() => resolver.resolve({ conversationId: unknown, firstOccurredAt: '2026-07-22T10:00:00Z', lastOccurredAt: '2026-07-23T00:00:00Z' }), { code: 'm4_extractor_identity_alias_missing' });
  assert.equal(resolver.resolve({ conversationId: unknown, firstOccurredAt: '2026-07-22T10:00:00.000000001Z', lastOccurredAt: '2026-07-23T00:00:00Z' }), unknown);
});

test('tamper, wrong authority, unsorted entries, and false legacy mappings fail closed', () => {
  const value = manifest(); value.aliases[0].extractionIdentity = value.aliases[0].conversationId;
  assert.throws(() => verifyM4ConversationExtractorAliases(value, key), { code: 'm4_extractor_alias_manifest_invalid' });
  assert.throws(() => verifyM4ConversationExtractorAliases(manifest(), Buffer.alloc(32, 42)), { code: 'm4_extractor_alias_manifest_invalid' });
  assert.throws(() => createM4ConversationExtractorAliases({ coveredThrough: '2026-07-22T10:00:00Z', aliases: [
    { conversationId: native, extractionIdentity: native }, { conversationId: mapped, extractionIdentity: legacy },
  ] }, key), { code: 'm4_extractor_alias_order_invalid' });
  assert.throws(() => createM4ConversationExtractorAliases({ coveredThrough: '2026-07-22T10:00:00Z', aliases: [
    { conversationId: mapped, extractionIdentity: `ses_${'d'.repeat(64)}` },
  ] }, key), { code: 'm4_extractor_alias_binding_invalid' });
});

test('hostile inputs and invalid time ranges expose only fixed errors', () => {
  const hostile = new Proxy({}, { get() { throw new Error('private value'); } });
  assert.throws(() => verifyM4ConversationExtractorAliases(hostile, key), { code: 'm4_extractor_alias_manifest_invalid' });
  const resolver = createM4ConversationExtractorIdentityResolver(manifest(), key);
  assert.throws(() => resolver.resolve({ conversationId: native, firstOccurredAt: '2026-02-01T00:00:00Z', lastOccurredAt: '2026-01-01T00:00:00Z' }), { code: 'm4_extractor_identity_input_invalid' });
});
