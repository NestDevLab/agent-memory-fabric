import crypto from 'node:crypto';

import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId } from './m4-v2-conversation-projector.mjs';

export const M4_CONVERSATION_EXTRACTOR_ALIASES_SCHEMA = 'amf.m4-conversation-extractor-aliases/v1';
export const M4_CONVERSATION_EXTRACTOR_ALIASES_MAX = 100_000;

const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const LEGACY_SESSION_ID = /^ses_[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAC = /^hmac-sha256:[A-Za-z0-9_-]{43}$/;

function failure(code) { const error = new Error(code); error.code = code; return error; }
function fail(code) { throw failure(code); }
function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function key(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail('m4_extractor_alias_key_invalid');
  return value;
}
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function mac(value, secret) { return `hmac-sha256:${crypto.createHmac('sha256', secret).update(canonicalJson(value), 'utf8').digest('base64url')}`; }
function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const actual = Buffer.from(left, 'utf8'); const expected = Buffer.from(right, 'utf8');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
function canonicalTimestamp(value) {
  if (typeof value !== 'string' || !isConversationEventUtcTimestamp(value) || !value.endsWith('Z')) fail('m4_extractor_alias_timestamp_invalid');
  return value;
}
function timestampKey(value) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) fail('m4_extractor_identity_input_invalid');
  return `${match[1]}.${(match[2] || '').padEnd(9, '0')}`;
}
function alias(value) {
  if (!exact(value, ['conversationId', 'extractionIdentity']) || !CONVERSATION_ID.test(value.conversationId)
    || !(LEGACY_SESSION_ID.test(value.extractionIdentity) || value.extractionIdentity === value.conversationId)) {
    fail('m4_extractor_alias_entry_invalid');
  }
  if (LEGACY_SESSION_ID.test(value.extractionIdentity)
    && deriveM4V3ConversationIdFromLegacySessionId(value.extractionIdentity) !== value.conversationId) {
    fail('m4_extractor_alias_binding_invalid');
  }
  return { conversationId: value.conversationId, extractionIdentity: value.extractionIdentity };
}
function aliases(value) {
  if (!Array.isArray(value) || value.length > M4_CONVERSATION_EXTRACTOR_ALIASES_MAX) fail('m4_extractor_alias_entries_invalid');
  const result = value.map(alias);
  for (let index = 0; index < result.length; index += 1) {
    if (index > 0 && result[index - 1].conversationId >= result[index].conversationId) fail('m4_extractor_alias_order_invalid');
  }
  return result;
}
export function createM4ConversationArchiveCoverageBinding(value) {
  if (!Array.isArray(value) || value.length > M4_CONVERSATION_EXTRACTOR_ALIASES_MAX
    || value.some(item => typeof item !== 'string' || !CONVERSATION_ID.test(item))) fail('m4_extractor_alias_coverage_invalid');
  for (let index = 1; index < value.length; index += 1) {
    if (value[index - 1] >= value[index]) fail('m4_extractor_alias_coverage_invalid');
  }
  return { conversationCount: value.length, conversationDigest: digest(value) };
}
function body({ coveredThrough, entries }) {
  const coverage = createM4ConversationArchiveCoverageBinding(entries.map(item => item.conversationId));
  return {
    schema: M4_CONVERSATION_EXTRACTOR_ALIASES_SCHEMA,
    version: 1,
    coveredThrough: canonicalTimestamp(coveredThrough),
    archiveBinding: { ...coverage, aliasDigest: digest(entries) },
    aliases: entries,
  };
}

export function createM4ConversationExtractorAliases({ coveredThrough, aliases: input } = {}, secret) {
  let entries; try { entries = aliases(structuredClone(input)); } catch (error) { if (error?.code) throw error; fail('m4_extractor_alias_entries_invalid'); }
  const unsigned = body({ coveredThrough, entries });
  return structuredClone({ ...unsigned, mac: mac(unsigned, key(secret)) });
}

export function verifyM4ConversationExtractorAliases(value, secret) {
  let snapshot; try { snapshot = structuredClone(value); } catch { fail('m4_extractor_alias_manifest_invalid'); }
  if (!exact(snapshot, ['schema', 'version', 'coveredThrough', 'archiveBinding', 'aliases', 'mac'])
    || snapshot.schema !== M4_CONVERSATION_EXTRACTOR_ALIASES_SCHEMA || snapshot.version !== 1
    || !exact(snapshot.archiveBinding, ['conversationCount', 'conversationDigest', 'aliasDigest'])
    || !Number.isSafeInteger(snapshot.archiveBinding.conversationCount) || snapshot.archiveBinding.conversationCount < 0
    || !DIGEST.test(snapshot.archiveBinding.conversationDigest) || !DIGEST.test(snapshot.archiveBinding.aliasDigest)
    || !MAC.test(snapshot.mac)) fail('m4_extractor_alias_manifest_invalid');
  const entries = aliases(snapshot.aliases); const unsigned = body({ coveredThrough: snapshot.coveredThrough, entries });
  if (snapshot.archiveBinding.conversationCount !== unsigned.archiveBinding.conversationCount
    || snapshot.archiveBinding.aliasDigest !== unsigned.archiveBinding.aliasDigest
    || !safeEqual(snapshot.mac, mac(unsigned, key(secret)))) fail('m4_extractor_alias_manifest_invalid');
  return structuredClone(unsigned);
}

export function createM4ConversationExtractorIdentityResolver(value, secret) {
  const verified = verifyM4ConversationExtractorAliases(value, secret);
  const identities = new Map(verified.aliases.map(item => [item.conversationId, item.extractionIdentity]));
  const cutoff = timestampKey(verified.coveredThrough);
  return Object.freeze({
    kind: 'm4-conversation-extractor-aliases-v1',
    conversationCount: identities.size,
    coveredThrough: verified.coveredThrough,
    coverageBinding: Object.freeze({ coveredThrough: verified.coveredThrough, coveredThroughKey: timestampKey(verified.coveredThrough),
      conversationCount: verified.archiveBinding.conversationCount, conversationDigest: verified.archiveBinding.conversationDigest }),
    resolve({ conversationId, firstOccurredAt, lastOccurredAt } = {}) {
      if (!CONVERSATION_ID.test(conversationId) || !isConversationEventUtcTimestamp(firstOccurredAt)
        || !isConversationEventUtcTimestamp(lastOccurredAt) || timestampKey(firstOccurredAt) > timestampKey(lastOccurredAt)) {
        fail('m4_extractor_identity_input_invalid');
      }
      const found = identities.get(conversationId);
      if (found) return found;
      if (timestampKey(firstOccurredAt) <= cutoff) fail('m4_extractor_identity_alias_missing');
      return conversationId;
    },
  });
}
