import crypto from 'node:crypto';
import { validateAmfMemoryRecord } from './amf-memory-record-validator.mjs';
import { canonicalJson } from './ingest/transcripts/canonical.mjs';

export const RAW_MEMORY_EXTRACTOR_STATE_SCHEMA = 'amf.raw-memory-extractor-state/v1';
export const CONVERSATION_MEMORY_EXTRACTOR_STATE_SCHEMA = 'amf.raw-memory-extractor-state/v2';
export const RAW_MEMORY_EXTRACTOR_VERSION = 'amf.raw-memory-extractor/v1';

const ELIGIBLE_TYPES = new Set(['decision', 'preference', 'instruction', 'summary']);
const OPERATIONAL = /\b(?:error|exception|failed?|failure|incident|outage|alert|metric|counter|latency|throughput|deploy(?:ment)?|restart(?:ed)?|health ?check|ticket|log|trace|cpu|memory usage)\b/i;
const DURABLE = /\b(?:decid(?:e|ed|ing|iamo|iamo di)|prefer(?:s|red|enza)?|always|never|must|should|will|commit(?:ted|ment)?|agreed|conclusion|policy|standard|regola|preferisc|decidiamo|mai|sempre|dobbiamo|impegno)\b/i;
const PROJECT_SCOPED = /\b(?:project-specific|this project|the project)\b/i;
const CONVERSATION_ID = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const EXTRACTION_IDENTITY = /^(?:ses_[a-f0-9]{64}|ccon_[a-z0-9][a-z0-9_-]{7,127})$/;
const VISIBLE_REVISION_DIGEST = /^sha256:[a-f0-9]{64}$/;

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function normalizeClaimText(value) {
  return String(value || '').normalize('NFKC').replace(/\s+/g, ' ').trim().toLocaleLowerCase('en-US');
}

export function transcriptText(items) {
  if (!Array.isArray(items)) return '';
  return items.filter(item => item && ['user', 'assistant'].includes(item.role))
    .map(item => ({ role: item.role, text: typeof item.text === 'string' ? item.text : item.content?.text }))
    .filter(item => typeof item.text === 'string')
    .map(item => `${item.role}: ${item.text.trim()}`).filter(Boolean).join('\n');
}

// GPT tokenizers are byte based: UTF-8 bytes are a conservative, model-independent
// upper bound.  This is deliberately not a character-count approximation.
export function utf8TokenUpperBound(value) {
  return Buffer.byteLength(String(value || ''), 'utf8');
}

export function truncateUtf8ToTokenUpperBound(value, maximum) {
  const bytes = Buffer.from(String(value || ''), 'utf8');
  if (!Number.isSafeInteger(maximum) || maximum < 0) throw new Error('extractor_token_bound_invalid');
  if (bytes.length <= maximum) return bytes.toString('utf8');
  let end = maximum;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString('utf8');
}

export function triageConversation(items, { minChars = 80 } = {}) {
  const text = transcriptText(items);
  if (!text) return { pass: false, reason: 'empty_or_nonconversational' };
  if (text.length < minChars) return { pass: false, reason: 'too_short' };
  if (OPERATIONAL.test(text)) return { pass: false, reason: 'operational_content' };
  if (!DURABLE.test(text)) return { pass: false, reason: 'no_durable_signal' };
  return { pass: true, text, reason: 'durable_signal' };
}

export function createExtractorState({ readerGeneration = 'legacy-v2' } = {}) {
  if (readerGeneration === 'conversation-v3') return { schema: CONVERSATION_MEMORY_EXTRACTOR_STATE_SCHEMA, version: 2,
    stream: 'shared:global', phase: 'newest-first', readerGeneration, cursor: null, inFlight: null, days: {}, legacyBoundary: null };
  if (readerGeneration !== 'legacy-v2') throw new Error('extractor_state_generation_invalid');
  return { schema: RAW_MEMORY_EXTRACTOR_STATE_SCHEMA, version: 1, stream: 'shared:global', phase: 'newest-first',
    cursor: null, inFlight: null, days: {} };
}

export function normalizeState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== RAW_MEMORY_EXTRACTOR_STATE_SCHEMA
      || value.version !== 1 || value.stream !== 'shared:global' || value.phase !== 'newest-first'
      || (value.cursor !== null && typeof value.cursor !== 'string') || (value.inFlight !== null && typeof value.inFlight !== 'object')
      || !value.days || typeof value.days !== 'object' || Array.isArray(value.days)) throw new Error('extractor_state_invalid');
  return value;
}

export function normalizeConversationExtractorState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema !== CONVERSATION_MEMORY_EXTRACTOR_STATE_SCHEMA
      || value.version !== 2 || value.stream !== 'shared:global' || value.phase !== 'newest-first'
      || value.readerGeneration !== 'conversation-v3' || (value.cursor !== null && typeof value.cursor !== 'string')
      || (value.inFlight !== null && !validConversationInFlight(value.inFlight)) || !value.days || typeof value.days !== 'object'
      || Array.isArray(value.days) || (value.legacyBoundary !== null && (!value.legacyBoundary
        || typeof value.legacyBoundary !== 'object' || Array.isArray(value.legacyBoundary)
        || Object.keys(value.legacyBoundary).sort().join('\0') !== 'schema\0stateDigest'
        || value.legacyBoundary.schema !== RAW_MEMORY_EXTRACTOR_STATE_SCHEMA
        || !/^sha256:[a-f0-9]{64}$/.test(value.legacyBoundary.stateDigest)))) throw new Error('extractor_state_invalid');
  return value;
}

function validConversationInFlight(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && CONVERSATION_ID.test(value.sessionId) && EXTRACTION_IDENTITY.test(value.extractionIdentity)
    && VISIBLE_REVISION_DIGEST.test(value.visibleRevisionDigest)
    && ['model_pending', 'model_done', 'proposing'].includes(value.stage)
    && (value.stage !== 'proposing' || (Array.isArray(value.proposalKeys) && Array.isArray(value.proposalRecords)));
}

export function migrateExtractorStateToConversationV3(value) {
  const legacy = normalizeState(structuredClone(value));
  if (legacy.cursor !== null || legacy.inFlight !== null) throw new Error('extractor_state_migration_not_at_boundary');
  const migrated = createExtractorState({ readerGeneration: 'conversation-v3' });
  migrated.days = structuredClone(legacy.days);
  if (legacy.planUsage !== undefined) migrated.planUsage = structuredClone(legacy.planUsage);
  migrated.legacyBoundary = { schema: RAW_MEMORY_EXTRACTOR_STATE_SCHEMA,
    stateDigest: `sha256:${crypto.createHash('sha256').update(canonicalJson(legacy), 'utf8').digest('hex')}` };
  return normalizeConversationExtractorState(migrated);
}

function dayKey(now) {
  return new Date(now).toISOString().slice(0, 10);
}

function day(state, now) {
  const key = dayKey(now);
  state.days[key] ||= { reservedInputTokens: 0, reservedOutputTokens: 0, usedInputTokens: 0, usedOutputTokens: 0 };
  return state.days[key];
}

export function reserveModelBudget(state, config, now = new Date().toISOString()) {
  const current = day(state, now);
  const input = Number(config.maxInputTokensPerConversation);
  const output = Number(config.maxOutputTokensPerConversation);
  if (!Number.isSafeInteger(input) || !Number.isSafeInteger(output) || input < 1 || output < 1) throw new Error('extractor_budget_invalid');
  if (current.usedInputTokens + current.reservedInputTokens + input > Number(config.dailyInputTokens)
      || current.usedOutputTokens + current.reservedOutputTokens + output > Number(config.dailyOutputTokens)) return { reserved: false, day: dayKey(now) };
  current.reservedInputTokens += input; current.reservedOutputTokens += output;
  return { reserved: true, day: dayKey(now), inputTokens: input, outputTokens: output };
}

export function settleModelBudget(state, reservation, usage = {}) {
  if (!reservation?.reserved) return;
  const current = state.days[reservation.day];
  if (!current) throw new Error('extractor_budget_reservation_missing');
  const input = Number(usage.inputTokens || 0);
  const output = Number(usage.outputTokens || 0);
  if (!Number.isSafeInteger(input) || !Number.isSafeInteger(output) || input < 0 || output < 0) throw new Error('extractor_model_usage_invalid');
  current.reservedInputTokens -= reservation.inputTokens; current.reservedOutputTokens -= reservation.outputTokens;
  current.usedInputTokens += input; current.usedOutputTokens += output;
}

export function validateClaims(value, { maxClaims = 2 } = {}) {
  if (!Array.isArray(value) || value.length > maxClaims) throw new Error('extractor_claims_invalid');
  const seen = new Set();
  return value.map(item => {
    if (!item || typeof item !== 'object' || !ELIGIBLE_TYPES.has(item.claimType) || typeof item.claim !== 'string') throw new Error('extractor_claim_invalid');
    const claim = item.claim.replace(/\s+/g, ' ').trim();
    if (claim.length < 12 || claim.length > 280 || OPERATIONAL.test(claim)) throw new Error('extractor_claim_invalid');
    const normalized = normalizeClaimText(claim);
    if (seen.has(normalized)) throw new Error('extractor_claim_duplicate');
    seen.add(normalized);
    return { claimType: item.claimType, claim, confidence: Math.max(0, Math.min(1, Number(item.confidence ?? 0.5))) };
  });
}

export function duplicateCanonicalClaim(claim, records) {
  const candidate = normalizeClaimText(claim);
  return (Array.isArray(records) ? records : []).some(item => normalizeClaimText(item?.record?.claim?.text ?? item?.claim?.text) === candidate);
}

export function sharedDurableClaim(claim) {
  return !PROJECT_SCOPED.test(String(claim || ''));
}

export function resumeExtractorInFlight({ inFlight, sessionId, extractionIdentity, visibleRevisionDigest = undefined, readerGeneration = 'legacy-v2', maxClaims = 2 }) {
  if (!inFlight || typeof inFlight !== 'object' || Array.isArray(inFlight) || !['legacy-v2', 'conversation-v3'].includes(readerGeneration)) return null;
  const inFlightIdentity = inFlight.extractionIdentity ?? (readerGeneration === 'legacy-v2' ? inFlight.sessionId : null);
  const matchingRevision = readerGeneration === 'legacy-v2' || (VISIBLE_REVISION_DIGEST.test(visibleRevisionDigest)
    && inFlight.visibleRevisionDigest === visibleRevisionDigest);
  if (inFlight.sessionId !== sessionId || inFlightIdentity !== extractionIdentity || !matchingRevision
      || !['model_done', 'proposing'].includes(inFlight.stage)) return null;
  const claims = validateClaims(inFlight.claims, { maxClaims });
  if (inFlight.stage !== 'proposing') return { stage: inFlight.stage, claims, usage: inFlight.usage, inputTokenUpperBound: inFlight.inputTokenUpperBound };
  const proposalRecords = validatePersistedProposalRecords({ records: inFlight.proposalRecords, proposalKeys: inFlight.proposalKeys,
    claims, sessionId, extractionIdentity, visibleRevisionDigest });
  return { stage: inFlight.stage, claims, usage: inFlight.usage, inputTokenUpperBound: inFlight.inputTokenUpperBound,
    proposalKeys: [...inFlight.proposalKeys], proposalRecords };
}

function validatePersistedProposalRecords({ records, proposalKeys, claims, sessionId, extractionIdentity, visibleRevisionDigest }) {
  if (!Array.isArray(records) || !Array.isArray(proposalKeys) || records.length !== proposalKeys.length
      || new Set(proposalKeys).size !== proposalKeys.length) throw new Error('extractor_inflight_invalid');
  const byClaim = new Map(claims.map(claim => [claim.claim, claim]));
  return records.map((record, index) => {
    const claim = byClaim.get(record?.claim?.text);
    const key = proposalIdempotencyKey({ sessionId, extractionIdentity, visibleRevisionDigest, claim: record?.claim?.text });
    const timestamp = record?.createdAt; const provenance = record?.provenance?.[0];
    if (!claim || proposalKeys[index] !== key || !validateAmfMemoryRecord(record).ok || record.schema !== 'amf-memory/v1'
      || record.id !== `mem_extract_${key.slice('raw-extractor:'.length, 'raw-extractor:'.length + 40)}`
      || record.claimType !== claim.claimType || record.claim?.encoding !== 'plain' || record.claim?.text !== claim.claim
      || record.scope?.type !== 'shared' || record.scope?.id !== 'shared:global' || record.visibility !== 'shared'
      || JSON.stringify(record.subjects) !== JSON.stringify([{ identityId: 'agent:raw-extractor', role: 'owner' }])
      || record.confidence?.score !== claim.confidence || record.confidence?.basis !== 'inferred' || record.confidence?.assessedAt !== timestamp
      || record.lifecycle?.status !== 'active' || record.lifecycle?.validFrom !== timestamp || record.lifecycle?.validTo !== null
      || !Array.isArray(record.lifecycle?.supersedes) || record.lifecycle.supersedes.length !== 0
      || record.lifecycle?.revokedAt !== null || record.lifecycle?.revocationReason !== null
      || !Array.isArray(record.provenance) || record.provenance.length !== 1 || provenance?.sourceType !== 'raw-conversation'
      || provenance?.sourceId !== String(extractionIdentity) || provenance?.eventId !== `session-${sha256(String(extractionIdentity)).slice(0, 32)}`
      || !/^[a-f0-9]{64}$/.test(provenance?.contentSha256) || provenance?.capturedAt !== timestamp
      || record.updatedAt !== timestamp) {
      throw new Error('extractor_inflight_invalid');
    }
    return record;
  });
}

export function extractionFingerprint({ sessionId, extractionIdentity = sessionId, visibleRevisionDigest = undefined, claim }) {
  // Keep existing v2 keys byte-for-byte stable. A v3 revision becomes part of
  // the identity only when the caller supplies a validated, content-free digest.
  const identity = visibleRevisionDigest === undefined ? String(extractionIdentity) : (() => {
    if (!VISIBLE_REVISION_DIGEST.test(visibleRevisionDigest)) throw new Error('extractor_visible_revision_invalid');
    return `${String(extractionIdentity)}\0${visibleRevisionDigest}`;
  })();
  return sha256(`${RAW_MEMORY_EXTRACTOR_VERSION}\0${identity}\0${normalizeClaimText(claim)}`);
}

export function buildMemoryRecord({ sessionId, extractionIdentity = sessionId, visibleRevisionDigest = undefined, transcript, claim, now }) {
  const fingerprint = extractionFingerprint({ extractionIdentity, visibleRevisionDigest, claim: claim.claim });
  const timestamp = new Date(now).toISOString().replace('.000Z', 'Z');
  return {
    schema: 'amf-memory/v1', id: `mem_extract_${fingerprint.slice(0, 40)}`, revision: 1,
    claimType: claim.claimType, scope: { type: 'shared', id: 'shared:global' }, visibility: 'shared',
    confidence: { score: claim.confidence, basis: 'inferred', assessedAt: timestamp },
    subjects: [{ identityId: 'agent:raw-extractor', role: 'owner' }], claim: { encoding: 'plain', text: claim.claim },
    lifecycle: { status: 'active', validFrom: timestamp, validTo: null, supersedes: [], revokedAt: null, revocationReason: null },
    provenance: [{ sourceType: 'raw-conversation', sourceId: String(extractionIdentity), eventId: `session-${sha256(String(extractionIdentity)).slice(0, 32)}`,
      contentSha256: sha256(transcript), capturedAt: timestamp }], createdAt: timestamp, updatedAt: timestamp
  };
}

export function proposalIdempotencyKey({ sessionId, extractionIdentity = sessionId, visibleRevisionDigest = undefined, claim }) {
  return `raw-extractor:${extractionFingerprint({ extractionIdentity, visibleRevisionDigest, claim })}`;
}
