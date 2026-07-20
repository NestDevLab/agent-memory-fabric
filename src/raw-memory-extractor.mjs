import crypto from 'node:crypto';

export const RAW_MEMORY_EXTRACTOR_STATE_SCHEMA = 'amf.raw-memory-extractor-state/v1';
export const RAW_MEMORY_EXTRACTOR_VERSION = 'amf.raw-memory-extractor/v1';

const ELIGIBLE_TYPES = new Set(['decision', 'preference', 'instruction', 'summary']);
const OPERATIONAL = /\b(?:error|exception|failed?|failure|incident|outage|alert|metric|counter|latency|throughput|deploy(?:ment)?|restart(?:ed)?|health ?check|ticket|log|trace|cpu|memory usage)\b/i;
const DURABLE = /\b(?:decid(?:e|ed|ing|iamo|iamo di)|prefer(?:s|red|enza)?|always|never|must|should|will|commit(?:ted|ment)?|agreed|conclusion|policy|standard|regola|preferisc|decidiamo|mai|sempre|dobbiamo|impegno)\b/i;

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

export function createExtractorState() {
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

export function extractionFingerprint({ sessionId, claim }) {
  return sha256(`${RAW_MEMORY_EXTRACTOR_VERSION}\0${String(sessionId)}\0${normalizeClaimText(claim)}`);
}

export function buildMemoryRecord({ sessionId, transcript, claim, now }) {
  const fingerprint = extractionFingerprint({ sessionId, claim: claim.claim });
  const timestamp = new Date(now).toISOString().replace('.000Z', 'Z');
  return {
    schema: 'amf-memory/v1', id: `mem_extract_${fingerprint.slice(0, 40)}`, revision: 1,
    claimType: claim.claimType, scope: { type: 'shared', id: 'shared:global' }, visibility: 'shared',
    confidence: { score: claim.confidence, basis: 'inferred', assessedAt: timestamp },
    subjects: [{ identityId: 'agent:raw-extractor', role: 'owner' }], claim: { encoding: 'plain', text: claim.claim },
    lifecycle: { status: 'active', validFrom: timestamp, validTo: null, supersedes: [], revokedAt: null, revocationReason: null },
    provenance: [{ sourceType: 'raw-conversation', sourceId: String(sessionId), eventId: `session-${sha256(String(sessionId)).slice(0, 32)}`,
      contentSha256: sha256(transcript), capturedAt: timestamp }], createdAt: timestamp, updatedAt: timestamp
  };
}

export function proposalIdempotencyKey({ sessionId, claim }) {
  return `raw-extractor:${extractionFingerprint({ sessionId, claim })}`;
}
