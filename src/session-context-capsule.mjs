import crypto from 'node:crypto';

const CONVERSATION_ID = /^ccon_[A-Za-z0-9_-]{8,128}$/;
const RESOURCE_ID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const REASONS = new Set(['exact_anchor', 'authority', 'freshness', 'hybrid_similarity', 'recency']);

function failure(code) { throw Object.assign(new Error(code), { code }); }
function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function points(value, max) { return Array.from(String(value ?? '')).slice(0, max).join(''); }
function id(prefix, ...parts) { return `${prefix}${crypto.createHash('sha256').update(parts.join('\0'), 'utf8').digest('base64url').slice(0, 24)}`; }
function secondTimestamp(value) { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) failure('session_context_capsule_invalid'); return new Date(Math.floor(parsed / 1000) * 1000).toISOString().replace('.000Z', 'Z'); }

function transcriptItems(transcript) {
  if (!transcript || transcript.view !== 'redacted' || !Array.isArray(transcript.items) || transcript.items.length > 100) failure('session_context_capsule_invalid');
  return transcript.items.map(item => {
    const text = item?.content?.text;
    if (item?.content?.redacted !== true || item?.content?.contentType !== 'text' || typeof text !== 'string' || !['user', 'assistant'].includes(item.role)) failure('session_context_capsule_invalid');
    return { eventId: String(item.eventId), occurredAt: secondTimestamp(item.occurredAt), role: item.role, text };
  });
}

/**
 * Produce the exact bounded redacted transcript view that an expansion can
 * disclose.  The reference store hashes this projection, rather than a live
 * reader cursor or an unbounded transcript, so an expansion cannot silently
 * return content different from the capsule that issued its reference.
 */
export function createSessionContextExpansionSnapshot({ transcript } = {}) {
  const rows = transcriptItems(transcript).slice(0, 5);
  const excerpts = rows.map(row => freeze({ eventId: row.eventId, occurredAt: row.occurredAt, role: row.role, text: points(row.text, 1024), redacted: true }))
    .filter(item => /\S/u.test(item.text));
  if (!excerpts.length) failure('session_context_capsule_not_found');
  return freeze({ view: 'redacted', excerpts });
}

function safeReasons(value) {
  const input = value ?? ['hybrid_similarity'];
  if (!Array.isArray(input) || input.length < 1 || input.length > 5 || new Set(input).size !== input.length || input.some(reason => !REASONS.has(reason))) failure('session_context_capsule_invalid');
  return [...input];
}

export function createSessionContextCapsule({ session, transcript, expansionRef, query = '', now = new Date().toISOString(), ttlSeconds = 86_400,
  position = 1, reasons, contradiction = 'unknown', supersession = 'unknown', authority = 'source_asserted' } = {}) {
  if (!CONVERSATION_ID.test(session?.id) || !RESOURCE_ID.test(expansionRef) || typeof query !== 'string' || Array.from(query).length > 512 ||
    !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 2_592_000 || !Number.isSafeInteger(position) || position < 1 || position > 10_000 ||
    !['none', 'present', 'unknown'].includes(contradiction) || !['current', 'superseded', 'unknown'].includes(supersession) || !['source_asserted', 'derived'].includes(authority)) failure('session_context_capsule_invalid');
  const nowMs = Date.parse(now); if (!Number.isFinite(nowMs)) failure('session_context_capsule_invalid');
  const rows = transcriptItems(transcript);
  const observedAt = secondTimestamp(session.lastOccurredAt ?? rows.at(-1)?.occurredAt ?? now);
  if (Date.parse(observedAt) > nowMs) failure('session_context_capsule_invalid');
  const expiresAt = secondTimestamp(new Date(nowMs + (ttlSeconds * 1000)).toISOString());
  const queryText = query.trim().toLocaleLowerCase('und');
  const ranked = [...rows].sort((left, right) => {
    const leftExact = queryText && left.text.toLocaleLowerCase('und').includes(queryText) ? 1 : 0;
    const rightExact = queryText && right.text.toLocaleLowerCase('und').includes(queryText) ? 1 : 0;
    return rightExact - leftExact || right.occurredAt.localeCompare(left.occurredAt) || left.eventId.localeCompare(right.eventId);
  }).slice(0, 3);
  const snippets = ranked.map(row => freeze({ ref: id('snp_', session.id, row.eventId), text: points(row.text, 512), redacted: true })).filter(item => /\S/u.test(item.text));
  const ageSeconds = Math.floor((nowMs - Date.parse(observedAt)) / 1000);
  const capsule = {
    id: id('csc_', session.id, observedAt, query),
    provenance: { sourceKind: 'conversation', sourceRef: expansionRef, observedAt, authority },
    freshness: { observedAt, expiresAt, state: ageSeconds > 604_800 ? 'stale' : 'fresh' },
    relevance: { state: 'relevant', overlap: Math.min(100, queryText ? 75 : 50), reasons: safeReasons(reasons) },
    contradiction, supersession, snippets, expansionRef
  };
  return freeze(capsule);
}

export function capsuleToPublicResource(capsule, position = 1) {
  if (!capsule || !RESOURCE_ID.test(capsule.expansionRef) || capsule.freshness?.state === 'expired' || !Number.isSafeInteger(position) || position < 1) failure('session_context_capsule_invalid');
  const text = capsule.snippets?.length ? capsule.snippets.map(item => item.text).join('\n') : 'Relevant conversation context is available.';
  return freeze({ id: capsule.expansionRef, kind: 'conversation', text: points(text, 65_536), admission: 'authorized', ranking: { position, reasons: [...capsule.relevance.reasons] }, contradiction: capsule.contradiction });
}

export function createSessionContextNotice(capsules) {
  if (!Array.isArray(capsules) || capsules.length > 50) failure('session_context_capsule_invalid');
  const count = capsules.filter(capsule => capsule?.freshness?.state !== 'expired').length;
  if (!count) return freeze({ ok: false, outcome: 'not_found' });
  return freeze({ ok: true, outcome: 'notice', notice: { mode: 'notice_only', state: 'available', candidateCount: count, expansionRequired: true } });
}

export function expandSessionContextTranscript({ id: resourceId, transcript } = {}) {
  if (!RESOURCE_ID.test(resourceId)) failure('session_context_capsule_invalid');
  const snapshot = createSessionContextExpansionSnapshot({ transcript });
  const excerpts = snapshot.excerpts.map(row => freeze({ id: id('exc_', resourceId, row.eventId), text: row.text, redacted: true }));
  return freeze({ excerpts, resource: { id: resourceId, kind: 'conversation', text: excerpts.map(item => item.text).join('\n'), admission: 'authorized', ranking: { position: 1, reasons: ['freshness'] }, contradiction: 'unknown' } });
}
