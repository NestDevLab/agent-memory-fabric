import crypto from 'node:crypto';

const RESOURCE_ID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const CURSOR = /^cur_[A-Za-z0-9_-]{16,256}$/;
const KINDS = new Set(['canonical_memory', 'document', 'conversation']);
const OUTCOMES = new Set(['forbidden', 'invalid_request']);

/** Explicit bounded tolerance for provider-conformance search comparisons. */
export const CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES = deepFreeze({
  maxCountDelta: 2,
  minOverlapRatio: 0.8,
  minRankingAgreement: 0.7
});

function error() { const value = new Error('capability_search_equivalence_invalid'); value.code = value.message; return value; }
function deepFreeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
function exact(value, keys) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length || own.some(key => typeof key !== 'string' || !keys.includes(key))) return null;
    const out = {};
    for (const key of keys) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null; out[key] = descriptor.value; }
    return out;
  } catch { return null; }
}
function cleanArray(value) {
  try { return Array.isArray(value) && value.length <= 50 && Reflect.ownKeys(value).length === value.length + 1 && [...value.keys()].every(index => { const descriptor = Object.getOwnPropertyDescriptor(value, String(index)); return descriptor?.enumerable && Object.hasOwn(descriptor, 'value'); }); } catch { return false; }
}
function item(value) { const row = exact(value, ['id', 'kind', 'text']); return row && typeof row.id === 'string' && RESOURCE_ID.test(row.id) && KINDS.has(row.kind) && typeof row.text === 'string' && row.text.length > 0 && row.text.length <= 65536 && /\S/.test(row.text) ? row : null; }
function snapshotResult(value) {
  const found = exact(value, ['ok', 'outcome', 'items', 'nextCursor']);
  if (found && found.ok === true && found.outcome === 'found' && cleanArray(found.items) && (found.nextCursor === null || (typeof found.nextCursor === 'string' && CURSOR.test(found.nextCursor)))) {
    const items = found.items.map(item); if (items.every(Boolean)) return { outcome: 'found', items: items.map(row => ({ kind: row.kind, text: row.text })) };
  }
  const failure = exact(value, ['ok', 'outcome']);
  return failure && failure.ok === false && typeof failure.outcome === 'string' && OUTCOMES.has(failure.outcome) ? { outcome: failure.outcome } : null;
}
function fingerprint(row) { return crypto.createHash('sha256').update(`${row.kind}\0${row.text}`, 'utf8').digest('hex'); }
function occurrences(hashes) {
  const counts = new Map();
  return hashes.map(hash => {
    const occurrence = (counts.get(hash) || 0) + 1;
    counts.set(hash, occurrence);
    return `${hash}:${occurrence}`;
  });
}
function normalizedConfig(value) {
  const config = value === undefined ? CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES : exact(value, ['maxCountDelta', 'minOverlapRatio', 'minRankingAgreement']);
  if (!config || !Number.isSafeInteger(config.maxCountDelta) || config.maxCountDelta < 0
    || config.maxCountDelta > CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES.maxCountDelta
    || !Number.isFinite(config.minOverlapRatio)
    || config.minOverlapRatio < CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES.minOverlapRatio
    || config.minOverlapRatio > 1 || !Number.isFinite(config.minRankingAgreement)
    || config.minRankingAgreement < CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES.minRankingAgreement
    || config.minRankingAgreement > 1) throw error();
  return deepFreeze({ ...config });
}

/**
 * Compare two public `search` results without returning result content or opaque IDs.
 * Authorization and non-success outcomes must match exactly. Successful pages tolerate
 * small count drift, but require substantial fingerprint overlap and rank agreement.
 */
export function createCapabilitySearchEquivalenceComparator(config) {
  const tolerances = normalizedConfig(config);
  return Object.freeze((leftValue, rightValue) => {
    const left = snapshotResult(leftValue); const right = snapshotResult(rightValue);
    if (!left || !right) throw error();
    const outcomeParity = left.outcome === right.outcome;
    if (left.outcome !== 'found' || right.outcome !== 'found') return deepFreeze({ comparable: outcomeParity, outcomeParity, successful: false, leftCount: 0, rightCount: 0, countDelta: 0, overlapCount: 0, overlapRatio: 0, rankingAgreement: 0 });
    const leftOccurrences = occurrences(left.items.map(fingerprint));
    const rightOccurrences = occurrences(right.items.map(fingerprint));
    const leftPositions = new Map(leftOccurrences.map((token, index) => [token, index]));
    const rightPositions = new Map(rightOccurrences.map((token, index) => [token, index]));
    const overlap = leftOccurrences.filter(token => rightPositions.has(token)); const overlapCount = overlap.length;
    const bothEmpty = leftOccurrences.length === 0 && rightOccurrences.length === 0;
    const overlapRatio = bothEmpty ? 1 : overlapCount / Math.max(leftOccurrences.length, rightOccurrences.length, 1);
    const rankingAgreement = bothEmpty ? 1 : overlapCount < 2 ? (overlapCount === 1 ? 1 : 0) : 1 - overlap.reduce((sum, token) => sum + Math.abs(leftPositions.get(token) - rightPositions.get(token)), 0) / (overlapCount * Math.max(leftOccurrences.length, rightOccurrences.length, 1));
    const countDelta = Math.abs(left.items.length - right.items.length);
    const comparable = countDelta <= tolerances.maxCountDelta && overlapRatio >= tolerances.minOverlapRatio && rankingAgreement >= tolerances.minRankingAgreement;
    return deepFreeze({ comparable, outcomeParity: true, successful: true, leftCount: left.items.length, rightCount: right.items.length, countDelta, overlapCount, overlapRatio, rankingAgreement });
  });
}
