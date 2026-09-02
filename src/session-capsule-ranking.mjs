export const SESSION_CAPSULE_RANKING_POLICY = 'capability-mcp-v2-rank/v2';

const AUTHORITY = new Map([['unknown', 0], ['derived_projection', 1], ['attributed_observation', 2], ['reviewed_canonical', 3], ['source_authority', 4]]);
const RESOURCE_ID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const SAFE_REASONS = ['exact_anchor', 'authority', 'freshness', 'hybrid_similarity', 'recency'];
const MAX_CAPSULES = 1000;
const MAX_TEXT_POINTS = 4096;
const MAX_ANCHORS = 32;
const MAX_ANCHOR_POINTS = 256;
const MAX_QUERY_POINTS = 512;
const MAX_VECTOR_IDS = 10_000;
const MAX_FUZZY_TOKEN_POINTS = 48;
const MAX_FUZZY_COMPARISONS = 4096;

function fail(code) { throw new Error(code); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function points(value) { return Array.from(value).length; }
function normalizedText(value, maximum, code) {
  if (typeof value !== 'string' || points(value) > maximum) fail(code);
  return value.normalize('NFKC').toLocaleLowerCase('und').replace(/\s+/gu, ' ').trim();
}
function timestamp(value, code) {
  if (typeof value !== 'string' || !ISO_UTC.test(value) || !Number.isFinite(Date.parse(value))) fail(code);
  const canonical = new Date(value).toISOString();
  if (value !== canonical && value !== canonical.replace('.000Z', 'Z')) fail(code);
  return Date.parse(canonical);
}
function tokens(value) { return [...value.matchAll(/[\p{L}\p{N}]+/gu)].map(item => item[0]).filter(token => {
  const length = points(token); return length > 1 && length <= MAX_QUERY_POINTS;
}).slice(0, 128); }
function fuzzyEligible(token) { const length = points(token); return length >= 3 && length <= MAX_FUZZY_TOKEN_POINTS; }
function unique(values) { return [...new Set(values)]; }
function asciiCompare(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference) return difference;
  }
  return left.length - right.length;
}
function laneOrder(scores) { return [...scores].sort((left, right) => right.score - left.score || asciiCompare(left.id, right.id)).map(item => item.id); }
function distance(left, right) {
  const leftPoints = Array.from(left); const rightPoints = Array.from(right);
  if (Math.abs(leftPoints.length - rightPoints.length) > 2) return 3;
  let previous = Array.from({ length: rightPoints.length + 1 }, (_, index) => index);
  for (let row = 1; row <= leftPoints.length; row += 1) {
    const current = [row]; let smallest = current[0];
    for (let column = 1; column <= rightPoints.length; column += 1) {
      const value = Math.min(previous[column] + 1, current[column - 1] + 1, previous[column - 1] + (leftPoints[row - 1] === rightPoints[column - 1] ? 0 : 1));
      current.push(value); smallest = Math.min(smallest, value);
    }
    if (smallest > 2) return 3;
    previous = current;
  }
  return previous[rightPoints.length];
}
function freshness(ageSeconds) {
  if (ageSeconds <= 86_400) return 4;
  if (ageSeconds <= 604_800) return 3;
  if (ageSeconds <= 2_592_000) return 2;
  return 1;
}
function rrf(lanes, id) { return Object.values(lanes).reduce((total, lane) => { const index = lane.indexOf(id); return total + (index < 0 ? 0 : 1 / (60 + index + 1)); }, 0); }

function normalizeCapsule(value, rankedAtMs) {
  if (!plain(value) || Object.keys(value).some(key => !['id', 'redactedText', 'anchors', 'authorityClass', 'freshnessAt', 'recencyAt', 'expiresAt'].includes(key))
    || !RESOURCE_ID.test(value.id) || !AUTHORITY.has(value.authorityClass)) fail('session_capsule_ranking_input_invalid');
  const text = normalizedText(value.redactedText, MAX_TEXT_POINTS, 'session_capsule_ranking_input_invalid');
  if (!Array.isArray(value.anchors) || value.anchors.length > MAX_ANCHORS) fail('session_capsule_ranking_input_invalid');
  const anchors = value.anchors.map(item => normalizedText(item, MAX_ANCHOR_POINTS, 'session_capsule_ranking_input_invalid'));
  const freshnessAt = value.freshnessAt === undefined ? null : timestamp(value.freshnessAt, 'session_capsule_ranking_input_invalid');
  const recencyAt = timestamp(value.recencyAt, 'session_capsule_ranking_input_invalid');
  const expiresAt = value.expiresAt === undefined ? null : timestamp(value.expiresAt, 'session_capsule_ranking_input_invalid');
  // No envelope timestamp may be future-dated. A future expiry is expected;
  // expiry is a boundary, not a freshness or recency signal.
  if ((freshnessAt !== null && freshnessAt > rankedAtMs) || recencyAt > rankedAtMs) return null;
  if (expiresAt !== null && expiresAt <= rankedAtMs) return null;
  return { id: value.id, text, anchors, authority: AUTHORITY.get(value.authorityClass),
    freshness: freshnessAt === null ? 0 : freshness(Math.floor((rankedAtMs - freshnessAt) / 1000)), recencyAt, words: unique(tokens(`${text} ${anchors.join(' ')}`)) };
}

function buildLanes(capsules, query, vectorIds) {
  const queryWords = unique(tokens(query));
  const exact = []; const lexical = []; const fuzzy = [];
  let fuzzyComparisons = 0;
  for (const capsule of [...capsules].sort((left, right) => asciiCompare(left.id, right.id))) {
    if (capsule.anchors.includes(query)) exact.push({ id: capsule.id, score: 1 });
    const overlap = queryWords.reduce((count, token) => count + (capsule.words.includes(token) ? 1 : 0), 0);
    if (overlap) lexical.push({ id: capsule.id, score: overlap });
    let fuzzyMatches = 0;
    for (const token of queryWords) {
      if (fuzzyComparisons >= MAX_FUZZY_COMPARISONS) break;
      if (!fuzzyEligible(token)) continue;
      let matched = false;
      for (const word of capsule.words) {
        if (!fuzzyEligible(word)) continue;
        if (fuzzyComparisons >= MAX_FUZZY_COMPARISONS) break;
        fuzzyComparisons += 1;
        if (distance(token, word) <= Math.min(2, Math.floor(points(token) / 3))) { matched = true; break; }
      }
      if (matched) fuzzyMatches += 1;
    }
    if (fuzzyMatches) fuzzy.push({ id: capsule.id, score: fuzzyMatches });
  }
  const known = new Set(capsules.map(item => item.id));
  const vector = unique(vectorIds).filter(id => known.has(id));
  return { exact: laneOrder(exact), lexical: laneOrder(lexical), fuzzy: laneOrder(fuzzy), vector };
}

/**
 * Ranks private, already-authorized capsule envelopes. This module has no
 * provider access and accepts no provider/native score. All output is safe:
 * opaque id, one-based position, and bounded reason names only.
 */
export function rankSessionCapsules({ capsules, query, rankedAt, vectorIds = [] } = {}) {
  if (!Array.isArray(capsules) || capsules.length > MAX_CAPSULES || !Array.isArray(vectorIds) || vectorIds.length > MAX_VECTOR_IDS) fail('session_capsule_ranking_input_invalid');
  const rankedAtMs = timestamp(rankedAt, 'session_capsule_ranking_input_invalid');
  const normalizedQuery = normalizedText(query, MAX_QUERY_POINTS, 'session_capsule_ranking_input_invalid');
  if (!normalizedQuery) fail('session_capsule_ranking_query_invalid');
  if (vectorIds.some(id => !RESOURCE_ID.test(id))) fail('session_capsule_ranking_input_invalid');
  const accepted = capsules.map(item => normalizeCapsule(item, rankedAtMs)).filter(Boolean);
  if (new Set(accepted.map(item => item.id)).size !== accepted.length) fail('session_capsule_ranking_duplicate_id');
  const lanes = buildLanes(accepted, normalizedQuery, vectorIds);
  const laneUnion = new Set(Object.values(lanes).flat());
  const ranked = accepted.filter(item => laneUnion.has(item.id)).map(item => ({ ...item, exact: lanes.exact.includes(item.id), rrf: rrf(lanes, item.id) })).sort((left, right) =>
    Number(right.exact) - Number(left.exact) || right.authority - left.authority || right.freshness - left.freshness
      || right.rrf - left.rrf || right.recencyAt - left.recencyAt || asciiCompare(left.id, right.id));
  return Object.freeze(ranked.map((item, index) => {
    const hybrid = lanes.lexical.includes(item.id) || lanes.fuzzy.includes(item.id) || lanes.vector.includes(item.id);
    const reasons = SAFE_REASONS.filter(reason => {
      if (reason === 'exact_anchor') return lanes.exact.includes(item.id);
      if (reason === 'authority') return item.authority > 0;
      if (reason === 'freshness') return item.freshness > 0;
      if (reason === 'hybrid_similarity') return hybrid;
      return true;
    }).slice(0, 5);
    if (!reasons.length) fail('session_capsule_ranking_reason_invalid');
    return Object.freeze({ id: item.id, position: index + 1, reasons: Object.freeze(reasons) });
  }));
}
