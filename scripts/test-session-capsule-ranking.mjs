import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { SESSION_CAPSULE_RANKING_POLICY, rankSessionCapsules } from '../src/session-capsule-ranking.mjs';

const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/session-capsule-ranking-v1.conformance.json', import.meta.url), 'utf8'));
const capabilitySchema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf.capability-mcp-v2.schema.json', import.meta.url), 'utf8'));
const fixture = id => structuredClone(fixtures.scenarios.find(item => item.id === id));
const capsule = (id, authorityClass, freshnessAt, recencyAt = freshnessAt) => ({ id, redactedText: 'Atlas durable decision', anchors: ['Atlas'], authorityClass, freshnessAt, recencyAt });
const RANKED_AT = '2026-09-01T12:00:00.000Z';
const RANKING_SCHEMA = capabilitySchema.$defs.ranking;
const REASONS = new Set(RANKING_SCHEMA.properties.reasons.items.enum);

test('conformance vectors preserve Unicode normalization, vector ordering, and schema-compatible safe output only', () => {
  assert.equal(fixtures.policy, SESSION_CAPSULE_RANKING_POLICY);
  for (const scenario of fixtures.scenarios) assert.deepEqual(rankSessionCapsules(scenario.input), scenario.expected, scenario.id);
  const input = fixture('deterministic_authority_freshness_rrf').input;
  const reordered = { ...input, capsules: [...input.capsules].reverse(), vectorIds: [...input.vectorIds] };
  assert.deepEqual(rankSessionCapsules(reordered), rankSessionCapsules(input));
  for (const item of rankSessionCapsules(input)) {
    assert.deepEqual(Object.keys(item).sort(), ['id', 'position', 'reasons']);
    assert.ok(Number.isInteger(item.position) && item.position >= RANKING_SCHEMA.properties.position.minimum && item.position <= RANKING_SCHEMA.properties.position.maximum);
    assert.ok(item.reasons.length >= RANKING_SCHEMA.properties.reasons.minItems && item.reasons.length <= RANKING_SCHEMA.properties.reasons.maxItems && new Set(item.reasons).size === item.reasons.length && item.reasons.every(reason => REASONS.has(reason)));
  }
  assert.equal(JSON.stringify(rankSessionCapsules(input)).includes('score'), false);
  const unicode = capsule('rid_unicode001', 'unknown', RANKED_AT); unicode.redactedText = 'Café'; unicode.anchors = ['Café'];
  assert.ok(rankSessionCapsules({ rankedAt: RANKED_AT, query: 'Cafe\u0301', capsules: [unicode], vectorIds: [] })[0].reasons.includes('exact_anchor'));
});

test('blank/no-match inputs fail closed, only lane-union candidates rank, and vector-only admission is safe', () => {
  const input = fixture('opaque_id_tie').input;
  for (const query of ['', ' \t\n ']) assert.throws(() => rankSessionCapsules({ ...input, query }), /session_capsule_ranking_query_invalid/);
  assert.deepEqual(rankSessionCapsules({ ...input, query: 'absent', vectorIds: [] }), []);
  assert.deepEqual(rankSessionCapsules({ ...input, query: 'absent', vectorIds: ['rid_tie_beta01', 'rid_missing000'] }), [{ id: 'rid_tie_beta01', position: 1, reasons: ['freshness', 'hybrid_similarity', 'recency'] }]);
  const bodyOnly = { ...input, query: 'match', capsules: [{ ...input.capsules[0], anchors: [] }], vectorIds: [] };
  assert.equal(rankSessionCapsules(bodyOnly)[0].reasons.includes('exact_anchor'), false);
});

test('public 512-point queries and long lexical tokens do not enter bounded fuzzy comparison', () => {
  const lexical = length => {
    const token = 'a'.repeat(length);
    return { rankedAt: RANKED_AT, query: token, vectorIds: [], capsules: [{ ...capsule(`rid_long${String(length).padStart(4, '0')}`, 'unknown', RANKED_AT), redactedText: token, anchors: [] }] };
  };
  for (const length of [49, 512]) assert.deepEqual(rankSessionCapsules(lexical(length))[0].reasons, ['freshness', 'hybrid_similarity', 'recency']);
  assert.throws(() => rankSessionCapsules(lexical(513)), /session_capsule_ranking_input_invalid/);
});

test('authority and freshness buckets use exact B1/V2 boundaries before RRF', () => {
  const input = { rankedAt: RANKED_AT, query: 'missing', capsules: [
    capsule('rid_unknown000', 'unknown', '2026-07-01T12:00:00.000Z'), capsule('rid_derived000', 'derived_projection', '2026-07-01T12:00:00.000Z'),
    capsule('rid_attrib0000', 'attributed_observation', '2026-07-01T12:00:00.000Z'), capsule('rid_review000', 'reviewed_canonical', '2026-07-01T12:00:00.000Z'),
    capsule('rid_source000', 'source_authority', '2026-07-01T12:00:00.000Z')
  ] };
  input.vectorIds = input.capsules.map(item => item.id);
  assert.deepEqual(rankSessionCapsules(input).map(item => item.id), ['rid_source000', 'rid_review000', 'rid_attrib0000', 'rid_derived000', 'rid_unknown000']);
  const fresh = age => capsule(`rid_age_${String(age).padStart(7, '0')}`, 'unknown', new Date(Date.parse(RANKED_AT) - age * 1000).toISOString(), '2026-08-01T12:00:00.000Z');
  const unknownFreshness = capsule('rid_age_unknown', 'unknown', RANKED_AT, '2026-08-01T12:00:00.000Z'); delete unknownFreshness.freshnessAt;
  const ages = [unknownFreshness, fresh(2_592_001), fresh(2_592_000), fresh(604_801), fresh(604_800), fresh(86_401), fresh(86_400)];
  assert.deepEqual(rankSessionCapsules({ rankedAt: RANKED_AT, query: 'missing', capsules: ages, vectorIds: [...ages].reverse().map(item => item.id) }).map(item => item.id), ['rid_age_0086400', 'rid_age_0086401', 'rid_age_0604800', 'rid_age_0604801', 'rid_age_2592000', 'rid_age_2592001', 'rid_age_unknown']);
});

test('ASCII opaque-ID ties, bounded non-BMP fuzzy matching, and canonical timestamp forms are deterministic', () => {
  const ties = [capsule('rid_tie_aaaa', 'unknown', RANKED_AT), capsule('rid_tie_Aaaa', 'unknown', RANKED_AT), capsule('rid_tie-Aaaa', 'unknown', RANKED_AT)].map(item => ({ ...item, anchors: [], redactedText: 'tie' }));
  const tieInput = { rankedAt: RANKED_AT, query: 'tie', capsules: ties, vectorIds: [] };
  assert.deepEqual(rankSessionCapsules(tieInput).map(item => item.id), ['rid_tie-Aaaa', 'rid_tie_Aaaa', 'rid_tie_aaaa']);
  assert.deepEqual(rankSessionCapsules({ ...tieInput, capsules: [...ties].reverse() }), rankSessionCapsules(tieInput));
  const fuzzy = capsule('rid_astral001', 'unknown', RANKED_AT); fuzzy.anchors = []; fuzzy.redactedText = '𠀀abd';
  assert.deepEqual(rankSessionCapsules({ rankedAt: RANKED_AT, query: '𠀀abc', capsules: [fuzzy], vectorIds: [] })[0].reasons, ['freshness', 'hybrid_similarity', 'recency']);
  const seconds = capsule('rid_second001', 'unknown', '2026-09-01T12:00:00Z', '2026-09-01T12:00:00Z'); seconds.anchors = []; seconds.redactedText = 'time';
  const millis = { ...seconds, id: 'rid_millis001', freshnessAt: RANKED_AT, recencyAt: RANKED_AT };
  assert.deepEqual(rankSessionCapsules({ rankedAt: RANKED_AT, query: 'time', capsules: [seconds, millis], vectorIds: [] }).map(item => item.id), ['rid_millis001', 'rid_second001']);
  assert.deepEqual(rankSessionCapsules({ rankedAt: '2026-09-01T12:00:00Z', query: 'time', capsules: [seconds, millis], vectorIds: [] }), rankSessionCapsules({ rankedAt: RANKED_AT, query: 'time', capsules: [seconds, millis], vectorIds: [] }));
  assert.throws(() => rankSessionCapsules({ rankedAt: RANKED_AT, query: 'time', capsules: [{ ...seconds, freshnessAt: '2026-09-01T12:00:00.00Z' }], vectorIds: [] }), /session_capsule_ranking_input_invalid/);
});

test('expired/future input is excluded, while malformed or duplicate private envelopes fail closed', () => {
  const input = fixture('deterministic_authority_freshness_rrf').input;
  assert.equal(rankSessionCapsules(input).some(item => item.id === 'rid_expired004'), false);
  assert.equal(rankSessionCapsules(input).some(item => item.id === 'rid_future0005'), false);
  const duplicate = fixture('opaque_id_tie').input; duplicate.capsules.push(structuredClone(duplicate.capsules[0]));
  assert.throws(() => rankSessionCapsules(duplicate), /session_capsule_ranking_duplicate_id/);
  const missingAuthority = fixture('opaque_id_tie').input; delete missingAuthority.capsules[0].authorityClass;
  assert.throws(() => rankSessionCapsules(missingAuthority), /session_capsule_ranking_input_invalid/);
  const futureRecency = fixture('opaque_id_tie').input; futureRecency.capsules[0].recencyAt = '2026-09-01T12:00:01.000Z';
  assert.deepEqual(rankSessionCapsules(futureRecency).map(item => item.id), ['rid_tie_alpha2']);
});
