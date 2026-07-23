import assert from 'node:assert/strict';
import test from 'node:test';
import { CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES, createCapabilitySearchEquivalenceComparator } from '../src/capability-query-equivalence.mjs';

const result = (...texts) => ({ ok: true, outcome: 'found', items: texts.map((text, index) => ({ id: `rid_${String(index).padStart(8, 'a')}`, kind: 'canonical_memory', text })), nextCursor: null });
const compare = createCapabilitySearchEquivalenceComparator();

test('comparable results expose frozen aggregate metrics only', () => {
  const output = compare(result('one', 'two', 'three', 'four', 'five'), result('one', 'two', 'three', 'four', 'other'));
  assert.deepEqual(output, { comparable: true, outcomeParity: true, successful: true, leftCount: 5, rightCount: 5, countDelta: 0, overlapCount: 4, overlapRatio: 0.8, rankingAgreement: 1 });
  assert.equal(Object.isFrozen(output), true); assert.throws(() => { output.leftCount = 99; }, TypeError);
  assert.equal(JSON.stringify(output).includes('one'), false); assert.equal(JSON.stringify(output).includes('rid_'), false);
});
test('divergent count, overlap, and ranking fail comparison', () => {
  assert.deepEqual(compare(result(), result()), { comparable: true, outcomeParity: true, successful: true, leftCount: 0, rightCount: 0, countDelta: 0, overlapCount: 0, overlapRatio: 1, rankingAgreement: 1 });
  assert.equal(compare(result('one', 'two', 'three'), result('four', 'five', 'six')).comparable, false);
  assert.equal(compare(result('one', 'two', 'three', 'four'), result('four', 'three', 'two', 'one')).comparable, false);
  assert.equal(compare(result('one', 'two'), result('one', 'two', 'three', 'four', 'five')).comparable, false);
});
test('duplicate-heavy pages compare fingerprint occurrences rather than unique values', () => {
  assert.equal(compare(result('one', 'one', 'one', 'one', 'two'), result('one', 'two', 'two', 'two', 'two')).comparable, false);
  assert.equal(compare(result('one', 'one', 'one', 'one', 'two'), result('one', 'two')).comparable, false);
  assert.equal(compare(result('one', 'one', 'two', 'two'), result('one', 'one', 'two', 'two')).comparable, true);
});
test('authorization and failure outcomes require exact parity', () => {
  const forbidden = { ok: false, outcome: 'forbidden' }; const invalid = { ok: false, outcome: 'invalid_request' };
  assert.deepEqual(compare(forbidden, forbidden), { comparable: true, outcomeParity: true, successful: false, leftCount: 0, rightCount: 0, countDelta: 0, overlapCount: 0, overlapRatio: 0, rankingAgreement: 0 });
  assert.equal(compare(forbidden, invalid).comparable, false);
  assert.equal(compare(forbidden, result('one')).comparable, false);
});
test('malformed and hostile inputs fail closed without content leaks', () => {
  const privateText = 'private-comparator-secret'; const accessor = { ok: true, outcome: 'found', items: [], nextCursor: null }; Object.defineProperty(accessor, 'secret', { enumerable: true, get() { throw Error(privateText); } });
  for (const bad of [accessor, { ok: true, outcome: 'found', items: [{ id: 'bad', kind: 'canonical_memory', text: privateText }], nextCursor: null }, { ok: false, outcome: privateText }]) assert.throws(() => compare(bad, result('one')), failure => failure.code === 'capability_search_equivalence_invalid' && !failure.message.includes(privateText));
});
test('configuration is bounded, strict, and isolated from caller mutation', () => {
  assert.deepEqual(CAPABILITY_SEARCH_EQUIVALENCE_TOLERANCES, { maxCountDelta: 2, minOverlapRatio: 0.8, minRankingAgreement: 0.7 });
  assert.throws(() => createCapabilitySearchEquivalenceComparator({ maxCountDelta: 51, minOverlapRatio: 0.8, minRankingAgreement: 0.7 }), { code: 'capability_search_equivalence_invalid' });
  assert.throws(() => createCapabilitySearchEquivalenceComparator({ maxCountDelta: 3, minOverlapRatio: 0.8, minRankingAgreement: 0.7 }), { code: 'capability_search_equivalence_invalid' });
  assert.throws(() => createCapabilitySearchEquivalenceComparator({ maxCountDelta: 2, minOverlapRatio: 0.79, minRankingAgreement: 0.7 }), { code: 'capability_search_equivalence_invalid' });
  assert.throws(() => createCapabilitySearchEquivalenceComparator({ maxCountDelta: 2, minOverlapRatio: 0.8, minRankingAgreement: 0.69 }), { code: 'capability_search_equivalence_invalid' });
  assert.throws(() => createCapabilitySearchEquivalenceComparator({ maxCountDelta: 2, minOverlapRatio: 0.8, minRankingAgreement: 0.7, private: true }), { code: 'capability_search_equivalence_invalid' });
  const config = { maxCountDelta: 0, minOverlapRatio: 1, minRankingAgreement: 1 }; const strict = createCapabilitySearchEquivalenceComparator(config); config.maxCountDelta = 50; assert.equal(strict(result('one'), result('one', 'two')).comparable, false);
});
