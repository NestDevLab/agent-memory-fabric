import assert from 'node:assert/strict';
import test from 'node:test';

import {
  compressionEvidence,
  measurePostgresEvidence,
  measureSqliteEvidence
} from './measure-content-protection-v1.mjs';

const CONTENT_CLASSES = ['conversation', 'proposal', 'canonical-memory', 'document'];
const VARIANTS = ['plaintext', 'aes', 'deflate-aes'];

test('SQLite measurement compares three physical variants for every content class', () => {
  const measurement = measureSqliteEvidence();
  assert.equal(measurement.version, 2);
  assert.equal(measurement.synthetic, true);
  assert.deepEqual(Object.keys(measurement.sqlite.variants), VARIANTS);

  for (const variant of Object.values(measurement.sqlite.variants)) {
    assert.deepEqual(Object.keys(variant.classes), CONTENT_CLASSES);
    assert.equal(variant.filesystem.normalizedBlockBytes, 4096);
    assert.ok(variant.filesystem.allocatedBytes > 0);
    assert.ok(variant.filesystem.allocatedBlocks4KiB > 0);
    assert.equal(variant.query.operations, 64);
    assert.equal(variant.query.indexedPlan, true);
    assert.equal(variant.query.nonNormative, true);
    assert.ok(Number.isFinite(variant.query.observedMs));
    for (const item of Object.values(variant.classes)) {
      assert.equal(item.sampleCount, 16);
      assert.ok(item.logicalBytes > 0);
      assert.ok(item.serializedBytes > 0);
    }
  }

  assert.deepEqual(measurement.compressionEvidence, compressionEvidence(measurement));
  for (const [contentClass, evidence] of Object.entries(measurement.compressionEvidence)) {
    assert.equal(evidence.algorithm, 'deflate-raw');
    assert.equal(evidence.contentClass, contentClass);
    assert.equal(
      evidence.savingsBytes,
      evidence.uncompressedEnvelopeBytes - evidence.compressedEnvelopeBytes
    );
    assert.equal(evidence.justified, evidence.sampleCount > 0 && evidence.savingsBytes >= 64);
  }
});

if (process.env.AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL) {
  test('PostgreSQL measurement compares the same three aggregate variants', async () => {
    const measurement = await measurePostgresEvidence(
      process.env.AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL
    );
    assert.deepEqual(Object.keys(measurement.variants), VARIANTS);
    assert.deepEqual(measurement.filesystem, { measured: false, reason: 'sqlite_only' });
    for (const variant of Object.values(measurement.variants)) {
      assert.deepEqual(Object.keys(variant.classes), CONTENT_CLASSES);
      assert.equal(variant.query.operations, 64);
      assert.equal(variant.query.indexedPlan, true);
      assert.equal(variant.query.nonNormative, true);
      assert.ok(Number.isFinite(variant.query.observedMs));
      for (const item of Object.values(variant.classes)) {
        assert.equal(item.sampleCount, 16);
        assert.ok(item.logicalBytes > 0);
        assert.ok(item.serializedBytes > 0);
      }
    }
  });
} else {
  test('PostgreSQL measurement is opt-in', {
    skip: 'set AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL'
  }, () => {});
}
