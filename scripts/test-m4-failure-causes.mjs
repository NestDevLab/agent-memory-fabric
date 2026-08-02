import assert from 'node:assert/strict';
import test from 'node:test';

import { reportedFailure } from './amf-m4-v2-backfill.mjs';

test('the report names the layer that failed without changing the stable field', () => {
  const error = new Error('m4_backfill_delivery_failed');
  error.code = 'm4_backfill_delivery_failed';
  assert.deepEqual(reportedFailure(error), { error: 'm4_operator_failed', failedWith: 'm4_backfill_delivery_failed' });
});

test('an operator code stays in the stable field', () => {
  const error = new Error('m4_operator_catalog_baseline_mismatch');
  error.code = 'm4_operator_catalog_baseline_mismatch';
  assert.deepEqual(reportedFailure(error), { error: 'm4_operator_catalog_baseline_mismatch' });
});

test('anything that is not a fixed identifier is withheld, so content cannot ride out on the code', () => {
  for (const value of ['SYNTHETIC_PRIVATE_EVENT', 'user said: hello', 'a'.repeat(200), 42, null, undefined]) {
    const error = new Error('x'); error.code = value;
    assert.deepEqual(reportedFailure(error), { error: 'm4_operator_failed' }, `leaked: ${String(value)}`);
  }
  assert.deepEqual(reportedFailure(undefined), { error: 'm4_operator_failed' });
});
