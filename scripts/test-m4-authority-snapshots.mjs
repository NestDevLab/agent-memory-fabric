import assert from 'node:assert/strict';
import test from 'node:test';

import {
  collectM4CatalogReferenceSnapshot,
  collectM4SelectorScopeSnapshot,
  verifyM4CatalogReferenceSnapshot,
  verifyM4SelectorScopeSnapshot,
} from '../src/migration/m4-authority-snapshots.mjs';

const digest = character => `sha256:${character.repeat(64)}`;
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });
const source = 'src_authorityscope1';
const policy = { schema: 'amf.content-protection-policy/v1', revision: 'authority-policy-v1',
  defaults: { conversation: 'plaintext', proposal: 'plaintext', 'canonical-memory': 'plaintext', document: 'plaintext' }, rules: [] };

async function catalogSnapshot() {
  return collectM4CatalogReferenceSnapshot({ snapshotId: 'catalog-snapshot-one', revision: 3,
    catalogRevision: { id: 'catalog-revision-one', digest: digest('1') }, observedAt: '2026-01-01T00:00:00Z', validThrough: '2026-01-02T00:00:00Z',
    catalogSource: iterable([
      { id: 'legacy-object-two', digest: digest('3'), objectType: 'transcript-blob', sourceInstanceId: source, contentClass: 'conversation', references: [{ id: 'catalog-reference-one', digest: digest('4') }] },
      { id: 'legacy-object-one', digest: digest('2'), objectType: 'transcript-row', sourceInstanceId: source, contentClass: 'conversation', references: [] },
    ]), keyDocument: key('catalog-authority-key', 1) });
}

test('catalog collector signs a complete canonical scan and derives only exact zero-reference targets', async () => {
  const manifest = await catalogSnapshot();
  assert.equal(manifest.scannedObjectCount, 2); assert.equal(manifest.scannedReferenceCount, 1);
  assert.deepEqual(manifest.objects.map(item => item.id), ['legacy-object-one', 'legacy-object-two']);
  assert.deepEqual(manifest.eligibleTargets.map(item => item.id), ['legacy-object-one']);
  assert.deepEqual(verifyM4CatalogReferenceSnapshot(manifest, key('catalog-authority-key', 1)), manifest);
});

test('catalog snapshot rejects forged counts, omitted scan rows, reordered entries, and wrong authority', async () => {
  for (const mutate of [
    value => { value.eligibleTargets[0].referenceCount = 1; },
    value => { value.scanDigest = digest('f'); },
    value => { value.objects.pop(); },
    value => { value.objects.reverse(); },
  ]) { const manifest = await catalogSnapshot(); mutate(manifest); assert.throws(() => verifyM4CatalogReferenceSnapshot(manifest, key('catalog-authority-key', 1)), /m4_catalog_reference_snapshot_(?:invalid|digest_mismatch)/); }
  const valid = await catalogSnapshot();
  assert.throws(() => verifyM4CatalogReferenceSnapshot(valid, key('other-catalog-key', 2)), /m4_catalog_reference_snapshot_key_id_mismatch/);
});

test('selector-scope collector signs the active policy and exact canonical selector set', async () => {
  const manifest = await collectM4SelectorScopeSnapshot({ snapshotId: 'selector-snapshot-one', revision: 2, policy,
    observedAt: '2026-01-01T00:00:00Z', validThrough: '2026-01-02T00:00:00Z',
    selectorSource: iterable([{ sourceInstanceId: source, contentClass: 'conversation' }]), keyDocument: key('selector-authority-key', 3) });
  assert.equal(manifest.policyRevision, policy.revision); assert.equal(manifest.selectors.length, 1);
  assert.deepEqual(verifyM4SelectorScopeSnapshot(manifest, key('selector-authority-key', 3)), manifest);
  for (const mutate of [value => { value.policyRevision = 'other-policy'; }, value => { value.selectors.push({ ...value.selectors[0] }); }, value => { value.selectorDigest = digest('e'); }]) {
    const changed = structuredClone(manifest); mutate(changed); assert.throws(() => verifyM4SelectorScopeSnapshot(changed, key('selector-authority-key', 3)), /m4_selector_scope_snapshot_(?:invalid|digest_mismatch)/);
  }
  assert.throws(() => verifyM4SelectorScopeSnapshot(manifest, key('other-selector-key', 4)), /m4_selector_scope_snapshot_key_id_mismatch/);
});

test('collectors reject duplicate identities, invalid windows, extras, and hostile sources', async () => {
  await assert.rejects(() => collectM4CatalogReferenceSnapshot({ snapshotId: 'catalog-snapshot-two', revision: 1,
    catalogRevision: { id: 'catalog-revision-two', digest: digest('1') }, observedAt: '2026-01-02T00:00:00Z', validThrough: '2026-01-01T00:00:00Z',
    catalogSource: iterable([]), keyDocument: key('catalog-authority-key', 1) }), /m4_catalog_reference_snapshot_input_invalid/);
  await assert.rejects(() => collectM4SelectorScopeSnapshot({ snapshotId: 'selector-snapshot-two', revision: 1, policy,
    observedAt: '2026-01-01T00:00:00Z', validThrough: '2026-01-02T00:00:00Z',
    selectorSource: iterable([{ sourceInstanceId: source, contentClass: 'conversation' }, { sourceInstanceId: source, contentClass: 'conversation' }]), keyDocument: key('selector-authority-key', 3) }), /m4_selector_scope_snapshot_input_invalid/);
  await assert.rejects(() => collectM4SelectorScopeSnapshot(new Proxy({}, { get() { throw new Error('private'); } })), /m4_selector_scope_snapshot_input_invalid/);
});

test('strict UTC validation rejects nonexistent dates and accepts a real leap day with nanoseconds', async () => {
  for (const observedAt of ['2026-02-30T00:00:00Z', '2025-02-29T00:00:00Z', '2026-01-01T24:00:00Z']) {
    await assert.rejects(() => collectM4SelectorScopeSnapshot({ snapshotId: 'selector-invalid-date', revision: 1, policy,
      observedAt, validThrough: '2026-12-31T00:00:00Z', selectorSource: iterable([{ sourceInstanceId: source, contentClass: 'conversation' }]),
      keyDocument: key('selector-authority-key', 3) }), /m4_selector_scope_snapshot_input_invalid/);
  }
  const leap = await collectM4SelectorScopeSnapshot({ snapshotId: 'selector-leap-date', revision: 1, policy,
    observedAt: '2024-02-29T23:59:59.123456789Z', validThrough: '2024-03-01T00:00:00Z',
    selectorSource: iterable([{ sourceInstanceId: source, contentClass: 'conversation' }]), keyDocument: key('selector-authority-key', 3) });
  assert.deepEqual(verifyM4SelectorScopeSnapshot(leap, key('selector-authority-key', 3)), leap);
});
