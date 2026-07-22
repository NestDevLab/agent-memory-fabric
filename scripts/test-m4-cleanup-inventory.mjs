import assert from 'node:assert/strict';
import test from 'node:test';

import { createM4CleanupInventory, createM4CleanupManifest, m4CleanupManifestEvidence, verifyM4CleanupInventory, verifyM4CleanupManifest } from '../src/migration/m4-cleanup-inventory.mjs';
import { createM4CutoverAuthorization } from '../src/migration/m4-cutover-authorization.mjs';
import { digest, keyDocument, m4CutoverFixture } from './helpers/m4-cutover-fixtures.mjs';

async function input() {
  const fixture = await m4CutoverFixture(); const cutover = createM4CutoverAuthorization(fixture.authorizationInput, { selectorScopeKeyDocument: fixture.keys.selectorScope });
  const authorities = { catalogSnapshotKeyDocument: fixture.keys.catalogSnapshot };
  return { fixture, cutover, authorities, value: { manifestId: 'cleanup-inventory-one', revision: 1, inventoriedAt: '2026-01-02T01:04:00Z', cutoverManifest: cutover,
    cutoverKeyDocument: fixture.keys.authorization, preservationManifest: fixture.preservation, preservationKeyDocument: fixture.keys.preservation,
    catalogSnapshotManifest: fixture.catalogSnapshot,
    targets: structuredClone(fixture.catalogSnapshot.eligibleTargets), cleanupKeyDocument: fixture.keys.cleanup } };
}

test('creates exact zero-reference targets and projects the existing cleanup manifest inputs', async () => {
  const { fixture, cutover, authorities, value } = await input(); const before = structuredClone(value); const inventory = createM4CleanupInventory(value, authorities);
  assert.deepEqual(value, before); assert.equal(inventory.state, 'ready'); assert.equal(inventory.targets.length, 2);
  assert.deepEqual(verifyM4CleanupInventory(inventory, fixture.keys.cleanup), inventory);
  const projected = m4CleanupManifestEvidence(inventory, fixture.keys.cleanup, cutover, fixture.keys.authorization);
  assert.equal(projected.reconciliationEvidence.state, 'complete'); assert.equal(projected.cutoverCanary.state, 'passed');
  assert.equal(projected.restoreTest, 'passed'); assert.deepEqual(projected.targets, inventory.targets.map(item => ({ id: item.id, digest: item.digest })));
  const cleanup = createM4CleanupManifest({ manifestId: 'cleanup-manifest-one', revision: 1, inventory, inventoryKeyDocument: fixture.keys.cleanup,
    cutoverAuthorization: cutover, cutoverKeyDocument: fixture.keys.authorization, migrationKeyDocument: fixture.keys.cleanup });
  assert.equal(cleanup.schema, 'amf.migration-manifest/v1'); assert.equal(cleanup.phase, 'cleanup'); assert.equal(cleanup.cleanup.state, 'ready');
  assert.deepEqual(verifyM4CleanupManifest(cleanup, fixture.keys.cleanup), cleanup);
});

test('rejects referenced, missing, extra, unsorted, duplicate, and unknown-selector targets', async () => {
  const mutations = [
    value => { value.targets[0].referenceCount = 1; }, value => { value.targets.pop(); }, value => { value.targets.push({ ...value.targets[1], id: 'cleanup-transcript-third', digest: digest('5') }); },
    value => { value.targets.reverse(); }, value => { value.targets[1].digest = value.targets[0].digest; }, value => { value.targets[0].sourceInstanceId = 'src_unknownselector1'; },
  ];
  for (const mutate of mutations) { const { value, authorities } = await input(); mutate(value); assert.throws(() => createM4CleanupInventory(value, authorities), /m4_cleanup_inventory_(?:input_invalid|catalog_mismatch|count_mismatch|selector_invalid)/); }
});

test('rejects preserved overlap and any target drift from catalog authority', async () => {
  const preserved = await input(); preserved.value.targets[0].digest = preserved.fixture.preservation.preservedSharedData[0].binding.digest;
  assert.throws(() => createM4CleanupInventory(preserved.value, preserved.authorities), /m4_cleanup_inventory_catalog_mismatch/);
  const catalog = await input(); catalog.value.targets[0].id = catalog.fixture.catalogSnapshot.catalogRevision.id;
  catalog.value.targets.sort((left, right) => left.id.localeCompare(right.id));
  assert.throws(() => createM4CleanupInventory(catalog.value, catalog.authorities), /m4_cleanup_inventory_catalog_mismatch/);
});

test('tamper, wrong authority, unsafe projection, extras, and hostile input fail closed', async () => {
  const { fixture, cutover, authorities, value } = await input(); const inventory = createM4CleanupInventory(value, authorities); inventory.targets[0].digest = digest('f');
  assert.throws(() => verifyM4CleanupInventory(inventory, fixture.keys.cleanup), /m4_cleanup_inventory_digest_mismatch/);
  const clean = createM4CleanupInventory(value, authorities);
  assert.throws(() => verifyM4CleanupInventory(clean, keyDocument('other-cleanup-key', 9)), /m4_cleanup_inventory_key_id_mismatch/);
  const changedCutover = structuredClone(cutover); changedCutover.legacyRecoveryCopy.digest = digest('e');
  assert.throws(() => m4CleanupManifestEvidence(clean, fixture.keys.cleanup, changedCutover, fixture.keys.authorization), /m4_cleanup_inventory_projection_invalid/);
  const extra = structuredClone(value); extra.glob = '*'; assert.throws(() => createM4CleanupInventory(extra, authorities), /m4_cleanup_inventory_input_invalid/);
  assert.throws(() => createM4CleanupInventory(new Proxy({}, { get() { throw new Error('private'); } }), authorities), /m4_cleanup_inventory_input_invalid/);
  assert.throws(() => verifyM4CleanupInventory({ uncloneable: () => 'private' }, fixture.keys.cleanup), error => error.code === 'm4_cleanup_inventory_manifest_invalid');
  assert.throws(() => verifyM4CleanupManifest({ uncloneable: () => 'private' }, fixture.keys.cleanup), error => error.code === 'm4_cleanup_manifest_invalid');
});

test('inventory rejects stale and tampered catalog authority evidence', async () => {
  const stale = await input(); stale.value.inventoriedAt = '2026-01-04T00:00:00Z';
  assert.throws(() => createM4CleanupInventory(stale.value, stale.authorities), /m4_cleanup_inventory_catalog_stale/);
  const tampered = await input(); tampered.value.catalogSnapshotManifest.objects.pop();
  assert.throws(() => createM4CleanupInventory(tampered.value, tampered.authorities), /m4_cleanup_inventory_evidence_invalid/);
});

test('catalog trust anchor is external and cannot reuse claimant authority', async () => {
  const injected = await input(); injected.value.catalogSnapshotKeyDocument = injected.fixture.keys.catalogSnapshot;
  assert.throws(() => createM4CleanupInventory(injected.value, injected.authorities), /m4_cleanup_inventory_input_invalid/);
  const sameId = await input();
  assert.throws(() => createM4CleanupInventory(sameId.value, { catalogSnapshotKeyDocument: sameId.fixture.keys.cleanup }), /m4_cleanup_inventory_authority_invalid/);
  const sameMaterial = await input();
  assert.throws(() => createM4CleanupInventory(sameMaterial.value,
    { catalogSnapshotKeyDocument: keyDocument('different-catalog-id', 9) }), /m4_cleanup_inventory_authority_invalid/);
});
