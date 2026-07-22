import assert from 'node:assert/strict';
import test from 'node:test';

import { attestM4V2CatalogRevision, verifyM4V2CatalogRevisionAttestation } from '../src/migration/m4-v2-catalog-revision-attestation.mjs';

const key = { schema: 'amf.migration-signing-key/v1', keyId: 'catalog-attestation-k1', key: Buffer.alloc(32, 7).toString('base64') };

function countedGetters(value) {
  const reads = Object.fromEntries(Object.keys(value).map(name => [name, 0])); const hostile = {};
  for (const [name, entry] of Object.entries(value)) Object.defineProperty(hostile, name, { enumerable: true, get() { reads[name] += 1; return entry; } });
  return { hostile, reads };
}

test('signs bounded content-free empty traversal deterministically and rejects tamper or key substitution', async () => {
  const catalog = { async listM4V2LogicalGroups(input) { assert.deepEqual(input, { after: null, limit: 50 }); return { items: [], next: null }; } };
  const first = await attestM4V2CatalogRevision({ catalog, keyDocument: key, pageLimit: 50 });
  const second = await attestM4V2CatalogRevision({ catalog, keyDocument: key, pageLimit: 50 });
  assert.deepEqual(first, second); assert.deepEqual(first.traversal.groupCount, 0); assert.doesNotMatch(JSON.stringify(first), /sourceTag|visible|ciphertext|rootPath/i);
  assert.deepEqual(verifyM4V2CatalogRevisionAttestation(first, key), first);
  const tampered = structuredClone(first); tampered.traversal.groupCount = 1;
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(tampered, key), { code: 'm4_v2_catalog_attestation_invalid' });
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(first, { ...key, keyId: 'other-key' }), { code: 'm4_v2_catalog_attestation_key_mismatch' });
});

test('fails closed on invalid catalog pagination before signing', async () => {
  await assert.rejects(() => attestM4V2CatalogRevision({ catalog: { async listM4V2LogicalGroups() { return { items: [], next: 'bad' }; } }, keyDocument: key, pageLimit: 50 }), { code: 'm4_v2_catalog_attestation_catalog_invalid' });
});

test('snapshots hostile signed documents and signing keys once before validation', async () => {
  const catalog = { async listM4V2LogicalGroups() { return { items: [], next: null }; } };
  const hostileKey = countedGetters(key);
  const attestation = await attestM4V2CatalogRevision({ catalog, keyDocument: hostileKey.hostile, pageLimit: 50 });
  assert.deepEqual(hostileKey.reads, { schema: 1, keyId: 1, key: 1 });
  const hostileDocument = countedGetters(attestation);
  assert.deepEqual(verifyM4V2CatalogRevisionAttestation(hostileDocument.hostile, key), attestation);
  assert.equal(Object.values(hostileDocument.reads).every(reads => reads === 1), true);
});
