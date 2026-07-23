import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  attestM4V2CatalogRevision,
  createM4V2CatalogRevisionAccumulator,
  verifyM4V2CatalogRevisionAttestation,
} from '../src/migration/m4-v2-catalog-revision-attestation.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';

const key = { schema: 'amf.migration-signing-key/v1', keyId: 'catalog-attestation-k1', key: Buffer.alloc(32, 7).toString('base64') };

function countedGetters(value) {
  const reads = Object.fromEntries(Object.keys(value).map(name => [name, 0])); const hostile = {};
  for (const [name, entry] of Object.entries(value)) Object.defineProperty(hostile, name, { enumerable: true, get() { reads[name] += 1; return entry; } });
  return { hostile, reads };
}
function signedV2WithCoveredThrough(attestation, coveredThrough) {
  const traversal = { ...attestation.traversal, coveredThrough };
  traversal.catalogRevisionDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson(['amf.m4-v2-catalog-revision-attestation/v2/revision', traversal.groupCount, traversal.observationCount, traversal.finalChain, traversal.coveredThrough]), 'utf8').digest('hex')}`;
  const unsigned = { schema: attestation.schema, traversal };
  const payloadDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest('hex')}`;
  return { ...unsigned, integrity: { algorithm: 'hmac-sha256', keyId: key.keyId, payloadDigest,
    signature: crypto.createHmac('sha256', Buffer.from(key.key, 'base64')).update(canonicalJson(['amf.m4-v2-catalog-revision-attestation/v2/integrity', payloadDigest, key.keyId]), 'utf8').digest('base64url') } };
}

test('signs bounded content-free empty traversal deterministically and rejects tamper or key substitution', async () => {
  const catalog = { async listM4V2LogicalGroups(input) { assert.deepEqual(input, { after: null, limit: 50 }); return { items: [], next: null }; } };
  const first = await attestM4V2CatalogRevision({ catalog, keyDocument: key, pageLimit: 50 });
  const second = await attestM4V2CatalogRevision({ catalog, keyDocument: key, pageLimit: 50 });
  assert.deepEqual(first, second); assert.equal(first.schema, 'amf.m4-v2-catalog-revision-attestation/v2'); assert.deepEqual(first.traversal.groupCount, 0); assert.equal(first.traversal.coveredThrough, null); assert.doesNotMatch(JSON.stringify(first), /sourceTag|visible|ciphertext|rootPath/i);
  assert.deepEqual(verifyM4V2CatalogRevisionAttestation(first, key), first);
  const tampered = structuredClone(first); tampered.traversal.groupCount = 1;
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(tampered, key), { code: 'm4_v2_catalog_attestation_invalid' });
  const coveredThroughTamper = structuredClone(first); coveredThroughTamper.traversal.coveredThrough = '2026-07-22T12:00:00Z';
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(coveredThroughTamper, key), { code: 'm4_v2_catalog_attestation_invalid' });
  const v1DomainSignature = structuredClone(first); v1DomainSignature.integrity.signature = crypto.createHmac('sha256', Buffer.from(key.key, 'base64')).update(canonicalJson(['amf.m4-v2-catalog-revision-attestation/v1/integrity', first.integrity.payloadDigest, key.keyId]), 'utf8').digest('base64url');
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(v1DomainSignature, key), { code: 'm4_v2_catalog_attestation_signature_mismatch' });
  for (const nonCanonical of ['2026-07-22T12:00:00+00:00', '2026-07-22T12:00:00.1200Z']) assert.throws(() => verifyM4V2CatalogRevisionAttestation(signedV2WithCoveredThrough({ ...first, traversal: { ...first.traversal, groupCount: 1, observationCount: 1, coveredThrough: '2026-07-22T12:00:00Z' } }, nonCanonical), key), { code: 'm4_v2_catalog_attestation_invalid' });
  assert.throws(() => verifyM4V2CatalogRevisionAttestation(first, { ...key, keyId: 'other-key' }), { code: 'm4_v2_catalog_attestation_key_mismatch' });
});

test('untimed non-conversation metadata remains chain-bound without inventing a time bound', () => {
  const accumulator = createM4V2CatalogRevisionAccumulator();
  accumulator.append({
    logical: { logicalMessageId: `lmsg_${'a'.repeat(64)}` },
    observations: [{
      projection: {
        authoritativeDeletion: false,
        role: 'unknown',
        direction: 'unknown',
        conversationKind: 'session',
        contentType: 'none',
        hasContent: false,
        occurredAt: null,
        editedAt: null,
      },
    }],
  });
  const traversal = accumulator.traversal(50);
  assert.equal(traversal.groupCount, 1);
  assert.equal(traversal.observationCount, 1);
  assert.equal(traversal.coveredThrough, null);
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

test('continues to verify the prior V1 attestation shape without emitting it', () => {
  const finalChain = `sha256:${'a'.repeat(64)}`;
  const traversal = { pageLimit: 50, groupCount: 0, observationCount: 0, finalChain,
    catalogRevisionDigest: `sha256:${crypto.createHash('sha256').update(canonicalJson(['amf.m4-v2-catalog-revision-attestation/v1/revision', 0, 0, finalChain]), 'utf8').digest('hex')}` };
  const unsigned = { schema: 'amf.m4-v2-catalog-revision-attestation/v1', traversal };
  const payloadDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest('hex')}`;
  const signature = crypto.createHmac('sha256', Buffer.from(key.key, 'base64')).update(canonicalJson(['amf.m4-v2-catalog-revision-attestation/v1/integrity', payloadDigest, key.keyId]), 'utf8').digest('base64url');
  assert.deepEqual(verifyM4V2CatalogRevisionAttestation({ ...unsigned, integrity: { algorithm: 'hmac-sha256', keyId: key.keyId, payloadDigest, signature } }, key), { ...unsigned, integrity: { algorithm: 'hmac-sha256', keyId: key.keyId, payloadDigest, signature } });
});
