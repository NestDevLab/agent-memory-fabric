import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { aadSha256For, validateAmfMemoryRecord } from '../src/amf-memory-record-validator.mjs';

const timestamp = '2026-07-11T12:00:00Z';

function baseRecord() {
  return {
    schema: 'amf-memory/v1',
    id: 'mem_11111111-1111-4111-8111-111111111111',
    revision: 1,
    claimType: 'decision',
    scope: { type: 'shared', id: 'shared:global' },
    visibility: 'shared',
    subjects: [{ identityId: 'agent:22222222-2222-4222-8222-222222222222', role: 'owner' }],
    claim: { encoding: 'plain', text: 'A source-backed decision.' },
    lifecycle: { status: 'active', validFrom: timestamp, validTo: null, supersedes: [], revokedAt: null, revocationReason: null },
    provenance: [{ sourceType: 'test-session', sourceId: 'session-stable-0001', eventId: 'event-stable-0001', contentSha256: crypto.createHash('sha256').update('source').digest('hex'), capturedAt: timestamp }],
    createdAt: timestamp,
    updatedAt: timestamp
  };
}

function restrictedSealedRecord() {
  const record = { ...baseRecord(), visibility: 'restricted' };
  record.claim = {
    encoding: 'sealed', alg: 'AES-256-GCM', kekId: 'kek:version-0001', keyRef: 'key:external-record-0001',
    iv: Buffer.alloc(12, 1).toString('base64'), ciphertext: Buffer.from('ciphertext').toString('base64'), tag: Buffer.alloc(16, 2).toString('base64'), aadSha256: ''
  };
  record.claim.aadSha256 = aadSha256For(record);
  return record;
}

test('Fabric accepts the PAM 0.6 shared-plain and restricted-sealed fixtures', () => {
  assert.deepEqual(validateAmfMemoryRecord(baseRecord()), { ok: true, errors: [] });
  assert.deepEqual(validateAmfMemoryRecord(restrictedSealedRecord()), { ok: true, errors: [] });
});

test('Fabric enforces PAM 0.6 restricted sealing and exact record fields', () => {
  const restrictedPlain = { ...baseRecord(), visibility: 'restricted' };
  assert.equal(validateAmfMemoryRecord(restrictedPlain).ok, false);
  const unknown = { ...baseRecord(), legacyScope: 'shared' };
  assert.match(validateAmfMemoryRecord(unknown).errors.join('\n'), /unknown field/);
  const wrongScope = { ...baseRecord(), scope: { type: 'domain', id: 'main-lab' } };
  assert.match(validateAmfMemoryRecord(wrongScope).errors.join('\n'), /scope.id must be canonical/);
});

test('Fabric enforces the PAM 0.6 sealed envelope, key refs, base64 sizes and canonical AAD', () => {
  const cases = [
    ['algorithm', { alg: 'AES-GCM' }, /alg/],
    ['KEK', { kekId: 'not-a-kek' }, /kekId/],
    ['key ref', { keyRef: 'not-a-key' }, /keyRef/],
    ['IV size', { iv: Buffer.alloc(11).toString('base64') }, /12 bytes/],
    ['ciphertext base64', { ciphertext: '=' }, /base64/],
    ['tag size', { tag: Buffer.alloc(15).toString('base64') }, /16 bytes/],
    ['AAD', { aadSha256: 'f'.repeat(64) }, /canonical AAD/]
  ];
  for (const [label, mutation, pattern] of cases) {
    const record = restrictedSealedRecord();
    record.claim = { ...record.claim, ...mutation };
    const validation = validateAmfMemoryRecord(record);
    assert.equal(validation.ok, false, `${label} was accepted`);
    assert.match(validation.errors.join('\n'), pattern);
  }
});
