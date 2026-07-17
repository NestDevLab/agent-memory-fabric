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
    confidence: { score: 0.9, basis: 'reviewed', assessedAt: timestamp },
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

test('Fabric requires the exact confidence object and rejects unsafe scores', () => {
  const missing = baseRecord();
  delete missing.confidence;
  assert.match(validateAmfMemoryRecord(missing).errors.join('\n'), /missing field: confidence/);

  const cases = [
    ['NaN', { score: Number.NaN }, /finite and between/],
    ['negative', { score: -0.01 }, /finite and between/],
    ['greater than one', { score: 1.01 }, /finite and between/],
    ['basis', { basis: 'guessed' }, /basis is invalid/],
    ['timestamp', { assessedAt: '2026-07-11T12:00:00+00:00' }, /RFC 3339 UTC/],
    ['unknown field', { legacy: true }, /unknown field: legacy/]
  ];
  for (const [label, mutation, pattern] of cases) {
    const record = baseRecord();
    record.confidence = { ...record.confidence, ...mutation };
    const validation = validateAmfMemoryRecord(record);
    assert.equal(validation.ok, false, `${label} confidence was accepted`);
    assert.match(validation.errors.join('\n'), pattern);
  }
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

test('sealed canonical AAD authenticates confidence score, basis and assessment time', () => {
  const cases = [
    ['score', { score: 0.8 }],
    ['basis', { basis: 'asserted' }],
    ['assessedAt', { assessedAt: '2026-07-11T11:00:00Z' }]
  ];
  for (const [label, mutation] of cases) {
    const record = restrictedSealedRecord();
    record.confidence = { ...record.confidence, ...mutation };
    const validation = validateAmfMemoryRecord(record);
    assert.equal(validation.ok, false, `${label} tamper was accepted`);
    assert.match(validation.errors.join('\n'), /canonical AAD/);
  }
});

test('plain sensitive claims are rejected by default and accepted only with the explicit opt-out', () => {
  const relational = {
    ...baseRecord(),
    claimType: 'relationship',
    scope: { type: 'relationship', id: 'relationship:vitae:joseph' },
    visibility: 'restricted',
    subjects: [
      { identityId: 'agent:vitae', role: 'owner' },
      { identityId: 'person:joseph', role: 'participant' }
    ]
  };
  const strict = validateAmfMemoryRecord(relational);
  assert.equal(strict.ok, false);
  assert.ok(strict.errors.includes('record requires a sealed claim'));
  assert.deepEqual(validateAmfMemoryRecord(relational, { allowPlainSensitiveClaims: true }), { ok: true, errors: [] });

  const personScoped = { ...baseRecord(), scope: { type: 'person', id: 'person:joseph' }, visibility: 'private' };
  assert.equal(validateAmfMemoryRecord(personScoped).ok, false);
  assert.equal(validateAmfMemoryRecord(personScoped, { allowPlainSensitiveClaims: true }).ok, true);

  assert.deepEqual(validateAmfMemoryRecord(restrictedSealedRecord(), { allowPlainSensitiveClaims: true }), { ok: true, errors: [] });
  const emptyPlain = { ...personScoped, claim: { encoding: 'plain', text: '   ' } };
  assert.equal(validateAmfMemoryRecord(emptyPlain, { allowPlainSensitiveClaims: true }).ok, false);
});
