import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { deflateRawSync, inflateRawSync } from 'node:zlib';

import {
  ContentProtectionError,
  contentProtectionLimits,
  protectContent,
  resolveContentProtection,
  unprotectContent
} from '../src/content-protection-v1.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { measureSqliteEvidence } from './measure-content-protection-v1.mjs';

const SOURCE = 'src_storageevidence1';
const CONTENT_CLASSES = ['conversation', 'proposal', 'canonical-memory', 'document'];
const CURRENT_KEY_REF = 'key:synthetic-current-v1';
const RETIRED_KEY_REF = 'key:synthetic-retired-v1';
const CURRENT_KEY = Buffer.alloc(32, 11);
const RETIRED_KEY = Buffer.alloc(32, 12);
const keys = new Map([
  [CURRENT_KEY_REF, CURRENT_KEY],
  [RETIRED_KEY_REF, RETIRED_KEY]
]);
const resolveKey = reference => keys.get(reference) ?? null;

function defaults() {
  return Object.fromEntries(CONTENT_CLASSES.map(contentClass => [contentClass, 'plaintext']));
}

function plaintextPolicy(rules = []) {
  return {
    schema: 'amf.content-protection-policy/v1',
    revision: 'synthetic-plaintext-v1',
    defaults: defaults(),
    rules
  };
}

function encryptedPolicy({
  compression = false,
  readKeyRefs = [CURRENT_KEY_REF, RETIRED_KEY_REF],
  writeKeyRef = CURRENT_KEY_REF,
  readPlaintext
} = {}) {
  return {
    schema: 'amf.content-protection-policy/v1',
    revision: 'synthetic-encrypted-v1',
    defaults: defaults(),
    rules: CONTENT_CLASSES.map(contentClass => ({
      sourceInstanceId: SOURCE,
      contentClass,
      enabled: true,
      codec: 'aes-256-gcm',
      writeKeyRef,
      readKeyRefs,
      ...(compression ? { compression: 'deflate-raw' } : {}),
      ...(readPlaintext === undefined ? {} : { readPlaintext })
    }))
  };
}

function expectCode(code, action) {
  assert.throws(action, error => error instanceof ContentProtectionError && error.code === code);
}

function aad(envelope) {
  return Buffer.from(canonicalJson([
    'amf.content-protection/v1/aad',
    envelope.v,
    envelope.codec,
    envelope.sourceInstanceId,
    envelope.contentClass,
    envelope.keyRef,
    envelope.compression,
    envelope.metadata
  ]), 'utf8');
}

function decryptPrepared(envelope, key) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(envelope.iv, 'base64')
  );
  decipher.setAAD(aad(envelope));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final()
  ]);
}

function sealPrepared({ contentClass, prepared, metadata = { record: 'bounded-expansion' } }) {
  const iv = Buffer.alloc(12, 9);
  const envelope = {
    v: 1,
    codec: 'aes-256-gcm',
    sourceInstanceId: SOURCE,
    contentClass,
    keyRef: CURRENT_KEY_REF,
    compression: 'deflate-raw',
    metadata,
    iv: iv.toString('base64'),
    ciphertext: '',
    tag: ''
  };
  const cipher = crypto.createCipheriv('aes-256-gcm', CURRENT_KEY, iv);
  cipher.setAAD(aad(envelope));
  envelope.ciphertext = Buffer.concat([cipher.update(prepared), cipher.final()]).toString('base64');
  envelope.tag = cipher.getAuthTag().toString('base64');
  return envelope;
}

test('all four policy classes rotate write keys and retain allowed old reads', () => {
  const oldPolicy = encryptedPolicy({
    writeKeyRef: RETIRED_KEY_REF,
    readKeyRefs: [RETIRED_KEY_REF, CURRENT_KEY_REF]
  });
  const currentPolicy = encryptedPolicy();

  for (const contentClass of CONTENT_CLASSES) {
    const oldEnvelope = protectContent({
      policy: oldPolicy,
      sourceInstanceId: SOURCE,
      contentClass,
      plaintext: Buffer.from(`synthetic-old-${contentClass}`),
      metadata: { record: contentClass },
      resolveKey
    });
    const currentEnvelope = protectContent({
      policy: currentPolicy,
      sourceInstanceId: SOURCE,
      contentClass,
      plaintext: Buffer.from(`synthetic-current-${contentClass}`),
      metadata: { record: contentClass },
      resolveKey
    });
    assert.equal(oldEnvelope.keyRef, RETIRED_KEY_REF);
    assert.equal(currentEnvelope.keyRef, CURRENT_KEY_REF);
    assert.equal(
      unprotectContent({ policy: currentPolicy, envelope: oldEnvelope, resolveKey }).toString(),
      `synthetic-old-${contentClass}`
    );
    assert.equal(
      unprotectContent({ policy: currentPolicy, envelope: currentEnvelope, resolveKey }).toString(),
      `synthetic-current-${contentClass}`
    );
    expectCode('content_protection_envelope_invalid', () => unprotectContent({
      policy: encryptedPolicy({ readKeyRefs: [CURRENT_KEY_REF] }),
      envelope: oldEnvelope,
      resolveKey
    }));
  }
});

test('plaintext rules need no key and remain readable after enabling AES', () => {
  const policy = plaintextPolicy([{
    sourceInstanceId: SOURCE,
    contentClass: 'conversation',
    enabled: true,
    codec: 'plaintext'
  }]);
  const throwingResolver = () => { throw new Error('plaintext_must_not_resolve_keys'); };
  const suppliedMetadata = { nested: { record: 'plain' } };
  const envelope = protectContent({
    policy,
    sourceInstanceId: SOURCE,
    contentClass: 'conversation',
    plaintext: Buffer.from('synthetic plaintext'),
    metadata: suppliedMetadata,
    resolveKey: throwingResolver
  });
  suppliedMetadata.nested.record = 'mutated-after-write';
  assert.equal(envelope.metadata.nested.record, 'plain');
  assert.equal(
    unprotectContent({ policy: encryptedPolicy(), envelope, resolveKey: throwingResolver }).toString(),
    'synthetic plaintext'
  );
  expectCode('content_protection_envelope_invalid', () => unprotectContent({
    policy: encryptedPolicy({ readPlaintext: false }),
    envelope,
    resolveKey: throwingResolver
  }));
  assert.equal(resolveContentProtection(policy, SOURCE, 'conversation').codec, 'plaintext');
  expectCode('content_protection_envelope_invalid', () => unprotectContent({
    policy,
    envelope: { ...envelope, compression: 'deflate-raw' },
    resolveKey: throwingResolver
  }));
});

test('runtime policy validation matches exact contract semantics', () => {
  const base = encryptedPolicy();
  expectCode('content_protection_policy_invalid', () => resolveContentProtection(
    { ...base, extra: true }, SOURCE, 'conversation'
  ));
  expectCode('content_protection_policy_invalid', () => resolveContentProtection(
    { ...base, revision: 'invalid revision' }, SOURCE, 'conversation'
  ));
  expectCode('content_protection_policy_invalid', () => resolveContentProtection(
    { ...base, rules: [base.rules[0], base.rules[0]] }, SOURCE, 'conversation'
  ));
  for (const field of ['writeKeyRef', 'readKeyRefs', 'compression', 'readPlaintext']) {
    expectCode('content_protection_policy_invalid', () => resolveContentProtection(plaintextPolicy([{
      sourceInstanceId: SOURCE,
      contentClass: 'conversation',
      enabled: false,
      codec: 'aes-256-gcm',
      [field]: field === 'readKeyRefs' ? [] : field === 'readPlaintext' ? false : ''
    }]), SOURCE, 'conversation'));
  }
});

test('metadata and key failures are bounded and normalized', () => {
  const policy = encryptedPolicy();
  const base = {
    policy,
    sourceInstanceId: SOURCE,
    contentClass: 'document',
    plaintext: Buffer.from('synthetic'),
    resolveKey
  };
  const cyclic = {};
  cyclic.self = cyclic;
  const sparse = [];
  sparse.length = 1;
  let aliased = { leaf: 'synthetic' };
  for (let depth = 0; depth < 15; depth += 1) aliased = { left: aliased, right: aliased };
  for (const metadata of [
    cyclic,
    { value: Infinity },
    { value: undefined },
    { value: new Date(0) },
    { value: sparse },
    { value: aliased }
  ]) {
    expectCode('content_protection_metadata_invalid', () => protectContent({ ...base, metadata }));
  }
  expectCode('content_protection_key_unavailable', () => protectContent({
    ...base,
    metadata: { record: 'key' },
    resolveKey: () => null
  }));
});

test('AES envelopes reject unknown fields, malformed bytes, wrong keys, and AAD tampering', () => {
  const policy = encryptedPolicy();
  const envelope = protectContent({
    policy,
    sourceInstanceId: SOURCE,
    contentClass: 'document',
    plaintext: Buffer.from('synthetic envelope'),
    metadata: { record: 'document' },
    resolveKey
  });
  const invalid = [
    { ...envelope, unknown: true },
    { ...envelope, iv: 'AAAA=' },
    { ...envelope, iv: Buffer.alloc(11).toString('base64') },
    { ...envelope, tag: Buffer.alloc(15).toString('base64') },
    { ...envelope, ciphertext: 'AAAA=' },
    { ...envelope, contentClass: 'proposal' },
    { ...envelope, metadata: { record: 'tampered' } }
  ];
  for (const candidate of invalid) {
    expectCode('content_protection_envelope_invalid', () => unprotectContent({
      policy,
      envelope: candidate,
      resolveKey
    }));
  }
  expectCode('content_protection_envelope_invalid', () => unprotectContent({
    policy,
    envelope,
    resolveKey: () => Buffer.alloc(32, 99)
  }));
});

test('class-bound measurement justifies the policy and compression precedes AES-GCM', () => {
  const evidence = measureSqliteEvidence().compressionEvidence;
  assert.equal(evidence['canonical-memory'].justified, true);
  const source = Buffer.from('synthetic compressible content '.repeat(200));
  const policy = encryptedPolicy({ compression: true });
  const envelope = protectContent({
    policy,
    sourceInstanceId: SOURCE,
    contentClass: 'canonical-memory',
    plaintext: source,
    metadata: { record: 'compressed' },
    resolveKey
  });
  const prepared = decryptPrepared(envelope, CURRENT_KEY);
  assert.ok(prepared.length < source.length);
  assert.equal(Buffer.from(envelope.ciphertext, 'base64').length, prepared.length);
  assert.equal(inflateRawSync(prepared).equals(source), true);
  assert.equal(unprotectContent({ policy, envelope, resolveKey }).equals(source), true);
});

test('AES reads survive compression policy changes in both directions', () => {
  const source = Buffer.from('synthetic compression migration '.repeat(80));
  const uncompressedPolicy = encryptedPolicy();
  const compressedPolicy = encryptedPolicy({ compression: true });
  const uncompressed = protectContent({
    policy: uncompressedPolicy,
    sourceInstanceId: SOURCE,
    contentClass: 'document',
    plaintext: source,
    metadata: { revision: 'before-compression' },
    resolveKey
  });
  const compressed = protectContent({
    policy: compressedPolicy,
    sourceInstanceId: SOURCE,
    contentClass: 'document',
    plaintext: source,
    metadata: { revision: 'after-compression' },
    resolveKey
  });
  assert.equal(unprotectContent({
    policy: compressedPolicy,
    envelope: uncompressed,
    resolveKey
  }).equals(source), true);
  assert.equal(unprotectContent({
    policy: uncompressedPolicy,
    envelope: compressed,
    resolveKey
  }).equals(source), true);
});

test('authenticated decompression rejects output beyond the content bound', () => {
  const oversized = Buffer.alloc(contentProtectionLimits.maxContentBytes + 1, 65);
  const envelope = sealPrepared({
    contentClass: 'document',
    prepared: deflateRawSync(oversized, { level: 9 })
  });
  expectCode('content_protection_envelope_invalid', () => unprotectContent({
    policy: encryptedPolicy({ compression: true }),
    envelope,
    resolveKey
  }));
});
