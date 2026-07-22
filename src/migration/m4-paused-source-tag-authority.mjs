import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4CrossPhaseIdentityAuthority } from './m4-cross-phase-identity-registry.mjs';

export const M4_PAUSED_SOURCE_TAG_AUTHORITY_SCHEMA = 'amf.m4-paused-source-tag-authority/v1';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAC = /^hmac-sha256:[A-Za-z0-9_-]{43}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const RUNTIME = new Set(['codex', 'claude', 'hermes', 'openclaw']);
const SOURCE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function key(value, code = 'm4_paused_source_tag_authority_key_invalid') {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail(code);
  return Buffer.from(value);
}
function equalBytes(left, right) { return left.length === right.length && crypto.timingSafeEqual(left, right); }
function keyPair(value) {
  if (!exact(value, ['registrySecret', 'sourceTagSecret'])) fail('m4_paused_source_tag_authority_key_invalid');
  const registrySecret = key(value.registrySecret); const sourceTagSecret = key(value.sourceTagSecret);
  if (equalBytes(registrySecret, sourceTagSecret)) fail('m4_paused_source_tag_authority_key_invalid');
  return { registrySecret, sourceTagSecret };
}
function authorityKey(value) {
  return Buffer.from(crypto.hkdfSync('sha256', key(value), Buffer.from('amf.m4-paused-source-tag-authority/salt/v1'),
    Buffer.from('amf.m4-paused-source-tag-authority/hmac/v1'), 32));
}
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function mac(value, secret) {
  return `hmac-sha256:${crypto.createHmac('sha256', secret)
    .update(canonicalJson(['amf.m4-paused-source-tag-authority/mac/v1', value]), 'utf8').digest('base64url')}`;
}
function equal(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function projectionBinding(value, code) {
  if (!exact(value, ['schema', 'runtime', 'sourceId', 'digest'])
    || value.schema !== 'amf.m4-paused-projection-binding/v1' || !RUNTIME.has(value.runtime)
    || typeof value.sourceId !== 'string' || !SOURCE_ID.test(value.sourceId)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { schema: value.schema, runtime: value.runtime, sourceId: value.sourceId, digest: value.digest };
}
function tags(value, code) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64
    || value.some(item => typeof item !== 'string' || !SOURCE_TAG.test(item))) fail(code);
  const result = [...value];
  for (let index = 1; index < result.length; index += 1) if (result[index - 1] >= result[index]) fail(code);
  return result;
}
function binding(value, code) {
  if (!exact(value, ['completionDigest', 'catalogRevisionDigest'])
    || !DIGEST.test(value.completionDigest) || !DIGEST.test(value.catalogRevisionDigest)) fail(code);
  return { completionDigest: value.completionDigest, catalogRevisionDigest: value.catalogRevisionDigest };
}
function mapping(value, code) {
  if (!exact(value, ['runtime', 'sourceId', 'projectionBindingDigest', 'sourceTags'])
    || !RUNTIME.has(value.runtime) || typeof value.sourceId !== 'string' || !SOURCE_ID.test(value.sourceId)
    || typeof value.projectionBindingDigest !== 'string' || !DIGEST.test(value.projectionBindingDigest)) fail(code);
  return { runtime: value.runtime, sourceId: value.sourceId, projectionBindingDigest: value.projectionBindingDigest,
    sourceTags: tags(value.sourceTags, code) };
}
function body({ registryAuthorityDigest, backfillBinding, mappings } = {}, code) {
  if (typeof registryAuthorityDigest !== 'string' || !DIGEST.test(registryAuthorityDigest)) fail(code);
  if (!Array.isArray(mappings) || mappings.length < 1 || mappings.length > 10_000) fail(code);
  const safe = mappings.map(item => mapping(item, code));
  for (let index = 1; index < safe.length; index += 1) {
    const left = `${safe[index - 1].runtime}\0${safe[index - 1].sourceId}\0${safe[index - 1].projectionBindingDigest}`;
    const right = `${safe[index].runtime}\0${safe[index].sourceId}\0${safe[index].projectionBindingDigest}`;
    if (left >= right) fail(code);
  }
  return { schema: M4_PAUSED_SOURCE_TAG_AUTHORITY_SCHEMA, version: 1, registryAuthorityDigest,
    backfillBinding: binding(backfillBinding, code), mappings: safe };
}

export function createM4PausedSourceTagAuthority({ registryAuthority, backfillBinding, mappings } = {}, keys) {
  const { registrySecret, sourceTagSecret } = keyPair(keys);
  let registry;
  try { registry = verifyM4CrossPhaseIdentityAuthority(registryAuthority, registrySecret); }
  catch { fail('m4_paused_source_tag_authority_invalid'); }
  if (canonicalJson(binding(backfillBinding, 'm4_paused_source_tag_authority_invalid')) !== canonicalJson(registry.backfillBinding)) {
    fail('m4_paused_source_tag_authority_invalid');
  }
  const unsigned = body({ registryAuthorityDigest: digest(registryAuthority), backfillBinding, mappings }, 'm4_paused_source_tag_authority_invalid');
  return structuredClone({ ...unsigned, mac: mac(unsigned, authorityKey(sourceTagSecret)) });
}

export function verifyM4PausedSourceTagAuthority(value, { sourceTagSecret } = {}) {
  let snapshot; try { snapshot = structuredClone(value); } catch { fail('m4_paused_source_tag_authority_invalid'); }
  if (!exact(snapshot, ['schema', 'version', 'registryAuthorityDigest', 'backfillBinding', 'mappings', 'mac'])
    || snapshot.schema !== M4_PAUSED_SOURCE_TAG_AUTHORITY_SCHEMA || snapshot.version !== 1
    || typeof snapshot.mac !== 'string' || !MAC.test(snapshot.mac)) fail('m4_paused_source_tag_authority_invalid');
  const unsigned = body(snapshot, 'm4_paused_source_tag_authority_invalid');
  if (!equal(snapshot.mac, mac(unsigned, authorityKey(sourceTagSecret)))) fail('m4_paused_source_tag_authority_invalid');
  return structuredClone(unsigned);
}

function verifiedResolverInput(input) {
  if (!exact(input, ['authority', 'registryAuthority', 'registrySecret', 'sourceTagSecret'])) {
    fail('m4_paused_source_tag_authority_input_invalid');
  }
  const { registrySecret, sourceTagSecret } = keyPair({ registrySecret: input.registrySecret, sourceTagSecret: input.sourceTagSecret });
  const safe = verifyM4PausedSourceTagAuthority(input.authority, { sourceTagSecret });
  let registry;
  try { registry = verifyM4CrossPhaseIdentityAuthority(input.registryAuthority, registrySecret); }
  catch { fail('m4_paused_source_tag_authority_binding_mismatch'); }
  if (digest(input.registryAuthority) !== safe.registryAuthorityDigest
    || canonicalJson(registry.backfillBinding) !== canonicalJson(safe.backfillBinding)) {
    fail('m4_paused_source_tag_authority_binding_mismatch');
  }
  return safe;
}

export function createM4PausedSourceTagResolver(input = {}) {
  const safe = verifiedResolverInput(input);
  const mappings = new Map();
  for (const item of safe.mappings) {
    const mapKey = `${item.runtime}\0${item.sourceId}\0${item.projectionBindingDigest}`;
    mappings.set(mapKey, Object.freeze([...item.sourceTags]));
  }
  return Object.freeze({
    kind: 'm4-paused-source-tag-resolver-v1',
    resolve(inputBinding) {
      const source = projectionBinding(inputBinding, 'm4_paused_source_tag_authority_input_invalid');
      const found = mappings.get(`${source.runtime}\0${source.sourceId}\0${source.digest}`);
      if (!found) fail('m4_paused_source_tag_authority_mapping_missing');
      return structuredClone(found);
    },
  });
}

export function resolveM4PausedSourceTags({ authority, registryAuthority, binding: input } = {}, keys) {
  const resolver = createM4PausedSourceTagResolver({ authority, registryAuthority, ...keys });
  return resolver.resolve(input);
}
