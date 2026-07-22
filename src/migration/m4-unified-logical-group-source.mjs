import crypto from 'node:crypto';

import { selectLogicalMessage } from '../ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';

export const M4_UNIFIED_GROUP_MAX_GROUPS = 100;
export const M4_UNIFIED_GROUP_MAX_MEMBERS = 1_000;
export const M4_UNIFIED_GROUP_MAX_INDEX_ENTRIES = 1_000_000;
export const M4_UNIFIED_GROUP_MAX_PROJECTION_VARIANTS = 128;

const AUTHORITY_SCHEMA = 'amf.m4-group-replay-authority/v1';
const REQUEST_SCHEMA = 'amf.m4-preserved-group-replay-request/v1';
const SOURCE_SCHEMA = 'amf.m4-preserved-group-replay-source/v1';
const DESCRIPTOR_SCHEMA = 'amf.m4-logical-group-descriptor/v1';
const INDEX_SCHEMA = 'amf.m4-unified-logical-index/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const LOGICAL = /^lmsg_[a-f0-9]{64}$/;
const EVENT = /^evt_[a-f0-9]{64}$/;
const ORIGINS = ['v2-archive', 'preserved-outbox', 'preserved-deadletter'];

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function sortCanonical(values) { return [...values].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))); }

function authority(value) {
  if (!exact(value, ['schema', 'authorityDigest']) || value.schema !== AUTHORITY_SCHEMA || !DIGEST.test(value.authorityDigest)) fail('m4_unified_authority_invalid');
  return structuredClone(value);
}

function entry(value, origin) {
  if (!exact(value, ['origin', 'position', 'legacyEventId', 'recordDigest', 'projectionDigests'])
    || value.origin !== origin || !Number.isSafeInteger(value.position) || value.position < 0
    || !EVENT.test(value.legacyEventId) || !DIGEST.test(value.recordDigest)
    || !Array.isArray(value.projectionDigests) || value.projectionDigests.length < 1
    || value.projectionDigests.length > M4_UNIFIED_GROUP_MAX_PROJECTION_VARIANTS
    || value.projectionDigests.some(item => !exact(item, ['logicalMessageId', 'projectionDigest'])
      || !LOGICAL.test(item.logicalMessageId) || !DIGEST.test(item.projectionDigest))
    || canonicalJson(value.projectionDigests) !== canonicalJson([...value.projectionDigests]
      .sort((left, right) => left.logicalMessageId.localeCompare(right.logicalMessageId)))
    || new Set(value.projectionDigests.map(item => item.logicalMessageId)).size !== value.projectionDigests.length) fail('m4_unified_index_invalid');
  return structuredClone(value);
}

function indexAttestation(value, origin, authorityDigest) {
  const entries = value?.entries;
  if (!exact(value, ['schema', 'authorityDigest', 'origin', 'complete', 'entries'])
    || value.schema !== INDEX_SCHEMA || value.authorityDigest !== authorityDigest || value.origin !== origin
    || value.complete !== true || !Array.isArray(entries) || entries.length > M4_UNIFIED_GROUP_MAX_INDEX_ENTRIES) {
    fail('m4_unified_index_invalid');
  }
  return entries.map(item => entry(item, origin));
}

function descriptor(authorityDigest, logicalMessageId, members) {
  const safeMembers = sortCanonical(members.map(member => ({ legacyEventId: member.legacyEventId,
    projectionDigest: member.projectionDigest, locators: sortCanonical(member.locators) })));
  const binding = { schema: 'amf.m4-logical-group-binding/v1', authorityDigest, logicalMessageId, members: safeMembers };
  return { schema: DESCRIPTOR_SCHEMA, authorityDigest, groupDigest: digest(binding), logicalMessageId, members: safeMembers };
}

function request(value, authorityDigest) {
  if (!exact(value, ['schema', 'authorityDigest', 'after', 'maxGroups', 'maxObservations', 'maxOutputEvents'])
    || value.schema !== REQUEST_SCHEMA || value.authorityDigest !== authorityDigest
    || (value.after !== null && !DIGEST.test(value.after))
    || !Number.isSafeInteger(value.maxGroups) || value.maxGroups < 1 || value.maxGroups > M4_UNIFIED_GROUP_MAX_GROUPS
    || !Number.isSafeInteger(value.maxObservations) || value.maxObservations < 1 || value.maxObservations > M4_UNIFIED_GROUP_MAX_MEMBERS
    || !Number.isSafeInteger(value.maxOutputEvents) || value.maxOutputEvents < 1 || value.maxOutputEvents > M4_UNIFIED_GROUP_MAX_MEMBERS) fail('m4_unified_request_invalid');
  return structuredClone(value);
}

function minimalObservation(value, member, migrationSequence) {
  const keys = ['eventId', 'sessionId', 'sourceTag', 'migrationSequence', 'projection', 'visibleText'];
  if (!exact(value, keys) || value.eventId !== member.legacyEventId || !plain(value.projection)
    || value.migrationSequence !== migrationSequence || digest(value.projection) !== member.projectionDigest) fail('m4_unified_materialization_mismatch');
  return structuredClone(value);
}

export async function prepareM4UnifiedLogicalGroupSource(input = {}) {
  if (!exact(input, ['authority', 'indexes', 'resolveCanonicalLogicalId', 'materializers'])) fail('m4_unified_dependency_invalid');
  const rawAuthority = input.authority; const rawIndexes = input.indexes;
  const resolveCanonicalLogicalId = input.resolveCanonicalLogicalId; const rawMaterializers = input.materializers;
  if (typeof resolveCanonicalLogicalId !== 'function' || !plain(rawIndexes) || !plain(rawMaterializers)
    || Object.keys(rawIndexes).length !== ORIGINS.length || Object.keys(rawMaterializers).length !== ORIGINS.length) fail('m4_unified_dependency_invalid');
  const safeAuthority = authority(rawAuthority); const materializers = {};
  const indexes = {};
  for (const origin of ORIGINS) {
    const rawIndex = rawIndexes[origin]; const materializer = rawMaterializers[origin];
    if (!plain(rawIndex) || typeof materializer !== 'function') fail('m4_unified_dependency_invalid');
    indexes[origin] = indexAttestation(rawIndex, origin, safeAuthority.authorityDigest);
    materializers[origin] = materializer;
  }
  Object.freeze(materializers); Object.freeze(indexes);
  const byEvent = new Map();
  const locatorOwners = new Map();
  let entryCount = 0;
  for (const origin of ORIGINS) {
    for (const indexed of indexes[origin]) {
      entryCount += 1;
      if (entryCount > M4_UNIFIED_GROUP_MAX_INDEX_ENTRIES) fail('m4_unified_bound_invalid');
      let logicalMessageId;
      try { logicalMessageId = await resolveCanonicalLogicalId({ authorityDigest: safeAuthority.authorityDigest,
        logicalMessageIds: indexed.projectionDigests.map(item => item.logicalMessageId) }); }
      catch { fail('m4_unified_canonical_resolution_failed'); }
      if (!LOGICAL.test(logicalMessageId)) fail('m4_unified_canonical_resolution_failed');
      const selectedProjection = indexed.projectionDigests.find(item => item.logicalMessageId === logicalMessageId);
      if (!selectedProjection) fail('m4_unified_canonical_resolution_failed');
      const previous = byEvent.get(indexed.legacyEventId);
      const locator = { origin: indexed.origin, position: indexed.position, recordDigest: indexed.recordDigest };
      const locatorKey = `${locator.origin}\0${locator.position}`;
      const owner = locatorOwners.get(locatorKey);
      if (owner !== undefined && owner !== indexed.legacyEventId) fail('m4_unified_index_mismatch');
      locatorOwners.set(locatorKey, indexed.legacyEventId);
      if (previous) {
        if (previous.projectionDigest !== selectedProjection.projectionDigest || previous.logicalMessageId !== logicalMessageId) fail('m4_unified_index_mismatch');
        if (previous.locators.some(item => item.origin === locator.origin)) fail('m4_unified_index_mismatch');
        previous.locators.push(locator);
      } else byEvent.set(indexed.legacyEventId, { legacyEventId: indexed.legacyEventId,
        projectionDigest: selectedProjection.projectionDigest, logicalMessageId, locators: [locator] });
    }
  }
  const grouped = new Map();
  for (const item of byEvent.values()) {
    item.locators = sortCanonical(item.locators);
    const members = grouped.get(item.logicalMessageId) ?? [];
    members.push(item); grouped.set(item.logicalMessageId, members);
  }
  const prepared = [...grouped.entries()].map(([logicalMessageId, members]) => ({
    descriptor: descriptor(safeAuthority.authorityDigest, logicalMessageId, members),
    members: sortCanonical(members),
  })).sort((left, right) => left.descriptor.logicalMessageId.localeCompare(right.descriptor.logicalMessageId)
    || left.descriptor.groupDigest.localeCompare(right.descriptor.groupDigest));
  if (prepared.length > M4_UNIFIED_GROUP_MAX_INDEX_ENTRIES || prepared.some(group => group.members.length > M4_UNIFIED_GROUP_MAX_MEMBERS)) fail('m4_unified_bound_invalid');

  return Object.freeze({
    async open(rawRequest) {
      const accepted = request(rawRequest, safeAuthority.authorityDigest);
      const start = accepted.after === null ? 0 : prepared.findIndex(group => group.descriptor.groupDigest === accepted.after) + 1;
      if (accepted.after !== null && start === 0) fail('m4_unified_resume_invalid');
      const selected = []; let members = 0; let complete = true;
      for (const group of prepared.slice(start)) {
        if (selected.length >= accepted.maxGroups || members + group.members.length > accepted.maxObservations) { complete = false; break; }
        selected.push(group); members += group.members.length;
      }
      return {
        schema: SOURCE_SCHEMA, authorityDigest: safeAuthority.authorityDigest,
        groups: (async function* () {
          for (const group of selected) {
            const observations = [];
            for (const [memberIndex, member] of group.members.entries()) {
              const migrationSequence = memberIndex + 1; let acceptedObservation = null;
              for (const locator of member.locators) {
                let observation;
                try { observation = await materializers[locator.origin]({ authorityDigest: safeAuthority.authorityDigest,
                  canonicalLogicalMessageId: group.descriptor.logicalMessageId, migrationSequence,
                  legacyEventId: member.legacyEventId, projectionDigest: member.projectionDigest, ...locator }); }
                catch { fail('m4_unified_materialization_failed'); }
                let safe;
                try { safe = minimalObservation(observation, member, migrationSequence); }
                catch { fail('m4_unified_materialization_mismatch'); }
                if (acceptedObservation !== null && canonicalJson(safe) !== canonicalJson(acceptedObservation)) fail('m4_unified_materialization_mismatch');
                acceptedObservation = safe;
              }
              observations.push(acceptedObservation);
            }
            let logical;
            try { logical = selectLogicalMessage(observations.map(item => ({ eventId: item.eventId, projection: item.projection }))); }
            catch { fail('m4_unified_logical_recompute_failed'); }
            if (logical.logicalMessageId !== group.descriptor.logicalMessageId) fail('m4_unified_logical_recompute_failed');
            yield { descriptor: structuredClone(group.descriptor), logical: { ...logical, eventIds: observations.map(item => item.eventId).sort() }, observations };
          }
        })(),
        completion: async () => ({ schema: SOURCE_SCHEMA, authorityDigest: safeAuthority.authorityDigest, complete }),
      };
    },
  });
}
