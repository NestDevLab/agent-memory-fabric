import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { RAW_EVENT_HTTP_MAX_BODY_BYTES, normalizeIngestKeyRing } from '../ingest/raw-event-contract.mjs';
import { buildM4V2LogicalGroup } from './m4-v2-catalog-groups.mjs';
import { isPotentialM4ConversationProjection } from './m4-v2-conversation-eligibility.mjs';
import { readM4V2CatalogObservation, readM4V2Observation } from './m4-v2-observation-reader.mjs';
import { projectM4V2LogicalGroup } from './m4-v2-conversation-projector.mjs';

const CHECKPOINT_ID = /^m4v2-([a-f0-9]{64})$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function objectLike(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }
function checkpoint(value, code) {
  if (!exact(value, ['id', 'digest']) || typeof value.id !== 'string' || !ID.test(value.id) || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { id: value.id, digest: value.digest };
}
function predecessor(hex) {
  const value = BigInt(`0x${hex}`);
  return value === 0n ? null : `lmsg_${(value - 1n).toString(16).padStart(64, '0')}`;
}
function validateFactory(value) {
  if (!plain(value) || Object.keys(value).some(key => !['catalog','rawStore','ingestKeys','verifyCatalogBinding','auditDecrypt','integrityFor','identityCollector','startCheckpoint','pageLimit','maxCiphertextBytes'].includes(key))
    || !objectLike(value.catalog) || typeof value.catalog.listM4V2LogicalGroups !== 'function'
    || !objectLike(value.rawStore) || typeof value.rawStore.getClientCiphertext !== 'function'
    || typeof value.verifyCatalogBinding !== 'function' || typeof value.auditDecrypt !== 'function'
    || typeof value.integrityFor !== 'function') fail('m4_v2_source_dependency_invalid');
  if (!(value.identityCollector === undefined || value.identityCollector === null
    || (plain(value.identityCollector) && Object.keys(value.identityCollector).length === 1
      && typeof value.identityCollector.accept === 'function'))) fail('m4_v2_source_dependency_invalid');
  const startCheckpoint = checkpoint(value.startCheckpoint, 'm4_v2_source_dependency_invalid');
  if (CHECKPOINT_ID.test(startCheckpoint.id)) fail('m4_v2_source_dependency_invalid');
  const pageLimit = value.pageLimit ?? 50;
  const maxCiphertextBytes = value.maxCiphertextBytes ?? RAW_EVENT_HTTP_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(pageLimit) || pageLimit < 1 || pageLimit > 100
    || !Number.isSafeInteger(maxCiphertextBytes) || maxCiphertextBytes < 1024 || maxCiphertextBytes > RAW_EVENT_HTTP_MAX_BODY_BYTES) {
    fail('m4_v2_source_dependency_invalid');
  }
  let ingestKeys;
  try {
    normalizeIngestKeyRing(value.ingestKeys);
    ingestKeys = structuredClone(value.ingestKeys);
  } catch { fail('m4_v2_source_dependency_invalid'); }
  return { ...value, ingestKeys, startCheckpoint, pageLimit, maxCiphertextBytes };
}
function validateOpen(value, startCheckpoint) {
  if (!exact(value, ['runId', 'phase', 'after', 'afterSequence', 'maxEvents'])
    || typeof value.runId !== 'string' || !ID.test(value.runId) || value.phase !== 'v2-archive'
    || !Number.isSafeInteger(value.afterSequence) || value.afterSequence < 0
    || !Number.isSafeInteger(value.maxEvents) || value.maxEvents < 1 || value.maxEvents > 1000) fail('m4_v2_source_request_invalid');
  const after = checkpoint(value.after, 'm4_v2_source_request_invalid');
  if (value.afterSequence === 0 && canonicalJson(after) !== canonicalJson(startCheckpoint)) fail('m4_v2_source_checkpoint_drift');
  if (value.afterSequence > 0 && !CHECKPOINT_ID.test(after.id)) fail('m4_v2_source_checkpoint_drift');
  return { ...value, after };
}
function groupDigest(group, events) {
  return digest({ schema: 'amf.m4-v2-archive-source/group/v1', logicalMessageId: group.logical.logicalMessageId,
    logical: group.logical, events: events.map(event => ({ eventId: event.eventId, logicalDigest: event.logicalDigest, payloadDigest: event.integrity.payloadDigest, state: event.state, revision: event.revision })) });
}
function rowFor(group, events, position, sequence) {
  const event = events[position];
  const binding = groupDigest(group, events);
  return {
    sequence,
    checkpoint: { id: `m4v2-${group.logical.logicalMessageId.slice(5)}`, digest: digest({ schema: 'amf.m4-v2-archive-source/checkpoint/v1', group: binding, eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, position }) },
    event: structuredClone(event),
  };
}

export function createM4V2ArchiveSource(input = {}) {
  const dependencies = validateFactory(input);
  return {
    open(openInput) {
      const request = validateOpen(openInput, dependencies.startCheckpoint);
      return (async function* () {
      let sequence = request.afterSequence;
      let after = null;
      let resume = null;
      if (request.afterSequence > 0) {
        const match = CHECKPOINT_ID.exec(request.after.id);
        const logicalMessageId = `lmsg_${match[1]}`;
        after = predecessor(match[1]);
        resume = { logicalMessageId, checkpoint: request.after };
      }
      let emitted = 0;
      try {
        while (emitted < request.maxEvents + 1) {
          let page;
          try { page = await dependencies.catalog.listM4V2LogicalGroups({ after, limit: dependencies.pageLimit }); }
          catch { fail('m4_v2_source_catalog_failed'); }
          if (!exact(page, ['items', 'next']) || !Array.isArray(page.items) || page.items.length > dependencies.pageLimit
            || (page.next !== null && (typeof page.next !== 'string' || !/^lmsg_[a-f0-9]{64}$/.test(page.next)))) fail('m4_v2_source_catalog_failed');
          let pageLast = after;
          for (const candidate of page.items) {
            const logicalId = candidate?.logical?.logicalMessageId;
            if (!plain(candidate) || !plain(candidate.logical) || !Array.isArray(candidate.observations)
              || typeof logicalId !== 'string' || !/^lmsg_[a-f0-9]{64}$/.test(logicalId)
              || (pageLast !== null && logicalId <= pageLast)) fail('m4_v2_source_catalog_failed');
            pageLast = logicalId;
          }
          if (page.next !== null && (page.items.length !== dependencies.pageLimit || page.next !== pageLast)) fail('m4_v2_source_catalog_failed');
          if (page.items.length === 0) return;
          for (const candidate of page.items) {
            let group;
            try { group = buildM4V2LogicalGroup(candidate.logical, candidate.observations); }
            catch { fail('m4_v2_source_catalog_failed'); }
            if (resume && group?.logical?.logicalMessageId !== resume.logicalMessageId) fail('m4_v2_source_checkpoint_drift');
            const observations = [];
            for (const [index, catalogRow] of group.observations.entries()) {
              if (!isPotentialM4ConversationProjection(catalogRow.projection)) {
                try {
                  observations.push(readM4V2CatalogObservation({
                    catalogRow,
                    migrationSequence: index + 1,
                  }));
                } catch { fail('m4_v2_source_read_failed'); }
                continue;
              }
              let envelope;
              try { envelope = await dependencies.rawStore.getClientCiphertext(catalogRow.contentId); }
              catch { fail('m4_v2_source_envelope_unavailable'); }
              try {
                observations.push(await readM4V2Observation({ catalogRow, envelope, ingestKeys: dependencies.ingestKeys,
                  migrationSequence: index + 1, verifyCatalogBinding: dependencies.verifyCatalogBinding,
                  auditDecrypt: dependencies.auditDecrypt, maxCiphertextBytes: dependencies.maxCiphertextBytes }));
              } catch { fail('m4_v2_source_read_failed'); }
            }
            let projected;
            try { projected = await projectM4V2LogicalGroup({ logical: group.logical, observations,
              integrityFor: dependencies.integrityFor, identityCollector: dependencies.identityCollector ?? null }); }
            catch { fail('m4_v2_source_project_failed'); }
            if (!exact(projected, ['schema', 'outcome', 'reason', 'evidence', 'events']) || !Array.isArray(projected.events)) fail('m4_v2_source_project_failed');
            let start = 0;
            if (resume) {
              const rows = projected.events.map((_, position) => rowFor(group, projected.events, position, request.afterSequence + position + 1));
              const matched = rows.filter(row => canonicalJson(row.checkpoint) === canonicalJson(resume.checkpoint));
              if (matched.length !== 1) fail('m4_v2_source_checkpoint_drift');
              start = rows.findIndex(row => canonicalJson(row.checkpoint) === canonicalJson(resume.checkpoint)) + 1;
              resume = null;
            }
            for (let position = start; position < projected.events.length && emitted < request.maxEvents + 1; position += 1) {
              sequence += 1;
              yield rowFor(group, projected.events, position, sequence);
              emitted += 1;
            }
            after = group.logical.logicalMessageId;
            if (emitted >= request.maxEvents + 1) return;
          }
          if (page.next === null) return;
          after = page.next;
        }
      } catch (error) {
        if (error?.code?.startsWith('m4_v2_source_')) throw error;
        fail('m4_v2_source_enumeration_failed');
      }
      })();
    },
  };
}
