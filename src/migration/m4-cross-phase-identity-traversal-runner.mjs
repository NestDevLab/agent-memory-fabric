import crypto from 'node:crypto';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4CrossPhaseIdentityEmptyRegistry, readM4CrossPhaseIdentityStreamingCoverage } from './m4-cross-phase-identity-streaming-writer.mjs';
import { createM4CrossPhaseIdentityTraversalCompletion, createM4CrossPhaseIdentityZeroStreamingCoverage, verifyM4CrossPhaseIdentityTraversalRecord } from './m4-cross-phase-identity-traversal-completion.mjs';
import { canonicalM4V2CatalogRevisionAttestationDigest, verifyM4V2CatalogRevisionAttestation } from './m4-v2-catalog-revision-attestation.mjs';
import { createM4CrossPhaseIdentityTraversalGroupCheckpoint, createM4CrossPhaseIdentityTraversalPrefixAccumulator } from './m4-cross-phase-identity-traversal-store.mjs';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function clone(value, code) { try { return structuredClone(value); } catch { fail(code); } }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`; }

function request(value) {
  const keys = ['source', 'traversalStore', 'lease', 'runId', 'planDigest', 'catalogBaseline', 'catalogKeyDocument',
    'archiveCompletion', 'archiveCompletionKeyDocument', 'completionKeyDocument', 'registryKeyDocument',
    'manifestId', 'revision', 'registrySecret', 'registryKeyId', 'createWriter', 'catalogAttestor', 'publish'];
  if (!exact(value, keys)) fail('m4_cross_phase_identity_traversal_runner_input_invalid');
  value = Object.fromEntries(keys.map(key => [key, value[key]]));
  const source = value.source; let binding = source?.binding; const sourceOpen = source?.open;
  const store = value.traversalStore; const storeLoad = store?.load; const storeCommit = store?.commit; const storeComplete = store?.complete;
  const lease = value.lease; const acquire = lease?.acquire; const heartbeat = lease?.heartbeat; const release = lease?.release;
  if (!object(source) || !exact(binding, ['runId', 'planDigest', 'catalogBaselineDigest', 'groupCount']) || typeof sourceOpen !== 'function'
    || !object(store) || typeof storeLoad !== 'function' || typeof storeCommit !== 'function' || typeof storeComplete !== 'function'
    || !object(lease) || typeof acquire !== 'function' || typeof heartbeat !== 'function' || typeof release !== 'function'
    || typeof value.runId !== 'string' || !ID.test(value.runId) || typeof value.planDigest !== 'string' || !DIGEST.test(value.planDigest)
    || typeof value.manifestId !== 'string' || !ID.test(value.manifestId) || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !(value.registrySecret instanceof Uint8Array) || value.registrySecret.byteLength !== 32 || typeof value.registryKeyId !== 'string' || !ID.test(value.registryKeyId)
    || typeof value.createWriter !== 'function' || typeof value.catalogAttestor !== 'function' || typeof value.publish !== 'function') fail('m4_cross_phase_identity_traversal_runner_input_invalid');
  binding = Object.fromEntries(['runId', 'planDigest', 'catalogBaselineDigest', 'groupCount'].map(key => [key, binding[key]]));
  let baseline;
  try { baseline = verifyM4V2CatalogRevisionAttestation(value.catalogBaseline, value.catalogKeyDocument); }
  catch { fail('m4_cross_phase_identity_traversal_runner_baseline_invalid'); }
  if (baseline.schema !== 'amf.m4-v2-catalog-revision-attestation/v2' || baseline.traversal.groupCount < 1 || baseline.traversal.coveredThrough === null) {
    fail('m4_cross_phase_identity_traversal_runner_empty_catalog');
  }
  let baselineDigest;
  try { baselineDigest = canonicalM4V2CatalogRevisionAttestationDigest(value.catalogBaseline, value.catalogKeyDocument); }
  catch { fail('m4_cross_phase_identity_traversal_runner_baseline_invalid'); }
  if (binding.runId !== value.runId || binding.planDigest !== value.planDigest
    || binding.catalogBaselineDigest !== baselineDigest || binding.groupCount !== baseline.traversal.groupCount) fail('m4_cross_phase_identity_traversal_runner_source_binding_invalid');
  return Object.freeze({
    source, sourceOpen, store, storeLoad, storeCommit, storeComplete, baselineDigest,
    lease, acquire, heartbeat, release, runId: value.runId, planDigest: value.planDigest, baseline,
    catalogBaseline: clone(value.catalogBaseline, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    catalogKeyDocument: clone(value.catalogKeyDocument, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    archiveCompletion: clone(value.archiveCompletion, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    archiveCompletionKeyDocument: clone(value.archiveCompletionKeyDocument, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    completionKeyDocument: clone(value.completionKeyDocument, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    registryKeyDocument: clone(value.registryKeyDocument, 'm4_cross_phase_identity_traversal_runner_input_invalid'),
    manifestId: value.manifestId, revision: value.revision, registrySecret: Buffer.from(value.registrySecret), registryKeyId: value.registryKeyId,
    createWriter: value.createWriter, catalogAttestor: value.catalogAttestor, publish: value.publish,
  });
}

function resultGroup(value) {
  const keys = ['sequence', 'checkpoint', 'logicalMessageId', 'outcome', 'reason', 'identityBlock', 'identityBlockDigest'];
  if (!exact(value, keys)) fail('m4_cross_phase_identity_traversal_runner_source_invalid');
  value = clone(Object.fromEntries(keys.map(key => [key, value[key]])), 'm4_cross_phase_identity_traversal_runner_source_invalid');
  if (
    !Number.isSafeInteger(value.sequence) || value.sequence < 1 || typeof value.logicalMessageId !== 'string'
    || !/^lmsg_[a-f0-9]{64}$/.test(value.logicalMessageId) || !['accepted', 'excluded'].includes(value.outcome)
    || (value.outcome === 'accepted' && !(value.reason === null && value.identityBlock !== null && typeof value.identityBlockDigest === 'string' && DIGEST.test(value.identityBlockDigest)))
    || (value.outcome === 'excluded' && !(typeof value.reason === 'string' && value.identityBlock === null && value.identityBlockDigest === null))) {
    fail('m4_cross_phase_identity_traversal_runner_source_invalid');
  }
  if ((value.outcome === 'accepted' && digest(value.identityBlock) !== value.identityBlockDigest)
    || !same(value.checkpoint, createM4CrossPhaseIdentityTraversalGroupCheckpoint({ sequence:value.sequence, logicalMessageId:value.logicalMessageId,
      outcome:value.outcome, identityBlockDigest:value.identityBlockDigest }))) fail('m4_cross_phase_identity_traversal_runner_source_invalid');
  return clone(value, 'm4_cross_phase_identity_traversal_runner_source_invalid');
}

function checkpointGroup(value) {
  return { sequence: value.sequence, checkpoint: value.checkpoint, logicalMessageId: value.logicalMessageId,
    outcome: value.outcome, identityBlockDigest: value.identityBlockDigest };
}

function writerResult(value) {
  if (!exact(value, ['writer', 'databasePath'])) fail('m4_cross_phase_identity_traversal_runner_writer_invalid');
  const writer = value.writer; const databasePath = value.databasePath; const accept = writer?.accept; const seal = writer?.seal; const close = writer?.close;
  if (!object(writer) || typeof accept !== 'function' || typeof seal !== 'function' || typeof close !== 'function' || typeof databasePath !== 'string') {
    fail('m4_cross_phase_identity_traversal_runner_writer_invalid');
  }
  return { writer, accept, seal, close, databasePath };
}

async function invoke(code, callback, receiver, value = undefined) {
  try { return value === undefined ? await callback.call(receiver) : await callback.call(receiver, value); }
  catch { fail(code); }
}

function completionInput(safe, traversalRecord, coverage) {
  return {
    manifestId: safe.manifestId, revision: safe.revision, archiveCompletion: safe.archiveCompletion,
    archiveCompletionKeyDocument: safe.archiveCompletionKeyDocument, catalogBaseline: safe.catalogBaseline,
    catalogKeyDocument: safe.catalogKeyDocument, traversalRecord, coverage,
    completionKeyDocument: safe.completionKeyDocument, registryKeyDocument: safe.registryKeyDocument,
  };
}

// The traversal leaves streaming coverage open. Its restart path rescans the
// content-free sequence and verifies the durable prefix before any new write.
export async function runM4CrossPhaseIdentityTraversal(input = {}) {
  const safe = request(input);
  let acquired = false; let writer = null; let primary = null; let writerClosed = false; let databasePath = null;
  try {
    await invoke('m4_cross_phase_identity_traversal_runner_lease_failed', safe.acquire, safe.lease);
    acquired = true;
    let persisted = await invoke('m4_cross_phase_identity_traversal_runner_store_failed', safe.storeLoad, safe.store);
    if (!plain(persisted)) fail('m4_cross_phase_identity_traversal_runner_store_invalid');
    persisted=clone(persisted,'m4_cross_phase_identity_traversal_runner_store_invalid');
    if (!object(persisted.binding) || persisted.binding.runId !== safe.runId || persisted.binding.planDigest !== safe.planDigest
      || persisted.binding.catalogBaselineDigest !== safe.baselineDigest) fail('m4_cross_phase_identity_traversal_runner_store_binding_invalid');
    if (!Number.isSafeInteger(persisted.sequence) || persisted.sequence < 0 || persisted.sequence > safe.baseline.traversal.groupCount) fail('m4_cross_phase_identity_traversal_runner_store_invalid');
    const prefix = createM4CrossPhaseIdentityTraversalPrefixAccumulator({ runId: safe.runId, planDigest: safe.planDigest,
      catalogBaselineDigest: safe.baselineDigest });
    if (persisted.sequence===0) { try { if (!prefix.matches(persisted)) fail('m4_cross_phase_identity_traversal_runner_store_invalid'); } catch (error) { if (error?.code==='m4_cross_phase_identity_traversal_runner_store_invalid') throw error; fail('m4_cross_phase_identity_traversal_runner_store_invalid'); } }
    let prefixVerified = persisted.sequence === 0; let prefixFirstAccepted = null; let pendingOrphan = false;
    const preTraversalAttestation = await invoke('m4_cross_phase_identity_traversal_runner_attestation_failed', safe.catalogAttestor);
    let verifiedPre;
    try { verifiedPre = verifyM4V2CatalogRevisionAttestation(preTraversalAttestation, safe.catalogKeyDocument); }
    catch { fail('m4_cross_phase_identity_traversal_runner_attestation_failed'); }
    if (!same(verifiedPre, safe.baseline)) fail('m4_cross_phase_identity_traversal_runner_catalog_drift');
    let source;
    try { source = safe.sourceOpen.call(safe.source, { afterSequence: 0, afterCheckpoint: null }); }
    catch { fail('m4_cross_phase_identity_traversal_runner_source_failed'); }
    if (!source || typeof source[Symbol.asyncIterator] !== 'function') fail('m4_cross_phase_identity_traversal_runner_source_invalid');
    let expectedSequence=1;
    for await (const candidate of source) {
      const group = resultGroup(candidate);
      if (group.sequence!==expectedSequence || group.sequence>safe.baseline.traversal.groupCount) fail('m4_cross_phase_identity_traversal_runner_source_invalid');
      expectedSequence+=1;
      await invoke('m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed', safe.heartbeat, safe.lease);
      if (group.sequence <= persisted.sequence) {
        prefix.append(checkpointGroup(group));
        if (group.outcome === 'accepted' && prefixFirstAccepted === null) prefixFirstAccepted = clone(group.identityBlock, 'm4_cross_phase_identity_traversal_runner_source_invalid');
        if (group.sequence === persisted.sequence) {
          try { if (!prefix.matches(persisted)) fail('m4_cross_phase_identity_traversal_runner_prefix_drift'); } catch (error) { if (error?.code==='m4_cross_phase_identity_traversal_runner_prefix_drift') throw error; fail('m4_cross_phase_identity_traversal_runner_store_invalid'); }
          prefixVerified = true;
          if (persisted.acceptedGroupCount > 0) {
            if (prefixFirstAccepted === null) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
            const made = await invoke('m4_cross_phase_identity_traversal_runner_writer_failed', safe.createWriter, null,
              { expectedBlockCount: safe.baseline.traversal.groupCount, firstBlock: prefixFirstAccepted });
            writer = writerResult(made); databasePath = writer.databasePath;
            let existingCoverage;
            try { existingCoverage = readM4CrossPhaseIdentityStreamingCoverage({ databasePath }); }
            catch { fail('m4_cross_phase_identity_traversal_runner_coverage_failed'); }
            if (!['open','seal-intent','sealed'].includes(existingCoverage.state) || (existingCoverage.state !== 'open' && (!persisted.complete || existingCoverage.blockCount !== persisted.acceptedGroupCount)) || existingCoverage.expectedBlockCount !== safe.baseline.traversal.groupCount
              || ![persisted.acceptedGroupCount, persisted.acceptedGroupCount + 1].includes(existingCoverage.blockCount)) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
            pendingOrphan = existingCoverage.blockCount === persisted.acceptedGroupCount + 1;
          }
        }
        continue;
      }
      if (!prefixVerified) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
      if (pendingOrphan && group.outcome !== 'accepted') fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
      if (group.outcome === 'accepted') {
        if (writer === null) {
          const made = await invoke('m4_cross_phase_identity_traversal_runner_writer_failed', safe.createWriter, null,
            { expectedBlockCount: safe.baseline.traversal.groupCount, firstBlock: clone(group.identityBlock, 'm4_cross_phase_identity_traversal_runner_source_invalid') });
          writer = writerResult(made);
          databasePath = writer.databasePath;
          let existingCoverage;
          try { existingCoverage = readM4CrossPhaseIdentityStreamingCoverage({ databasePath }); }
          catch { fail('m4_cross_phase_identity_traversal_runner_coverage_failed'); }
          if (existingCoverage.state !== 'open' || existingCoverage.expectedBlockCount !== safe.baseline.traversal.groupCount
            || ![persisted.acceptedGroupCount, persisted.acceptedGroupCount + 1].includes(existingCoverage.blockCount)) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
          pendingOrphan = existingCoverage.blockCount === persisted.acceptedGroupCount + 1;
        }
        const accepted = await invoke('m4_cross_phase_identity_traversal_runner_writer_failed', writer.accept, writer.writer, group.identityBlock);
        if (!exact(accepted, ['blockDigest', 'accepted']) || accepted.blockDigest !== group.identityBlockDigest || typeof accepted.accepted !== 'boolean'
          || (pendingOrphan ? accepted.accepted !== false : accepted.accepted !== true)) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
        pendingOrphan = false;
      }
      await invoke('m4_cross_phase_identity_traversal_runner_store_failed', safe.storeCommit, safe.store, checkpointGroup(group));
    }
    if (!prefixVerified || pendingOrphan) fail('m4_cross_phase_identity_traversal_runner_prefix_drift');
    let traversalRecord = await invoke('m4_cross_phase_identity_traversal_runner_store_failed', safe.storeComplete, safe.store,
      { expectedGroupCount: safe.baseline.traversal.groupCount });
    try { traversalRecord=verifyM4CrossPhaseIdentityTraversalRecord(traversalRecord); } catch { fail('m4_cross_phase_identity_traversal_runner_store_invalid'); }
    if (traversalRecord.runId!==safe.runId || traversalRecord.planDigest!==safe.planDigest || traversalRecord.catalogAttestationDigest!==safe.baselineDigest) fail('m4_cross_phase_identity_traversal_runner_store_invalid');
    const postTraversalAttestation = await invoke('m4_cross_phase_identity_traversal_runner_attestation_failed', safe.catalogAttestor);
    let verifiedPost;
    try { verifiedPost = verifyM4V2CatalogRevisionAttestation(postTraversalAttestation, safe.catalogKeyDocument); }
    catch { fail('m4_cross_phase_identity_traversal_runner_attestation_failed'); }
    if (!same(verifiedPost, safe.baseline)) fail('m4_cross_phase_identity_traversal_runner_catalog_drift');
    let coverage; let registry = null;
    if (traversalRecord.acceptedGroupCount === 0) {
      if (writer !== null || traversalRecord.excludedGroupCount < 1) fail('m4_cross_phase_identity_traversal_runner_zero_invalid');
      coverage = createM4CrossPhaseIdentityZeroStreamingCoverage();
    } else {
      if (writer === null) fail('m4_cross_phase_identity_traversal_runner_writer_missing');
      databasePath = writer.databasePath;
      try { coverage = readM4CrossPhaseIdentityStreamingCoverage({ databasePath: writer.databasePath }); }
      catch { fail('m4_cross_phase_identity_traversal_runner_coverage_failed'); }
      if (coverage.state === 'sealed' || coverage.state === 'seal-intent') coverage={...coverage,state:'open'};
    }
    let traversalCompletion;
    try { traversalCompletion = createM4CrossPhaseIdentityTraversalCompletion({ ...completionInput(safe, traversalRecord, coverage), preTraversalAttestation: verifiedPre, postTraversalAttestation: verifiedPost }); }
    catch { fail('m4_cross_phase_identity_traversal_runner_completion_failed'); }
    if (traversalRecord.acceptedGroupCount === 0) {
      await invoke('m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed', safe.heartbeat, safe.lease);
      try {
        registry = createM4CrossPhaseIdentityEmptyRegistry({ traversalCompletion, completionKeyDocument: safe.completionKeyDocument,
          registrySecret: safe.registrySecret, registryKeyId: safe.registryKeyId });
      } catch { fail('m4_cross_phase_identity_traversal_runner_empty_registry_failed'); }
    } else {
      await invoke('m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed', safe.heartbeat, safe.lease);
      try { registry=await writer.seal.call(writer.writer,{traversalCompletion,completionKeyDocument:safe.completionKeyDocument}); }
      catch (error) { if (error?.code==='m4_cross_phase_identity_streaming_seal_binding_invalid') fail('m4_cross_phase_identity_traversal_runner_seal_binding_invalid'); fail('m4_cross_phase_identity_traversal_runner_seal_failed'); }
    }
    await invoke('m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed', safe.heartbeat, safe.lease);
    const postSealAttestation = await invoke('m4_cross_phase_identity_traversal_runner_attestation_failed', safe.catalogAttestor);
    let verifiedPostSeal;
    try { verifiedPostSeal=verifyM4V2CatalogRevisionAttestation(postSealAttestation,safe.catalogKeyDocument); } catch { fail('m4_cross_phase_identity_traversal_runner_attestation_failed'); }
    if (!same(verifiedPostSeal,safe.baseline)) fail('m4_cross_phase_identity_traversal_runner_catalog_drift');
    await invoke('m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed', safe.heartbeat, safe.lease);
    const publication=await invoke('m4_cross_phase_identity_traversal_runner_publish_failed',safe.publish,null,{traversalCompletion:clone(traversalCompletion,'m4_cross_phase_identity_traversal_runner_result_invalid'),registry:clone(registry,'m4_cross_phase_identity_traversal_runner_result_invalid'),coverage:clone(coverage,'m4_cross_phase_identity_traversal_runner_result_invalid')});
    let safePublication;
    try { if (!exact(publication,['state','artifactDigest'])) fail('m4_cross_phase_identity_traversal_runner_publish_invalid'); const snapshot={state:publication.state,artifactDigest:publication.artifactDigest}; if (snapshot.state!=='published'||typeof snapshot.artifactDigest!=='string'||!DIGEST.test(snapshot.artifactDigest)) fail('m4_cross_phase_identity_traversal_runner_publish_invalid'); safePublication=clone(snapshot,'m4_cross_phase_identity_traversal_runner_publish_invalid'); }
    catch (error) { if (error?.code==='m4_cross_phase_identity_traversal_runner_publish_invalid') throw error; fail('m4_cross_phase_identity_traversal_runner_publish_invalid'); }
    if (writer!==null) { await invoke('m4_cross_phase_identity_traversal_runner_cleanup_failed',writer.close,writer.writer); writerClosed=true; }
    return Object.freeze({ traversalRecord: clone(traversalRecord, 'm4_cross_phase_identity_traversal_runner_result_invalid'),
      traversalCompletion: clone(traversalCompletion, 'm4_cross_phase_identity_traversal_runner_result_invalid'), coverage,
      databasePath, publication:safePublication });
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    safe.registrySecret.fill(0);
    let cleanupFailure = null;
    if (writer !== null && !writerClosed) {
      try { await writer.close.call(writer.writer); } catch { cleanupFailure ??= 'm4_cross_phase_identity_traversal_runner_cleanup_failed'; }
    }
    if (acquired) {
      try { await safe.release.call(safe.lease); }
      catch { cleanupFailure ??= 'm4_cross_phase_identity_traversal_runner_release_failed'; }
    }
    if (primary === null && cleanupFailure !== null) fail(cleanupFailure);
  }
}
