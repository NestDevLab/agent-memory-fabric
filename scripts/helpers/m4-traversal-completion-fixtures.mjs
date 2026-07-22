import crypto from 'node:crypto';
import { canonicalJson } from '../../src/ingest/transcripts/canonical.mjs';
import { createM4CrossPhaseIdentityTraversalCompletion, createM4CrossPhaseIdentityTraversalRecord } from '../../src/migration/m4-cross-phase-identity-traversal-completion.mjs';

export const digest = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value),'utf8').digest('hex')}`;
export const key = (keyId, byte) => ({ schema:'amf.migration-signing-key/v1', keyId, key:Buffer.alloc(32,byte).toString('base64') });
export const sign = (domain, body, document) => crypto.createHmac('sha256',Buffer.from(document.key,'base64')).update(canonicalJson([domain,digest(body),document.keyId]),'utf8').digest('base64url');
export function fixture({ coverage, registrySecret, groupCount = coverage.blockCount, coveredThrough='2026-07-22T00:00:00Z', completionByte=3 } = {}) {
  const catalogKey=key('catalog-fixture-key',1), archiveKey=key('archive-fixture-key',2), completionKey=key('traversal-fixture-key',completionByte), registryKey={...key('registry-fixture-key',4),key:Buffer.from(registrySecret).toString('base64')};
  const chain=digest(['chain']); const traversal={ pageLimit:50,groupCount,observationCount:groupCount,finalChain:chain,coveredThrough,catalogRevisionDigest:digest(['amf.m4-v2-catalog-revision-attestation/v2/revision',groupCount,groupCount,chain,coveredThrough])};
  const catalogBody={schema:'amf.m4-v2-catalog-revision-attestation/v2',traversal}; const catalog={...catalogBody,integrity:{algorithm:'hmac-sha256',keyId:catalogKey.keyId,payloadDigest:digest(catalogBody),signature:sign('amf.m4-v2-catalog-revision-attestation/v2/integrity',catalogBody,catalogKey)}};
  const archiveBody={schema:'amf.m4-v2-archive-backfill-completion/v1',state:'complete',manifestId:'fixture-archive',revision:1,gateDigest:digest(['gate']),runnerPlanDigest:digest(['plan']),catalogAttestationDigest:digest(catalog),finalCheckpoint:{id:'fixture-checkpoint',digest:digest(['checkpoint'])},resultDigest:digest(['result']),catalogAttestationKeyId:catalogKey.keyId,completionKeyId:archiveKey.keyId};
  const archive={...archiveBody,integrity:{algorithm:'hmac-sha256',keyId:archiveKey.keyId,payloadDigest:digest(archiveBody),signature:sign('amf.m4-v2-archive-backfill-completion/v1/integrity',archiveBody,archiveKey)}};
  const acceptedGroupCount=coverage.blockCount, excludedGroupCount=groupCount-acceptedGroupCount, runId='fixture-traversal'; const planDigest=digest(['traversal-plan']); const traversalDigest=digest(['traversal']); const catalogAttestationDigest=digest(catalog);
  const traversalRecord=createM4CrossPhaseIdentityTraversalRecord({runId,planDigest,traversalDigest,catalogAttestationDigest,acceptedGroupCount,excludedGroupCount});
  const input={manifestId:'fixture-traversal-completion',revision:1,archiveCompletion:archive,archiveCompletionKeyDocument:archiveKey,catalogBaseline:catalog,catalogKeyDocument:catalogKey,preTraversalAttestation:catalog,postTraversalAttestation:catalog,traversalRecord,coverage,completionKeyDocument:completionKey,registryKeyDocument:registryKey};
  return { traversalCompletion:createM4CrossPhaseIdentityTraversalCompletion(input), completionKeyDocument:completionKey, registryKeyId:registryKey.keyId, input };
}
