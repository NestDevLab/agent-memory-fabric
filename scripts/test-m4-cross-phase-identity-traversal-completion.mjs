import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import Database from 'better-sqlite3';

import { createM4CrossPhaseIdentityStreamingWriter, readM4CrossPhaseIdentityStreamingCoverage } from '../src/migration/m4-cross-phase-identity-streaming-writer.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId, deriveM4V3SourceInstanceIdFromLegacySession } from '../src/migration/m4-v2-conversation-projector.mjs';
import { createM4CrossPhaseIdentityTraversalCompletion, createM4CrossPhaseIdentityTraversalRecord, createM4CrossPhaseIdentityZeroStreamingCoverage, verifyM4CrossPhaseIdentityTraversalCompletion, verifyM4CrossPhaseIdentityTraversalRecord } from '../src/migration/m4-cross-phase-identity-traversal-completion.mjs';
import { createM4CrossPhaseIdentityEmptyRegistry } from '../src/migration/m4-cross-phase-identity-streaming-writer.mjs';
import { verifyM4CrossPhaseIdentityAuthority } from '../src/migration/m4-cross-phase-identity-registry.mjs';
import { digest as fixtureDigest, fixture, sign } from './helpers/m4-traversal-completion-fixtures.mjs';

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const secret = Buffer.alloc(32, 7); const tag = `test:${hash('tag')}`; const opaque = `hmac-sha256:test:${hash('opaque')}`;
function block(label) { const legacySessionId = `ses_${hash(`session:${label}`)}`; const legacyEventId = `evt_${hash(`event:${label}`)}`; const conversationId = deriveM4V3ConversationIdFromLegacySessionId(legacySessionId); const context = { sender:[opaque], conversation:[opaque], room:[opaque] }; return { schema:'amf.m4-cross-phase-projector-identity-block/v1', session:{ legacySessionId, conversationId, conversationKind:'dm', sessionContextTags:{ conversation:[opaque], room:[opaque] } }, events:[{ legacyEventId, legacySessionId, eventId:deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId, sourceInstanceId:deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId,[tag]), sourceTags:[tag], conversationKind:'dm', authorizationContextTags:context, role:'user', direction:'inbound', state:'active', revision:1, replacesLegacyEventId:null, tombstonesLegacyEventId:null, conflictsWithLegacyEventIds:[] }] }; }

test('reads pinned streaming coverage without changing spool metadata or inode timestamps', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-coverage-')); const databasePath = path.join(root, 'private', 'spool.sqlite');
  try {
    const writer = createM4CrossPhaseIdentityStreamingWriter({ databasePath, registrySecret:secret, registryKeyId:'registry-fixture-key', capacityPreflight:{ availableBytes:5*1024*1024*1024, sampleBlocks:[block('sample')], expectedBlockCount:2 }, pageSink:{ writePage:async page => ({ pageKey:page.pageKey, digest:page.digest }) } }); writer.accept(block('one')); writer.close();
    const configured = new Database(databasePath); assert.equal(configured.pragma('journal_mode = WAL', { simple:true }), 'wal'); configured.close();
    const before = fs.statSync(databasePath); const coverage = readM4CrossPhaseIdentityStreamingCoverage({ databasePath }); const after = fs.statSync(databasePath);
    assert.deepEqual(coverage, { schema:'amf.m4-cross-phase-identity-streaming-coverage/v1', state:'open', expectedBlockCount:2, blockCount:1, sessionCount:1, eventCount:1 });
    assert.deepEqual([after.dev,after.ino,after.size,after.mtimeMs], [before.dev,before.ino,before.size,before.mtimeMs]);
    const checked = new Database(databasePath,{readonly:true}); assert.equal(checked.pragma('journal_mode',{simple:true}),'wal'); checked.close();
  } finally { fs.rmSync(root, { recursive:true, force:true }); }
});

test('creates and verifies a signed immutable traversal completion and record', () => {
  const coverage={ schema:'amf.m4-cross-phase-identity-streaming-coverage/v1', state:'open', expectedBlockCount:2, blockCount:1, sessionCount:1, eventCount:1 };
  const item=fixture({ coverage, registrySecret:Buffer.alloc(32,7) });
  const record=verifyM4CrossPhaseIdentityTraversalRecord(item.input.traversalRecord);
  assert.deepEqual(record, createM4CrossPhaseIdentityTraversalRecord({ runId:record.runId, planDigest:record.planDigest, traversalDigest:record.traversalDigest, catalogAttestationDigest:record.catalogAttestationDigest, acceptedGroupCount:1, excludedGroupCount:0 }));
  assert.deepEqual(verifyM4CrossPhaseIdentityTraversalCompletion(item.traversalCompletion,item.completionKeyDocument), item.traversalCompletion);
  assert.equal(item.traversalCompletion.manifestId, 'fixture-traversal-completion'); assert.equal(item.traversalCompletion.revision, 1);
});

test('fails closed on malformed coverage, mismatched record, registry material, and tampered completion', () => {
  const coverage={ schema:'amf.m4-cross-phase-identity-streaming-coverage/v1', state:'open', expectedBlockCount:2, blockCount:1, sessionCount:1, eventCount:1 };
  const item=fixture({ coverage, registrySecret:Buffer.alloc(32,7) });
  const zeroCapacity=structuredClone(item.input); zeroCapacity.coverage.expectedBlockCount=0;
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(zeroCapacity), { code:'m4_cross_phase_identity_traversal_coverage_invalid' });
  const mismatchedCoverage=structuredClone(item.input); mismatchedCoverage.coverage.blockCount=0;
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(mismatchedCoverage), { code:'m4_cross_phase_identity_traversal_coverage_mismatch' });
  const changedRecord=structuredClone(item.input); changedRecord.traversalRecord.catalogAttestationDigest='sha256:'.concat('0'.repeat(64));
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(changedRecord), { code:'m4_cross_phase_identity_traversal_record_invalid' });
  const longRegistry=structuredClone(item.input); longRegistry.registryKeyDocument.key=Buffer.alloc(33,9).toString('base64');
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(longRegistry), { code:'m4_cross_phase_identity_traversal_registry_key_invalid' });
  const equalKeys=structuredClone(item.input); equalKeys.completionKeyDocument.key=Buffer.alloc(32,7).toString('base64');
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(equalKeys), { code:'m4_cross_phase_identity_traversal_key_separation_invalid' });
  const zeroPaddedKeys=structuredClone(item.input); zeroPaddedKeys.completionKeyDocument.key=Buffer.concat([Buffer.alloc(32,7),Buffer.alloc(32)]).toString('base64');
  assert.throws(() => createM4CrossPhaseIdentityTraversalCompletion(zeroPaddedKeys), { code:'m4_cross_phase_identity_traversal_key_separation_invalid' });
  const tampered=structuredClone(item.traversalCompletion); tampered.archiveCompletionDigest='sha256:'.concat('f'.repeat(64));
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(tampered,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  const wrongCatalog=structuredClone(item.traversalCompletion); wrongCatalog.catalogBaselineDigest='sha256:'.concat('e'.repeat(64));
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(wrongCatalog,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  const wrongCount=structuredClone(item.traversalCompletion); wrongCount.coverage.blockCount=0;
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(wrongCount,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  const duplicateKeyId=structuredClone(item.traversalCompletion); duplicateKeyId.registryKeyId=duplicateKeyId.completionKeyId; const duplicateBody=structuredClone(duplicateKeyId); delete duplicateBody.integrity;
  duplicateKeyId.integrity={ algorithm:'hmac-sha256', keyId:item.completionKeyDocument.keyId, payloadDigest:fixtureDigest(duplicateBody), signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',duplicateBody,item.completionKeyDocument) };
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(duplicateKeyId,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  const badRecord=structuredClone(item.input.traversalRecord); badRecord.finalCheckpoint.digest='sha256:'.concat('0'.repeat(64));
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalRecord(badRecord), { code:'m4_cross_phase_identity_traversal_record_invalid' });
});

test('permits only a zero open coverage with a nonempty all-excluded baseline and creates an empty registry', () => {
  const zero=createM4CrossPhaseIdentityZeroStreamingCoverage(); const registrySecret=Buffer.alloc(32,7); const item=fixture({ coverage:zero, registrySecret, groupCount:1 });
  assert.deepEqual(item.traversalCompletion.coverage,zero); const first=createM4CrossPhaseIdentityEmptyRegistry({ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument, registrySecret, registryKeyId:item.registryKeyId });
  const second=createM4CrossPhaseIdentityEmptyRegistry({ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument, registrySecret, registryKeyId:item.registryKeyId });
  assert.deepEqual(first,second); assert.deepEqual(first.coverage,{acceptedBlockCount:0,sessionCount:0,eventCount:0,pageCount:0}); assert.deepEqual(verifyM4CrossPhaseIdentityAuthority(first.authority,registrySecret).pages,[]); assert.deepEqual(registrySecret,Buffer.alloc(32,7));
  const missingExclusion=structuredClone(item.traversalCompletion); const oldRecord=missingExclusion.traversalRecord; missingExclusion.traversalRecord=createM4CrossPhaseIdentityTraversalRecord({runId:oldRecord.runId,planDigest:oldRecord.planDigest,traversalDigest:oldRecord.traversalDigest,catalogAttestationDigest:oldRecord.catalogAttestationDigest,acceptedGroupCount:0,excludedGroupCount:0}); const missingExclusionBody=structuredClone(missingExclusion); delete missingExclusionBody.integrity; missingExclusion.integrity={algorithm:'hmac-sha256',keyId:item.completionKeyDocument.keyId,payloadDigest:fixtureDigest(missingExclusionBody),signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',missingExclusionBody,item.completionKeyDocument)};
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(missingExclusion,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  for (const field of ['blockCount','sessionCount','eventCount']) { const invalid={...zero,[field]:1}; assert.throws(() => fixture({ coverage:invalid, registrySecret, groupCount:1 }), { code:'m4_cross_phase_identity_traversal_coverage_invalid' }); }
  assert.throws(() => fixture({ coverage:{...zero,state:'sealed'}, registrySecret, groupCount:1 }), { code:'m4_cross_phase_identity_traversal_coverage_invalid' });
  assert.throws(() => fixture({ coverage:zero, registrySecret, groupCount:0, coveredThrough:null }), { code:'m4_cross_phase_identity_traversal_catalog_mismatch' });
});

test('empty registry rejects wrong binding, reused material, and hostile completion-key reads', () => {
  const registrySecret=Buffer.alloc(32,7); const item=fixture({ coverage:createM4CrossPhaseIdentityZeroStreamingCoverage(), registrySecret, groupCount:1 }); const input={ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument, registrySecret, registryKeyId:item.registryKeyId };
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,registryKeyId:'other-registry-key'}), { code:'m4_cross_phase_identity_empty_registry_binding_invalid' });
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,registrySecret:Buffer.alloc(32,9)}), { code:'m4_cross_phase_identity_empty_registry_binding_invalid' });
  const badCommitment=structuredClone(item.traversalCompletion); badCommitment.registryKeyCommitment='hmac-sha256:'.concat('a'.repeat(43)); const commitmentBody=structuredClone(badCommitment); delete commitmentBody.integrity; badCommitment.integrity={algorithm:'hmac-sha256',keyId:item.completionKeyDocument.keyId,payloadDigest:fixtureDigest(commitmentBody),signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',commitmentBody,item.completionKeyDocument)};
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,traversalCompletion:badCommitment}), { code:'m4_cross_phase_identity_empty_registry_binding_invalid' });
  const signingDocument={schema:'amf.migration-signing-key/v1',keyId:item.completionKeyDocument.keyId,key:registrySecret.toString('base64')}; const forged=structuredClone(item.traversalCompletion); const body=structuredClone(forged); delete body.integrity; forged.integrity={algorithm:'hmac-sha256',keyId:signingDocument.keyId,payloadDigest:fixtureDigest(body),signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',body,signingDocument)};
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,traversalCompletion:forged,completionKeyDocument:signingDocument}), { code:'m4_cross_phase_identity_empty_registry_key_separation_invalid' });
  const paddedDocument={schema:'amf.migration-signing-key/v1',keyId:item.completionKeyDocument.keyId,key:Buffer.concat([registrySecret,Buffer.alloc(32)]).toString('base64')}; const padded=structuredClone(item.traversalCompletion); const paddedBody=structuredClone(padded); delete paddedBody.integrity; padded.integrity={algorithm:'hmac-sha256',keyId:paddedDocument.keyId,payloadDigest:fixtureDigest(paddedBody),signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',paddedBody,paddedDocument)};
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,traversalCompletion:padded,completionKeyDocument:paddedDocument}), { code:'m4_cross_phase_identity_empty_registry_key_separation_invalid' });
  let reads=0; const hostile={schema:'amf.migration-signing-key/v1',keyId:item.completionKeyDocument.keyId,get key(){ reads+=1; return reads===1 ? registrySecret.toString('base64') : Buffer.alloc(32,99).toString('base64'); }};
  assert.throws(() => createM4CrossPhaseIdentityEmptyRegistry({...input,traversalCompletion:forged,completionKeyDocument:hostile}), { code:'m4_cross_phase_identity_empty_registry_key_separation_invalid' }); assert.equal(reads,1);
});
