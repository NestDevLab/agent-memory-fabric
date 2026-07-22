import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import Database from 'better-sqlite3';

import { createM4CrossPhaseIdentityStreamingWriter, readM4CrossPhaseIdentityStreamingCoverage } from '../src/migration/m4-cross-phase-identity-streaming-writer.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId, deriveM4V3SourceInstanceIdFromLegacySession } from '../src/migration/m4-v2-conversation-projector.mjs';
import { createM4CrossPhaseIdentityTraversalCompletion, createM4CrossPhaseIdentityTraversalRecord, verifyM4CrossPhaseIdentityTraversalCompletion, verifyM4CrossPhaseIdentityTraversalRecord } from '../src/migration/m4-cross-phase-identity-traversal-completion.mjs';
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
  const duplicateKeyId=structuredClone(item.traversalCompletion); duplicateKeyId.registryKeyId=duplicateKeyId.completionKeyId;
  const { integrity, ...duplicateBody }=duplicateKeyId; duplicateKeyId.integrity={ algorithm:'hmac-sha256', keyId:item.completionKeyDocument.keyId, payloadDigest:fixtureDigest(duplicateBody), signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',duplicateBody,item.completionKeyDocument) };
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalCompletion(duplicateKeyId,item.completionKeyDocument), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
  const badRecord=structuredClone(item.input.traversalRecord); badRecord.finalCheckpoint.digest='sha256:'.concat('0'.repeat(64));
  assert.throws(() => verifyM4CrossPhaseIdentityTraversalRecord(badRecord), { code:'m4_cross_phase_identity_traversal_record_invalid' });
});
