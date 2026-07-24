import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryCatalog } from '../src/fabric-store.mjs';
import { ciphertextContentId, normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';
import {
  canonicalizeM4CrossPhaseIdentityTraversalBlock,
  createM4CrossPhaseIdentityTraversalSource,
} from '../src/migration/m4-cross-phase-identity-traversal-source.mjs';
import { attestM4V2CatalogRevision } from '../src/migration/m4-v2-catalog-revision-attestation.mjs';
import { fixture } from './helpers/m4-traversal-completion-fixtures.mjs';

async function drain(iterator) { for await (const _ of iterator) {} }

const INGEST=Buffer.alloc(32,7).toString('base64'); const LOGICAL=Buffer.alloc(32,8).toString('base64'); const TAG=Buffer.alloc(32,9).toString('base64');
const KEYS={keys:{ingest:INGEST},digestKey:INGEST,authorizations:{ingest:{actors:['synthetic-actor'],sourceInstances:['synthetic-source']}},logicalMessageKeys:{currentKeyVersion:'logical-k1',keys:{'logical-k1':LOGICAL}}};
const DIGEST_KEY=normalizeIngestKeyRing(KEYS).digestKey;
const SIGNING={schema:'amf.migration-signing-key/v1',keyId:'catalog-fixture-key',key:Buffer.alloc(32,3).toString('base64')};
const tag=(namespace,value)=>opaqueContextTag(namespace,value,TAG,'routing-k1');
function value(label,{excluded=false,sourceKind='codex',logicalLabel=label,sessionVariant=null}={}) {
  const sender=tag('sender','synthetic-sender'); const conversation=tag('conversation','synthetic-conversation'); const direction=excluded?'internal':'inbound';
  const logicalInput={canonicalSenderIdentity:'synthetic-sender',senderTag:sender,conversationTag:conversation,direction,nativePlatform:'synthetic-platform',nativeConversationId:'synthetic-conversation',nativeMessageId:`native-${logicalLabel}`}; const logical=deriveLogicalMessageIds(logicalInput,KEYS.logicalMessageKeys);
  const raw=Buffer.from(`native-raw-${label}`); const eventId=deriveEventIdV2({sourceKind,observationClass:'native',rawBytes:raw}); const sessionId=sessionVariant===null?deriveSessionIdV2({sourceKind,conversationTag:conversation}):deriveSessionIdV2({sourceKind,nativeSessionId:sessionVariant}); const normalized={role:excluded?'system':'user',contentType:excluded?'structured':'text',value:excluded?{ignored:true}:`visible ${label}`};
  const event={schema:'amf.raw-event/v2',eventId,sessionId,occurredAt:'2026-07-21T12:00:01.000000000Z',source:{runtime:sourceKind,subtype:'message'},logical:logicalInput,normalized,raw:{encoding:'base64',line:raw.toString('base64'),lineEnding:'lf'},...(sessionVariant===null?{}:{derivation:{nativeSessionId:sessionVariant}})};
  const projection={schema:'amf.raw-event-projection/v2',eventId,sessionId,logicalMessageId:logical.logicalMessageId,logicalMessageAliases:logical.aliases,derivationVersion:'amf-logical-message/v1',keyVersion:logical.keyVersion,sourceKind,observationClass:'native',direction,conversationKind:'dm',contextTags:{actor:[tag('actor','synthetic-actor')],sender:[sender],conversation:[conversation],room:[tag('room','synthetic-room')]},subtype:'message',occurredAt:event.occurredAt,editedAt:null,nativeRevision:1,sourceSequence:1,authoritativeDeletion:false,role:normalized.role,contentType:normalized.contentType,contentParts:1,hasContent:true,normalizationVersion:'amf-observation-normalization/v1',normalizedPayloadDigest:normalizedObservationDigest({event},DIGEST_KEY)};
  return {event,projection};
}
function encrypt(input) { const root=fs.mkdtempSync(path.join(os.tmpdir(),'amf-m4-traversal-source-')); try { return new EncryptedOutbox({rootPath:root,encryptionKey:INGEST,digestKey:INGEST,sourceInstanceId:'synthetic-source',actorId:'synthetic-actor',keyId:'ingest'}).encrypt(input); } finally { fs.rmSync(root,{recursive:true,force:true}); } }
async function realFixture(items=[value('accepted'),value('excluded',{excluded:true})]) {
  const catalog=new MemoryCatalog(); const ciphertexts=new Map();
  for (const item of items) { const envelope=encrypt(item); const contentId=ciphertextContentId(envelope); ciphertexts.set(contentId,envelope); await catalog.ingestRawEventV2({eventId:item.event.eventId,sessionId:item.event.sessionId,logicalMessageId:item.projection.logicalMessageId,contentId,payloadDigest:envelope.payloadDigest,projection:item.projection,ownerTag:`catalog-k1:${'a'.repeat(64)}`,sourceTag:`catalog-k1:${'b'.repeat(64)}`,createdAt:'2026-07-22T12:00:01Z'},{contentId,mediaType:'application/json',byteLength:1,storageRef:`test/${contentId}`,createdAt:'2026-07-22T12:00:01Z'},{id:`audit-${item.event.eventId.slice(4,36)}`,ts:'2026-07-22T12:00:01Z',actorTag:`catalog-k1:${'a'.repeat(64)}`,action:'synthetic',targetId:item.event.eventId,details:{}}); }
  const baseline=await attestM4V2CatalogRevision({catalog,keyDocument:SIGNING,pageLimit:10}); const calls={raw:0,binding:0,audit:0};
  const source=createM4CrossPhaseIdentityTraversalSource({catalog,rawStore:{async getClientCiphertext(contentId){calls.raw+=1;return structuredClone(ciphertexts.get(contentId));}},ingestKeys:KEYS,verifyCatalogBinding:async()=>{calls.binding+=1;return {owner:true,source:true};},auditDecrypt:async input=>{calls.audit+=1;return {recorded:true,eventId:input.eventId,contentId:input.contentId};},integrityFor:async()=>({keyId:'m4-test-k1',key:Buffer.alloc(32,5),sentAt:'2026-07-22T12:00:02Z',nonce:'nonce00000000001'}),catalogBaseline:baseline,catalogKeyDocument:SIGNING,runId:'source-fixture',planDigest:`sha256:${'d'.repeat(64)}`,pageLimit:10}); return {source,calls,catalog,baseline,ciphertexts};
}

test('canonicalizes multi-event identity blocks before source digesting without mutating projector output', () => {
  const input = {
    schema: 'amf.m4-cross-phase-projector-identity-block/v1',
    session: { legacySessionId: `ses_${'a'.repeat(64)}` },
    events: [
      { legacyEventId: `evt_${'f'.repeat(64)}` },
      { legacyEventId: `evt_${'0'.repeat(64)}` },
    ],
  };
  const output = canonicalizeM4CrossPhaseIdentityTraversalBlock(input);
  assert.deepEqual(output.events.map(item => item.legacyEventId), [
    `evt_${'0'.repeat(64)}`,
    `evt_${'f'.repeat(64)}`,
  ]);
  assert.deepEqual(input.events.map(item => item.legacyEventId), [
    `evt_${'f'.repeat(64)}`,
    `evt_${'0'.repeat(64)}`,
  ]);
  assert.equal(
    crypto.createHash('sha256').update(JSON.stringify(output)).digest('hex'),
    crypto.createHash('sha256').update(JSON.stringify({
      ...input,
      events: [...input.events].reverse(),
    })).digest('hex'),
  );
});

test('binds a signed nonempty catalog once, snapshots method getters, and fails closed on group-count drift', async () => {
  const item=fixture({coverage:{schema:'amf.m4-cross-phase-identity-streaming-coverage/v1',state:'open',expectedBlockCount:0,blockCount:0,sessionCount:0,eventCount:0},registrySecret:Buffer.alloc(32,7),groupCount:1});
  let listReads=0; let rawReads=0;
  const catalog={get listM4V2LogicalGroups(){listReads+=1;return async()=>({items:[],next:null});}};
  const rawStore={get getClientCiphertext(){rawReads+=1;return async()=>{throw new Error('unreachable');};}};
  const source=createM4CrossPhaseIdentityTraversalSource({catalog,rawStore,ingestKeys:{keys:{ingest:Buffer.alloc(32,1).toString('base64')},digestKey:Buffer.alloc(32,1).toString('base64'),authorizations:{ingest:{actors:['synthetic-actor'],sourceInstances:['synthetic-source']}},logicalMessageKeys:{currentKeyVersion:'logical-k1',keys:{'logical-k1':Buffer.alloc(32,2).toString('base64')}}},verifyCatalogBinding:async()=>({}),auditDecrypt:async()=>({}),integrityFor:async()=>({}),catalogBaseline:item.input.catalogBaseline,catalogKeyDocument:item.input.catalogKeyDocument,runId:item.input.traversalRecord.runId,planDigest:item.input.traversalRecord.planDigest});
  assert.deepEqual(Object.keys(source.binding).sort(),['catalogBaselineDigest','groupCount','planDigest','runId']); assert.equal(listReads,1); assert.equal(rawReads,1);
  await assert.rejects(()=>drain(source.open({afterSequence:0,afterCheckpoint:null})),{code:'m4_cross_phase_identity_traversal_source_drift'});
});

test('projects one signed-catalog group and excludes an ineligible group without opening its RAW blob', async () => {
  const {source,calls}=await realFixture(); const rows=[];
  for await (const row of source.open({afterSequence:0,afterCheckpoint:null})) rows.push(row);
  assert.deepEqual(rows.map(row=>[row.sequence,row.outcome]),[[1,'accepted'],[2,'excluded']]); assert.equal(rows[0].identityBlock.events.length,1); assert.equal(rows[1].identityBlock,null); assert.equal(rows[1].reason,'preferred_ineligible');
  const serialized=JSON.stringify(rows); assert.equal(serialized.includes('visible accepted'),false); assert.equal(serialized.includes(JSON.stringify({ignored:true})),false); assert.equal(serialized.includes(Buffer.from('native-raw-accepted').toString('base64')),false); assert.equal(serialized.includes(Buffer.from('native-raw-excluded').toString('base64')),false); assert.doesNotMatch(serialized,/visibleText|normalizedPayloadDigest|integrity/); assert.equal(calls.raw,1); assert.equal(calls.binding,1); assert.equal(calls.audit,1);
});

test('batches every content-free identity block from a Hermes logical-id session collision', async () => {
  const values=[
    value('hermes-one',{sourceKind:'hermes',logicalLabel:'collision',sessionVariant:'one'}),
    value('hermes-two',{sourceKind:'hermes',logicalLabel:'collision',sessionVariant:'two'}),
  ];
  const {source,calls}=await realFixture(values); const rows=[];
  for await (const row of source.open({afterSequence:0,afterCheckpoint:null})) rows.push(row);
  assert.equal(rows.length,1); assert.equal(rows[0].outcome,'accepted');
  assert.equal(rows[0].identityBlock.schema,'amf.m4-cross-phase-projector-identity-block-batch/v1');
  assert.equal(rows[0].identityBlock.blocks.length,2);
  assert.deepEqual(rows[0].identityBlock.blocks.map(item=>item.session.legacySessionId),values.map(item=>item.event.sessionId).sort());
  assert.equal(rows[0].identityBlock.blocks.every(item=>item.events.length===1),true);
  assert.deepEqual(calls,{raw:2,binding:2,audit:2});
  assert.doesNotMatch(JSON.stringify(rows),/visible hermes/);
});

test('validates a resumed checkpoint before yielding a later group', async () => {
  const {source}=await realFixture(); const all=[]; for await (const row of source.open({afterSequence:0,afterCheckpoint:null})) all.push(row);
  const resumed=[]; for await (const row of source.open({afterSequence:1,afterCheckpoint:all[0].checkpoint})) resumed.push(row); assert.deepEqual(resumed.map(row=>row.sequence),[2]);
  let yielded=0; const forged={...all[0].checkpoint,digest:`sha256:${'f'.repeat(64)}`}; await assert.rejects(async()=>{for await (const _ of source.open({afterSequence:1,afterCheckpoint:forged})) yielded+=1;},{code:'m4_cross_phase_identity_traversal_source_drift'}); assert.equal(yielded,0);
});

test('normalizes raw callback failures without returning private error text', async () => {
  const {catalog,baseline}=await realFixture(); const privateText='/private/raw-path secret-token';
  const failing=createM4CrossPhaseIdentityTraversalSource({catalog,rawStore:{async getClientCiphertext(){throw new Error(privateText);}},ingestKeys:KEYS,verifyCatalogBinding:async()=>({}),auditDecrypt:async()=>({}),integrityFor:async()=>({}),catalogBaseline:baseline,catalogKeyDocument:SIGNING,runId:'source-fixture',planDigest:`sha256:${'d'.repeat(64)}`});
  await assert.rejects(()=>drain(failing.open({afterSequence:0,afterCheckpoint:null})),error=>error.code==='m4_cross_phase_identity_traversal_source_envelope_unavailable'&&!error.message.includes(privateText));
});

test('equal-count catalog substitution with a different final chain fails the signed baseline comparison', async () => {
  const {catalog,baseline,ciphertexts}=await realFixture(); const shifted={async listM4V2LogicalGroups(input){const page=structuredClone(await catalog.listM4V2LogicalGroups(input)); page.items[0].observations[0].sourceTag=`catalog-k1:${'c'.repeat(64)}`; return page;}};
  const source=createM4CrossPhaseIdentityTraversalSource({catalog:shifted,rawStore:{async getClientCiphertext(contentId){return structuredClone(ciphertexts.get(contentId));}},ingestKeys:KEYS,verifyCatalogBinding:async()=>({owner:true,source:true}),auditDecrypt:async input=>({recorded:true,eventId:input.eventId,contentId:input.contentId}),integrityFor:async()=>({keyId:'m4-test-k1',key:Buffer.alloc(32,5),sentAt:'2026-07-22T12:00:02Z',nonce:'nonce00000000001'}),catalogBaseline:baseline,catalogKeyDocument:SIGNING,runId:'source-fixture',planDigest:`sha256:${'d'.repeat(64)}`});
  await assert.rejects(()=>drain(source.open({afterSequence:0,afterCheckpoint:null})),{code:'m4_cross_phase_identity_traversal_source_drift'});
});

test('overcount is rejected before decrypting or yielding the excess signed-baseline group', async () => {
  const {catalog,ciphertexts}=await realFixture(); const signed=fixture({coverage:{schema:'amf.m4-cross-phase-identity-streaming-coverage/v1',state:'open',expectedBlockCount:0,blockCount:0,sessionCount:0,eventCount:0},registrySecret:Buffer.alloc(32,7),groupCount:1}); let reads=0; const rows=[];
  const source=createM4CrossPhaseIdentityTraversalSource({catalog,rawStore:{async getClientCiphertext(contentId){reads+=1;return structuredClone(ciphertexts.get(contentId));}},ingestKeys:KEYS,verifyCatalogBinding:async()=>({owner:true,source:true}),auditDecrypt:async input=>({recorded:true,eventId:input.eventId,contentId:input.contentId}),integrityFor:async()=>({keyId:'m4-test-k1',key:Buffer.alloc(32,5),sentAt:'2026-07-22T12:00:02Z',nonce:'nonce00000000001'}),catalogBaseline:signed.input.catalogBaseline,catalogKeyDocument:signed.input.catalogKeyDocument,runId:'source-fixture',planDigest:`sha256:${'d'.repeat(64)}`});
  await assert.rejects(async()=>{for await(const row of source.open({afterSequence:0,afterCheckpoint:null})) rows.push(row);},{code:'m4_cross_phase_identity_traversal_source_drift'}); assert.equal(rows.length,1); assert.equal(reads,1);
});
