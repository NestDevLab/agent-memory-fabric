import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { createM4CrossPhaseIdentityStreamingWriter } from '../src/migration/m4-cross-phase-identity-streaming-writer.mjs';
import { createM4CrossPhaseIdentityTraversalGroupCheckpoint, M4CrossPhaseIdentityTraversalStore } from '../src/migration/m4-cross-phase-identity-traversal-store.mjs';
import { runM4CrossPhaseIdentityTraversal } from '../src/migration/m4-cross-phase-identity-traversal-runner.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId, deriveM4V3SourceInstanceIdFromLegacySession } from '../src/migration/m4-v2-conversation-projector.mjs';
import { digest, fixture } from './helpers/m4-traversal-completion-fixtures.mjs';

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const opaque = `hmac-sha256:test:${hash('opaque')}`;
const tag = `test:${hash('tag')}`;
const block = label => {
  const legacySessionId = `ses_${hash(`session:${label}`)}`; const legacyEventId = `evt_${hash(`event:${label}`)}`;
  const conversationId = deriveM4V3ConversationIdFromLegacySessionId(legacySessionId);
  return { schema:'amf.m4-cross-phase-projector-identity-block/v1', session:{ legacySessionId,conversationId,conversationKind:'dm',sessionContextTags:{conversation:[opaque],room:[opaque]} }, events:[{ legacyEventId,legacySessionId,eventId:deriveM4V3EventIdFromLegacyEventId(legacyEventId),conversationId,sourceInstanceId:deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId,[tag]),sourceTags:[tag],conversationKind:'dm',authorizationContextTags:{sender:[opaque],conversation:[opaque],room:[opaque]},role:'user',direction:'inbound',state:'active',revision:1,replacesLegacyEventId:null,tombstonesLegacyEventId:null,conflictsWithLegacyEventIds:[] }] };
};
function result(sequence, outcome, label = `g${sequence}`) {
  const logicalMessageId = `lmsg_${hash(`logical:${label}`)}`; const identityBlock = outcome === 'accepted' ? block(label) : null;
  const identityBlockDigest = identityBlock === null ? null : digest(identityBlock);
  return { sequence, checkpoint:createM4CrossPhaseIdentityTraversalGroupCheckpoint({sequence,logicalMessageId,outcome,identityBlockDigest}), logicalMessageId,
    outcome,reason:outcome === 'accepted' ? null : 'preferred_ineligible',identityBlock,identityBlockDigest };
}
function source(binding, rows) { return Object.freeze({ binding:Object.freeze(binding), open({afterSequence,afterCheckpoint}) { assert.equal(afterSequence,0); assert.equal(afterCheckpoint,null); return (async function* () { for (const row of rows) yield structuredClone(row); })(); } }); }
function temporary() { return fs.mkdtempSync(path.join(os.tmpdir(),'amf-m4-runner-')); }
function setup(root, rows, { lease = null, events = [], writerCalls = { count:0 }, attestor = null, publish = null, writePage = null, groupCount = rows.length } = {}) {
  const registrySecret=Buffer.alloc(32,7); const item=fixture({coverage:{schema:'amf.m4-cross-phase-identity-streaming-coverage/v1',state:'open',expectedBlockCount:0,blockCount:0,sessionCount:0,eventCount:0},registrySecret,groupCount});
  const runId=item.input.traversalRecord.runId; const planDigest=item.input.traversalRecord.planDigest; const catalogBaselineDigest=digest(item.input.catalogBaseline);
  const store=new M4CrossPhaseIdentityTraversalStore({rootPath:path.join(root,'state'),runId,planDigest,catalogBaselineDigest});
  const activeLease=lease ?? { async acquire(){events.push('acquire');},async heartbeat(){events.push('heartbeat');},async release(){events.push('release');} };
  return { store, input:{ source:source({runId,planDigest,catalogBaselineDigest,groupCount},rows),traversalStore:store,lease:activeLease,runId,planDigest,
    catalogBaseline:item.input.catalogBaseline,catalogKeyDocument:item.input.catalogKeyDocument,archiveCompletion:item.input.archiveCompletion,archiveCompletionKeyDocument:item.input.archiveCompletionKeyDocument,
    completionKeyDocument:item.input.completionKeyDocument,registryKeyDocument:item.input.registryKeyDocument,manifestId:'runner-fixture',revision:1,registrySecret,registryKeyId:item.registryKeyId,
    catalogAttestor:attestor ?? (async()=>{events.push('attest');return structuredClone(item.input.catalogBaseline);}),
    createWriter:async ({expectedBlockCount,firstBlock})=>{writerCalls.count+=1; assert.equal(expectedBlockCount,groupCount); const databasePath=path.join(root,'private','identity.sqlite'); return {databasePath,writer:createM4CrossPhaseIdentityStreamingWriter({databasePath,registrySecret:Buffer.alloc(32,7),registryKeyId:item.registryKeyId,capacityPreflight:{availableBytes:5*1024*1024*1024,sampleBlocks:[firstBlock],expectedBlockCount},pageSink:{writePage:writePage ?? (async page=>({pageKey:page.pageKey,digest:page.digest}))}})};},
    publish:publish ?? (async value=>{events.push('publish'); assert.deepEqual(Object.keys(value).sort(),['coverage','registry','traversalCompletion']); return {state:'published',artifactDigest:`sha256:${'a'.repeat(64)}`};})
  }};
}

test('all-excluded traversal never opens a writer and creates a deterministic empty authority', async () => {
  const root=temporary(); const calls={count:0}; const events=[];
  try { const prepared=setup(root,[result(1,'excluded'),result(2,'excluded')],{writerCalls:calls,events}); const original=Buffer.from(prepared.input.registrySecret); const output=await runM4CrossPhaseIdentityTraversal(prepared.input);
    assert.equal(calls.count,0); assert.equal(output.databasePath,null); assert.equal(output.publication.state,'published'); assert.equal(output.coverage.blockCount,0); assert.deepEqual(prepared.input.registrySecret,original); assert.deepEqual(events,['acquire','attest','heartbeat','heartbeat','attest','heartbeat','heartbeat','attest','heartbeat','publish','release']);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('restart rescans and validates the committed prefix, reopens one existing writer, then drains excluded tail', async () => {
  const root=temporary(); const calls={count:0};
  try {
    const accepted=result(1,'accepted'); const excluded=result(2,'excluded'); const first=setup(root,[accepted],{writerCalls:calls,groupCount:2});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(first.input),{code:'m4_cross_phase_identity_traversal_runner_store_failed'});
    assert.equal(first.store.load().sequence,1); first.store.close();
    const second=setup(root,[accepted,excluded],{writerCalls:calls}); const output=await runM4CrossPhaseIdentityTraversal(second.input);
    assert.equal(calls.count,2); assert.equal(output.traversalRecord.acceptedGroupCount,1); assert.equal(output.traversalRecord.excludedGroupCount,1); assert.equal(output.coverage.blockCount,1); assert.equal(output.databasePath.endsWith('identity.sqlite'),true); assert.equal(output.writer,undefined); second.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('normalizes a competing lease and performs no source, writer, or store work', async () => {
  const root=temporary(); let sourceOpened=0; const calls={count:0};
  try { const prepared=setup(root,[result(1,'excluded')],{writerCalls:calls,lease:{async acquire(){throw new Error('/private/lease');},async heartbeat(){},async release(){}}}); prepared.input.source={...prepared.input.source,open(){sourceOpened+=1;throw new Error('unreachable');}};
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_lease_failed'}); assert.equal(sourceOpened,0); assert.equal(calls.count,0); assert.equal(prepared.store.load().sequence,0); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('attestation drift is rejected before source traversal and lease release still runs', async () => {
  const root=temporary(); const events=[];
  try { const prepared=setup(root,[result(1,'excluded')],{events,attestor:async()=>({})});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_attestation_failed'}); assert.deepEqual(events,['acquire','release']); assert.equal(prepared.store.load().sequence,0); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('an accept-before-store crash leaves one bounded orphan that retry catches up exactly', async () => {
  const root=temporary(); const calls={count:0};
  try { const accepted=result(1,'accepted'); const excluded=result(2,'excluded'); const prepared=setup(root,[accepted,excluded],{writerCalls:calls});
    const orphan=await prepared.input.createWriter({expectedBlockCount:2,firstBlock:accepted.identityBlock}); assert.equal(orphan.writer.accept(accepted.identityBlock).accepted,true); orphan.writer.close();
    const output=await runM4CrossPhaseIdentityTraversal(prepared.input); assert.equal(calls.count,2); assert.equal(output.traversalRecord.acceptedGroupCount,1); assert.equal(output.coverage.blockCount,1); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('invalid checkpoint or identity digest is rejected before a writer can mutate the spool', async () => {
  const root=temporary(); const calls={count:0};
  try { const bad=result(1,'accepted'); bad.checkpoint={...bad.checkpoint,digest:`sha256:${'f'.repeat(64)}`}; const prepared=setup(root,[bad],{writerCalls:calls});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_source_invalid'}); assert.equal(calls.count,0); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('post-traversal attestation failure releases the lease after durable traversal', async () => {
  const root=temporary(); const events=[]; let calls=0;
  try { const prepared=setup(root,[result(1,'excluded')],{events,attestor:async()=>{calls+=1; events.push(`attest-${calls}`); return calls===1 ? structuredClone(prepared.input.catalogBaseline) : {};}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_attestation_failed'}); assert.equal(prepared.store.load().complete,true); assert.equal(events.at(-1),'release'); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('heartbeat failure precedes writer and checkpoint mutation for the current group', async () => {
  const root=temporary(); const calls={count:0}; let released=0;
  try { const prepared=setup(root,[result(1,'accepted')],{writerCalls:calls,lease:{async acquire(){},async heartbeat(){throw new Error('expired');},async release(){released+=1;}}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_lease_heartbeat_failed'}); assert.equal(calls.count,0); assert.equal(prepared.store.load().sequence,0); assert.equal(released,1); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('out-of-order source row is rejected before heartbeat, writer, or checkpoint mutation', async () => {
  const root=temporary(); const calls={count:0}; let heartbeats=0;
  try { const bad=result(2,'accepted'); const prepared=setup(root,[bad],{writerCalls:calls,lease:{async acquire(){},async heartbeat(){heartbeats+=1;},async release(){}}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_source_invalid'}); assert.equal(heartbeats,0); assert.equal(calls.count,0); assert.equal(prepared.store.load().sequence,0); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('durable prefix drift is rejected before the writer factory is reached', async () => {
  const root=temporary(); const calls={count:0};
  try { const accepted=result(1,'accepted'); const changed=result(1,'excluded'); const prepared=setup(root,[changed],{writerCalls:calls}); prepared.store.commit({sequence:1,checkpoint:accepted.checkpoint,logicalMessageId:accepted.logicalMessageId,outcome:accepted.outcome,identityBlockDigest:accepted.identityBlockDigest});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_prefix_drift'}); assert.equal(calls.count,0); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('a pending orphan cannot be followed by an excluded group', async () => {
  const root=temporary(); const calls={count:0};
  try { const first=result(1,'accepted'); const orphan=result(2,'accepted'); const excluded=result(2,'excluded'); const prepared=setup(root,[first,excluded],{writerCalls:calls}); prepared.store.commit({sequence:1,checkpoint:first.checkpoint,logicalMessageId:first.logicalMessageId,outcome:first.outcome,identityBlockDigest:first.identityBlockDigest});
    const spool=await prepared.input.createWriter({expectedBlockCount:2,firstBlock:first.identityBlock}); spool.writer.accept(first.identityBlock); spool.writer.accept(orphan.identityBlock); spool.writer.close();
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_prefix_drift'}); assert.equal(prepared.store.load().sequence,1); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('publication runs under lease after final attestation and before writer close/release', async () => {
  const root=temporary(); const events=[];
  try { const prepared=setup(root,[result(1,'accepted')],{events}); const original=prepared.input.createWriter; prepared.input.createWriter=async input=>{const made=await original(input); const writer=made.writer; return {...made,writer:{accept:writer.accept.bind(writer),seal:writer.seal.bind(writer),close(){events.push('close');return writer.close();}}};};
    await runM4CrossPhaseIdentityTraversal(prepared.input); assert.ok(events.indexOf('publish')<events.indexOf('close')); assert.ok(events.indexOf('close')<events.indexOf('release')); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('post-seal catalog drift blocks publication and still closes/releases', async () => {
  const root=temporary(); const events=[]; let attests=0;
  try { const alternate=fixture({coverage:{schema:'amf.m4-cross-phase-identity-streaming-coverage/v1',state:'open',expectedBlockCount:0,blockCount:0,sessionCount:0,eventCount:0},registrySecret:Buffer.alloc(32,7),groupCount:1,coveredThrough:'2026-07-23T00:00:00Z'}); const prepared=setup(root,[result(1,'accepted')],{events,attestor:async()=>{attests+=1;return attests===3?structuredClone(alternate.input.catalogBaseline):structuredClone(prepared.input.catalogBaseline);}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_catalog_drift'}); assert.equal(events.includes('publish'),false); assert.equal(events.at(-1),'release'); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('hostile or failed publication cannot bypass close and lease release', async () => {
  const root=temporary(); const events=[];
  try { const prepared=setup(root,[result(1,'accepted')],{events,publish:async()=>({state:'published',get artifactDigest(){throw new Error('private');}})});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(prepared.input),{code:'m4_cross_phase_identity_traversal_runner_publish_invalid'}); assert.equal(events.at(-1),'release'); prepared.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('retry after sealed publication failure reopens, reseals, and republishes idempotently', async () => {
  const root=temporary(); const row=result(1,'accepted'); const firstEvents=[]; const secondEvents=[];
  try { const first=setup(root,[row],{events:firstEvents,publish:async()=>{throw new Error('publish interrupted');}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(first.input),{code:'m4_cross_phase_identity_traversal_runner_publish_failed'}); assert.equal(first.store.load().complete,true); first.store.close();
    const second=setup(root,[row],{events:secondEvents}); const output=await runM4CrossPhaseIdentityTraversal(second.input);
    assert.equal(output.publication.state,'published'); assert.equal(secondEvents.includes('publish'),true); assert.equal(secondEvents.at(-1),'release'); second.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('retry after seal-intent page failure resumes the matching seal and publishes', async () => {
  const root=temporary(); const row=result(1,'accepted'); let failedPages=0; let recoveredPages=0;
  try { const first=setup(root,[row],{writePage:async()=>{failedPages+=1; throw new Error('page interrupted');}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(first.input),{code:'m4_cross_phase_identity_traversal_runner_seal_failed'}); assert.equal(first.store.load().complete,true); assert.ok(failedPages>0); first.store.close();
    const second=setup(root,[row],{writePage:async page=>{recoveredPages+=1; return {pageKey:page.pageKey,digest:page.digest};}}); const output=await runM4CrossPhaseIdentityTraversal(second.input);
    assert.equal(output.publication.state,'published'); assert.ok(recoveredPages>0); second.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('sealed retry with a different re-derived completion binding fails distinctly without publishing', async () => {
  const root=temporary(); const row=result(1,'accepted'); let publishCalls=0;
  try { const first=setup(root,[row],{publish:async()=>{throw new Error('publish interrupted');}});
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(first.input),{code:'m4_cross_phase_identity_traversal_runner_publish_failed'}); first.store.close();
    const second=setup(root,[row],{publish:async()=>{publishCalls+=1; throw new Error('must not publish');}}); second.input.completionKeyDocument={...second.input.completionKeyDocument,key:Buffer.alloc(32,99).toString('base64')};
    await assert.rejects(()=>runM4CrossPhaseIdentityTraversal(second.input),{code:'m4_cross_phase_identity_traversal_runner_seal_binding_invalid'}); assert.equal(publishCalls,0); second.store.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
