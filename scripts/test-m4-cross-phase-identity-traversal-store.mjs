import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createM4CrossPhaseIdentityTraversalGroupCheckpoint, M4CrossPhaseIdentityTraversalStore } from '../src/migration/m4-cross-phase-identity-traversal-store.mjs';

const digest=value=>`sha256:${crypto.createHash('sha256').update(String(value)).digest('hex')}`;
const binding={runId:'traversal-run-test',planDigest:digest('plan'),catalogBaselineDigest:digest('catalog')};
const logical=index=>`lmsg_${crypto.createHash('sha256').update(`logical:${index}`).digest('hex')}`;
const group=(sequence,outcome='accepted')=>{ const value={sequence,logicalMessageId:logical(sequence),outcome,identityBlockDigest:outcome==='accepted'?digest(`block:${sequence}`):null}; return {...value,checkpoint:createM4CrossPhaseIdentityTraversalGroupCheckpoint(value)}; };
function root(){ return fs.mkdtempSync(path.join(os.tmpdir(),'amf-m4-traversal-store-')); }
function open(rootPath){ return new M4CrossPhaseIdentityTraversalStore({rootPath,...binding}); }
function name(rootPath){ const value=fs.readdirSync(rootPath).find(item=>/^m4-cross-phase-identity-traversal-[a-f0-9]{64}\.json$/.test(item)); assert.ok(value); return value; }
function code(fn,expected){ assert.throws(fn,error=>error?.code===expected); }

test('persists contiguous content-free traversal results and completes deterministically after restart',()=>{
  const rootPath=root(); let store=open(rootPath);
  try {
    assert.equal(store.load().sequence,0); store.commit(group(1)); store.commit(group(2,'excluded')); const before=store.load();
    assert.equal(before.acceptedGroupCount,1); assert.equal(before.excludedGroupCount,1); assert.equal(before.record,null); store.close(); store=open(rootPath);
    assert.deepEqual(store.commit(group(2,'excluded')),group(2,'excluded')); const record=store.complete({expectedGroupCount:2}); assert.deepEqual(store.complete({expectedGroupCount:2}),record); assert.equal(record.acceptedGroupCount,1); assert.equal(record.excludedGroupCount,1); assert.deepEqual(store.load().record,record);
    const contents=fs.readFileSync(path.join(rootPath,name(rootPath)),'utf8'); for(const forbidden of ['visibleText','ciphertext','projection','raw transcript','credential']) assert.equal(contents.includes(forbidden),false); assert.equal(fs.statSync(path.join(rootPath,name(rootPath))).mode&0o777,0o600);
  } finally { store.close(); fs.rmSync(rootPath,{recursive:true,force:true}); }
});

test('rejects gaps, drift, outcome mismatch, count mismatch, and commits after completion',()=>{
  const rootPath=root(); const store=open(rootPath);
  try {
    code(()=>store.commit(group(2)),'m4_cross_phase_identity_traversal_store_gap'); store.commit(group(1)); code(()=>store.commit(group(1,'excluded')),'m4_cross_phase_identity_traversal_store_drift'); code(()=>store.commit({...group(2,'accepted'),identityBlockDigest:null}),'m4_cross_phase_identity_traversal_store_group_invalid'); const checkpointDrift={...group(2),checkpoint:{...group(2).checkpoint,digest:digest('wrong')}}; code(()=>store.commit(checkpointDrift),'m4_cross_phase_identity_traversal_store_group_invalid'); code(()=>store.complete({expectedGroupCount:2}),'m4_cross_phase_identity_traversal_store_completion_invalid'); code(()=>store.complete({expectedGroupCount:2_000_001}),'m4_cross_phase_identity_traversal_store_completion_invalid'); store.complete({expectedGroupCount:1}); code(()=>store.commit(group(2)),'m4_cross_phase_identity_traversal_store_complete');
  } finally { store.close(); fs.rmSync(rootPath,{recursive:true,force:true}); }
});

test('recovers torn temporaries and fails closed on corrupt, symlink, and public state',()=>{
  const rootPath=root(); let store=open(rootPath);
  try {
    store.commit(group(1)); const state=path.join(rootPath,name(rootPath)); store.close(); const temp=path.join(rootPath,`.${name(rootPath)}.12345678-1234-1234-1234-123456789abc.tmp`); fs.writeFileSync(temp,'{torn',{mode:0o600}); store=open(rootPath); assert.equal(fs.existsSync(temp),false); fs.chmodSync(state,0o644); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_unsafe'); store.close(); fs.chmodSync(state,0o600); fs.writeFileSync(state,'{bad',{mode:0o600}); store=open(rootPath); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_corrupt'); store.close(); fs.unlinkSync(state); fs.symlinkSync('/dev/null',state); store=open(rootPath); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_unsafe');
  } finally { store.close(); fs.rmSync(rootPath,{recursive:true,force:true}); }
});

test('fails closed on valid-shaped checkpoint, count, and sequence-bound corruption',()=>{
  const rootPath=root(); let store=open(rootPath);
  try {
    store.commit(group(1)); const state=path.join(rootPath,name(rootPath)); store.close(); const original=JSON.parse(fs.readFileSync(state,'utf8'));
    const checkpointDrift=structuredClone(original); checkpointDrift.checkpoint.id=`m4id-${digest('other').slice(7)}`; fs.writeFileSync(state,JSON.stringify(checkpointDrift),{mode:0o600}); store=open(rootPath); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_corrupt'); store.close();
    const countDrift=structuredClone(original); countDrift.acceptedGroupCount=2; fs.writeFileSync(state,JSON.stringify(countDrift),{mode:0o600}); store=open(rootPath); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_corrupt'); store.close();
    const boundDrift=structuredClone(original); boundDrift.sequence=2_000_001; boundDrift.acceptedGroupCount=2_000_001; fs.writeFileSync(state,JSON.stringify(boundDrift),{mode:0o600}); store=open(rootPath); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_corrupt');
  } finally { store.close(); fs.rmSync(rootPath,{recursive:true,force:true}); }
});

test('rejects public and symlink roots and supports idempotent close',()=>{
  const rootPath=root(); try { fs.chmodSync(rootPath,0o755); code(()=>open(rootPath),'m4_cross_phase_identity_traversal_store_unsafe'); } finally { fs.rmSync(rootPath,{recursive:true,force:true}); }
  const parent=root(); try { const target=path.join(parent,'target'); fs.mkdirSync(target,{mode:0o700}); const link=path.join(parent,'link'); fs.symlinkSync(target,link); code(()=>open(link),'m4_cross_phase_identity_traversal_store_unsafe'); } finally { fs.rmSync(parent,{recursive:true,force:true}); }
  const clean=root(); const store=open(clean); store.close(); store.close(); code(()=>store.load(),'m4_cross_phase_identity_traversal_store_closed'); fs.rmSync(clean,{recursive:true,force:true});
});
