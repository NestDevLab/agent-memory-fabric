import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { describeM4CrossPhaseIdentityPage } from '../migration/m4-cross-phase-identity-registry.mjs';
import { validateArtifactRoot } from './private-artifacts.mjs';

const ID=/^[a-z][a-z0-9-]{2,79}$/; const DIGEST=/^sha256:[a-f0-9]{64}$/; const MAX=8*1024*1024;
function fail(code){const error=new Error(code);error.code=code;throw error;}
function exact(v,k){return v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===k.length&&k.every(x=>Object.hasOwn(v,x));}
function clone(v,code){try{return structuredClone(v);}catch{fail(code);}}
function owner(stat,code){if(!stat.isDirectory()&&!stat.isFile())fail(code);if(BigInt(stat.uid)!==BigInt(process.getuid())||(Number(stat.mode)&0o077)!==0)fail(code);}
function directory(root,relative,code){let current=root;for(const part of relative.split('/')){current=path.join(current,part);try{fs.mkdirSync(current,{mode:0o700});}catch(error){if(error?.code!=='EEXIST')fail(code);}let stat;try{stat=fs.lstatSync(current);}catch{fail(code);}if(stat.isSymbolicLink()||!stat.isDirectory())fail(code);owner(stat,code);}return current;}
function filename(pageKey){return `${crypto.createHash('sha256').update(canonicalJson(['amf.m4-cross-phase-identity-page-store/v1',pageKey]),'utf8').digest('hex')}.json`;}
function page(value){const safe=clone(value,'m4_cross_phase_identity_page_store_page_invalid');let descriptor;try{descriptor=describeM4CrossPhaseIdentityPage(safe);}catch{fail('m4_cross_phase_identity_page_store_page_invalid');}if(descriptor.pageKey!==safe.pageKey||descriptor.digest!==safe.digest||!DIGEST.test(safe.digest))fail('m4_cross_phase_identity_page_store_page_invalid');return safe;}
function read(target,code){let fd;try{fd=fs.openSync(target,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);const opened=fs.fstatSync(fd,{bigint:true});if(!opened.isFile()||opened.nlink!==1n||opened.size<2n||opened.size>BigInt(MAX))fail(code);owner(opened,code);const identity={dev:opened.dev,ino:opened.ino,size:opened.size,mtimeNs:opened.mtimeNs,ctimeNs:opened.ctimeNs,nlink:opened.nlink};const bytes=fs.readFileSync(fd);const after=fs.fstatSync(fd,{bigint:true});for(const key of Object.keys(identity))if(after[key]!==identity[key])fail(code);return JSON.parse(bytes.toString('utf8'));}catch(error){if(error?.code===code)throw error;fail(code);}finally{if(fd!==undefined)try{fs.closeSync(fd);}catch{}}}

export function openM4CrossPhaseIdentityPageReader(input = {}) {
  if (!exact(input, ['artifactRoot', 'manifestId', 'revision'])) fail('m4_cross_phase_identity_page_reader_input_invalid');
  const root = validateArtifactRoot(input.artifactRoot, 'm4_cross_phase_identity_page_reader_input_invalid');
  if (!ID.test(input.manifestId) || !Number.isSafeInteger(input.revision) || input.revision < 1) fail('m4_cross_phase_identity_page_reader_input_invalid');
  let target = root; let expected;
  try {
    for (const component of ['m4', 'cross-phase-identity-pages', `${input.manifestId}-r${input.revision}`]) {
      target = path.join(target, component);
      const stat = fs.lstatSync(target, { bigint: true });
      if (stat.isSymbolicLink() || !stat.isDirectory()) fail('m4_cross_phase_identity_page_reader_unsafe');
      owner(stat, 'm4_cross_phase_identity_page_reader_unsafe');
      expected = { dev: stat.dev, ino: stat.ino };
    }
  } catch (error) {
    if (error?.code?.startsWith?.('m4_cross_phase_identity_')) throw error;
    fail('m4_cross_phase_identity_page_reader_unsafe');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isDirectory() || opened.dev !== expected.dev || opened.ino !== expected.ino) fail('m4_cross_phase_identity_page_reader_unsafe');
    owner(opened, 'm4_cross_phase_identity_page_reader_unsafe');
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error?.code?.startsWith?.('m4_cross_phase_identity_')) throw error;
    fail('m4_cross_phase_identity_page_reader_unsafe');
  }
  let closed = false; const child = name => `/proc/self/fd/${descriptor}/${name}`;
  return Object.freeze({
    loadPage(inputDescriptor) {
      if (closed) fail('m4_cross_phase_identity_page_reader_closed');
      const safe = clone(inputDescriptor, 'm4_cross_phase_identity_page_reader_descriptor_invalid');
      if (!exact(safe, ['pageKey', 'digest']) || typeof safe.pageKey !== 'string' || !DIGEST.test(safe.digest)) fail('m4_cross_phase_identity_page_reader_descriptor_invalid');
      let stored;
      try { stored = page(read(child(filename(safe.pageKey)), 'm4_cross_phase_identity_page_reader_invalid')); }
      catch { fail('m4_cross_phase_identity_page_reader_invalid'); }
      if (stored.pageKey !== safe.pageKey || stored.digest !== safe.digest) fail('m4_cross_phase_identity_page_reader_invalid');
      return clone(stored, 'm4_cross_phase_identity_page_reader_invalid');
    },
    close() { if (!closed) { closed = true; fs.closeSync(descriptor); } },
  });
}

export function createM4CrossPhaseIdentityPageStore(input={}){
 if(!exact(input,['artifactRoot','manifestId','revision']))fail('m4_cross_phase_identity_page_store_input_invalid');const root=validateArtifactRoot(input.artifactRoot,'m4_cross_phase_identity_page_store_input_invalid');if(!ID.test(input.manifestId)||!Number.isSafeInteger(input.revision)||input.revision<1)fail('m4_cross_phase_identity_page_store_input_invalid');const relative=`m4/cross-phase-identity-pages/${input.manifestId}-r${input.revision}`;const rootDirectory=directory(root,relative,'m4_cross_phase_identity_page_store_unsafe');let directoryFd;try{directoryFd=fs.openSync(rootDirectory,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);const stat=fs.fstatSync(directoryFd);if(!stat.isDirectory())fail('m4_cross_phase_identity_page_store_unsafe');owner(stat,'m4_cross_phase_identity_page_store_unsafe');}catch(error){if(directoryFd!==undefined)try{fs.closeSync(directoryFd);}catch{}if(error?.code?.startsWith?.('m4_cross_phase_identity_page_store_'))throw error;fail('m4_cross_phase_identity_page_store_unsafe');}let closed=false;const child=name=>`/proc/self/fd/${directoryFd}/${name}`;
 return Object.freeze({describe(){return Object.freeze({schema:'amf.m4-cross-phase-identity-page-store/v1',manifestId:input.manifestId,revision:input.revision});},close(){if(!closed){fs.closeSync(directoryFd);closed=true;}},verifyPage(descriptor){if(closed)fail('m4_cross_phase_identity_page_store_closed');const safe=clone(descriptor,'m4_cross_phase_identity_page_store_descriptor_invalid');if(!exact(safe,['pageKey','digest'])||typeof safe.pageKey!=='string'||!DIGEST.test(safe.digest))fail('m4_cross_phase_identity_page_store_descriptor_invalid');let stored;try{stored=page(read(child(filename(safe.pageKey)),'m4_cross_phase_identity_page_store_existing_invalid'));}catch(error){if(error?.code?.startsWith?.('m4_cross_phase_identity_page_store_'))throw error;fail('m4_cross_phase_identity_page_store_existing_invalid');}if(stored.pageKey!==safe.pageKey||stored.digest!==safe.digest)fail('m4_cross_phase_identity_page_store_existing_invalid');return Object.freeze({pageKey:safe.pageKey,digest:safe.digest});},async writePage(inputPage){if(closed)fail('m4_cross_phase_identity_page_store_closed');const safe=page(inputPage);const name=filename(safe.pageKey);const target=child(name);const bytes=Buffer.from(`${canonicalJson(safe)}\n`,'utf8');if(bytes.length>MAX)fail('m4_cross_phase_identity_page_store_page_invalid');let temporary;let fd;try{temporary=`.${crypto.randomUUID()}.tmp`;fd=fs.openSync(child(temporary),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;try{fs.linkSync(child(temporary),target);}catch(error){if(error?.code!=='EEXIST')throw error;const existing=page(read(target,'m4_cross_phase_identity_page_store_existing_invalid'));if(canonicalJson(existing)!==canonicalJson(safe))fail('m4_cross_phase_identity_page_store_conflict');}fs.unlinkSync(child(temporary));temporary=null;fs.fsyncSync(directoryFd);return Object.freeze({pageKey:safe.pageKey,digest:safe.digest});}catch(error){if(fd!==undefined)try{fs.closeSync(fd);}catch{}if(temporary!==null)try{fs.unlinkSync(child(temporary));}catch{}if(error?.code?.startsWith?.('m4_cross_phase_identity_page_store_'))throw error;fail('m4_cross_phase_identity_page_store_write_failed');}}});
}
