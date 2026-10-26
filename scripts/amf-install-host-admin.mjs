#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { validateHostAdminConfig } from '../src/host-admin-server.mjs';

const CODE_PATHS = ['src/host-file-catalog.mjs','src/host-admin-server.mjs','scripts/amf-host-admin.mjs'];
const TEMPLATE = 'deploy/systemd/amf-host-admin.service.in';
const UNIT = 'amf-host-admin.service';
const MAX_BYTES = 1024 * 1024;
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value && !/[\x00-\x1f\x7f]/.test(value);
const within = (filename,root) => filename.startsWith(`${root}/`);
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
const fail = code => { throw new Error(code); };

// Descriptor-relative operations pin every ancestor and refuse symlinks.
function at(filename, callback, { create=false }={}) {
  const parts=filename.split('/').filter(Boolean), leaf=parts.pop();
  let fd=fs.openSync('/',fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    for(const part of parts) {
      const target=`/proc/self/fd/${fd}/${part}`;
      let next;
      try { next=fs.openSync(target,fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); }
      catch(error) {
        if(error.code!=='ENOENT' || !create) throw error;
        fs.mkdirSync(target,{mode:0o700});
        next=fs.openSync(target,fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      }
      fs.closeSync(fd); fd=next;
    }
    return callback(leaf ? `/proc/self/fd/${fd}/${leaf}` : `/proc/self/fd/${fd}/.`);
  } finally { fs.closeSync(fd); }
}
function directory(filename,{create=false,privateRequired=true,ownedRequired=false}={}) {
  try {
    return at(filename,target=>{
      let stat;
      try { stat=fs.lstatSync(target); }
      catch(error) { if(error.code!=='ENOENT' || !create) throw error; fs.mkdirSync(target,{mode:0o700});stat=fs.lstatSync(target); }
      if(!stat.isDirectory() || stat.isSymbolicLink() || (privateRequired && (stat.uid!==process.getuid() || (stat.mode & 0o077))) || (ownedRequired && (stat.uid!==process.getuid() || (stat.mode & 0o022)))) fail('unsafe_install_directory');
      return true;
    },{create});
  } catch(error) { if(error.code==='ENOENT' && !create) return false; throw error; }
}
function readFile(filename,{privateRequired=false,optional=false,maxBytes=MAX_BYTES}={}) {
  try {
    return at(filename,target=>{
      const fd=fs.openSync(target,fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
      try {
        const stat=fs.fstatSync(fd,{bigint:true});
        if(!stat.isFile() || stat.nlink!==1n || stat.uid!==BigInt(process.getuid()) || (stat.mode & BigInt(privateRequired ? 0o077 : 0o022)) || stat.size>BigInt(maxBytes)) fail('unsafe_install_file');
        const buffer=Buffer.alloc(maxBytes+1); const length=fs.readSync(fd,buffer,0,buffer.length,0);
        const after=fs.fstatSync(fd,{bigint:true});
        if(BigInt(length)!==stat.size || after.size!==stat.size || after.mtimeNs!==stat.mtimeNs || after.ctimeNs!==stat.ctimeNs) fail('install_file_changed');
        return buffer.subarray(0,length);
      } finally { fs.closeSync(fd); }
    });
  } catch(error) { if(optional && error.code==='ENOENT') return null; throw error; }
}
function json(bytes) { try { return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); } catch { fail('invalid_install_json'); } }
function git(repo,args) { return execFileSync('git',args,{cwd:repo,encoding:null,maxBuffer:4*MAX_BYTES,stdio:['ignore','pipe','pipe'],env:{...process.env,GIT_OPTIONAL_LOCKS:'0'}}); }
function tokenState(filename) {
  try {
    return at(filename,target=>{
      const stat=fs.lstatSync(target,{bigint:true});
      if(!stat.isFile() || stat.nlink!==1n || stat.uid!==BigInt(process.getuid()) || (stat.mode & 0o077n) || stat.size<32n || stat.size>512n) fail('unsafe_token_file');
      // Never open, hash, serialize or return the token bytes.
      return {present:true,device:String(stat.dev),inode:String(stat.ino),size:Number(stat.size),mtimeNs:String(stat.mtimeNs),ctimeNs:String(stat.ctimeNs)};
    });
  } catch(error) { if(error.code==='ENOENT') return {present:false}; throw error; }
}
function validatePolicy(policy) {
  if(!plain(policy) || policy.schema!=='amf.host-file-catalog-policy/v1' || typeof policy.hostId!=='string' || !policy.hostId) fail('invalid_catalog_policy');
  for(const key of ['roots','excludePrefixes','metadataOnlyPrefixes']) if(!Array.isArray(policy[key]) || policy[key].some(value=>!absolute(value))) fail('invalid_catalog_policy');
  if(!policy.roots.length || !Array.isArray(policy.domains) || !plain(policy.content) || typeof policy.content.enabled!=='boolean' || !Number.isSafeInteger(policy.content.maxBytes) || policy.content.maxBytes<1 || policy.content.maxBytes>10*MAX_BYTES || !Array.isArray(policy.content.extensions) || policy.content.extensions.some(value=>typeof value!=='string' || !/^\.[a-z0-9]+$/i.test(value))) fail('invalid_catalog_policy');
  if(policy.limits!==undefined && (!plain(policy.limits) || (policy.limits.maxDirectoryEntries!==undefined && (!Number.isSafeInteger(policy.limits.maxDirectoryEntries) || policy.limits.maxDirectoryEntries<1 || policy.limits.maxDirectoryEntries>1000000)))) fail('invalid_catalog_policy');
  if(policy.metadataOnlyDirectoryNames!==undefined && (!Array.isArray(policy.metadataOnlyDirectoryNames) || policy.metadataOnlyDirectoryNames.some(name=>typeof name!=='string' || !/^[A-Za-z0-9._-]{1,255}$/.test(name) || name==='.' || name==='..'))) fail('invalid_catalog_policy');
  const ids=new Set();
  for(const domain of policy.domains) {
    if(!plain(domain) || typeof domain.id!=='string' || !domain.id || ids.has(domain.id) || !Array.isArray(domain.prefixes) || domain.prefixes.some(prefix=>!absolute(prefix)) || (domain.destination && !absolute(domain.destination))) fail('invalid_catalog_policy');
    ids.add(domain.id);
  }
  for(const virtual of ['/proc','/sys','/dev']) if(policy.roots.some(root=>root==='/' || root===virtual || within(root,virtual) || within(virtual,root)) && !policy.excludePrefixes.some(prefix=>prefix==='/' || prefix===virtual || within(virtual,prefix))) fail('virtual_filesystem_exclusion_required');
}
function validateTemplate(template) {
  const required={
    'Unit/After':'network.target',
    'Service/Type':'simple','Service/WorkingDirectory':'@RELEASE@',
    'Service/ExecStart':'@NODE@ @ENTRY@ --config @CONFIG@','Service/Restart':'on-failure',
    'Service/RestartSec':'5s','Service/NoNewPrivileges':'true','Service/UMask':'0077',
    'Install/WantedBy':'default.target'
  };
  const found=new Set();let section='';
  for(const line of template.split(/\r?\n/).map(value=>value.trim()).filter(value=>value && !value.startsWith('#'))) {
    if(/^\[(Unit|Service|Install)\]$/.test(line)) {section=line.slice(1,-1);continue;}
    const equal=line.indexOf('='),key=`${section}/${line.slice(0,equal)}`,value=line.slice(equal+1);
    if(equal<1 || found.has(key) || (key==='Unit/Description' ? !value : required[key]!==value)) fail('unit_template_invalid');
    found.add(key);
  }
  if(Object.keys(required).some(key=>!found.has(key))) fail('unit_template_invalid');
}
const quote = value => `"${value.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')}"`;
function build(options) {
  const {repo,revision,runtimeRoot,configSource,policySource,unitDirectory}=options;
  if(Number(process.versions.node.split('.')[0])<24) fail('node_24_required');
  for(const value of [repo,runtimeRoot,configSource,policySource,unitDirectory]) if(!absolute(value) || value==='/') fail('absolute_install_paths_required');
  if(!/^[a-f0-9]{40}$/.test(revision ?? '')) fail('exact_git_revision_required');
  directory(repo,{privateRequired:false});
  if(git(repo,['rev-parse','--show-toplevel']).toString().trim()!==repo || git(repo,['rev-parse',`${revision}^{commit}`]).toString().trim()!==revision) fail('git_revision_invalid');
  directory(runtimeRoot);directory(unitDirectory,{privateRequired:false,ownedRequired:true});
  if(within(unitDirectory,runtimeRoot) || within(runtimeRoot,unitDirectory) || unitDirectory===runtimeRoot) fail('overlapping_install_roots');
  const configBytes=readFile(configSource),policyBytes=readFile(policySource);
  const config=json(configBytes); validateHostAdminConfig(config);
  const policy=json(policyBytes); validatePolicy(policy);
  const configPath=path.join(runtimeRoot,'config.json'), policyPath=path.join(runtimeRoot,'catalog-policy.json'), manifestPath=path.join(runtimeRoot,'.installation.json');
  const release=path.join(runtimeRoot,'releases',revision),unitPath=path.join(unitDirectory,UNIT);
  if(config.policyPath!==policyPath || !absolute(config.tokenFile) || !within(config.tokenFile,runtimeRoot) || !absolute(config.databasePath) || !within(config.databasePath,path.join(runtimeRoot,'database'))) fail('runtime_config_path_forbidden');
  if([configPath,policyPath,manifestPath].some(filename=>filename===config.tokenFile || within(config.tokenFile,filename)) || within(config.tokenFile,path.join(runtimeRoot,'releases')) || within(config.tokenFile,path.join(runtimeRoot,'database')) || config.tokenFile===path.join(runtimeRoot,'releases') || config.tokenFile===path.join(runtimeRoot,'database')) fail('token_path_forbidden');
  const material=new Map(),blobs={};
  for(const source of [...CODE_PATHS,TEMPLATE]) {
    const mode=git(repo,['ls-tree',revision,'--',source]).toString().split(' ')[0];
    if(!['100644','100755'].includes(mode)) fail('git_source_mode_invalid');
    const blob=git(repo,['rev-parse',`${revision}:${source}`]).toString().trim();
    if(!/^[a-f0-9]{40}$/.test(blob) || git(repo,['cat-file','-t',blob]).toString().trim()!=='blob') fail('git_source_blob_invalid');
    const bytes=git(repo,['cat-file','blob',blob]); if(bytes.length>MAX_BYTES) fail('git_source_blob_too_large');
    blobs[source]={gitBlob:blob,sha256:sha(bytes)};
    if(source!==TEMPLATE) material.set(path.join(release,source),bytes);
    else {
      const template=new TextDecoder('utf-8',{fatal:true}).decode(bytes);validateTemplate(template);
      const variables={NODE:process.execPath,ENTRY:path.join(release,'scripts/amf-host-admin.mjs'),CONFIG:configPath,RELEASE:release};
      if(!absolute(process.execPath)) fail('node_executable_invalid');
      const rendered=template.replace(/@(NODE|ENTRY|CONFIG|RELEASE)@/g,(_,key)=>quote(variables[key]));
      if(/@[A-Z_]+@/.test(rendered)) fail('unit_template_invalid');
      material.set(unitPath,Buffer.from(rendered));
    }
  }
  material.set(configPath,configBytes);material.set(policyPath,policyBytes);
  const oldBytes=readFile(manifestPath,{privateRequired:true,optional:true});
  const old=oldBytes ? json(oldBytes) : null;
  if(old && (old.schema!=='amf.host-admin-installation/v1' || !plain(old.targets) || !/^[a-f0-9]{40}$/.test(old.revision ?? '') || old.runtimeRoot!==runtimeRoot || old.unitPath!==unitPath)) fail('installation_manifest_invalid');
  const managedTarget=filename=>filename===configPath || filename===policyPath || filename===unitPath || (within(filename,path.join(runtimeRoot,'releases')) && /^releases\/[a-f0-9]{40}\/(?:src\/(?:host-file-catalog|host-admin-server)\.mjs|scripts\/amf-host-admin\.mjs)$/.test(path.relative(runtimeRoot,filename)));
  const observed={};
  for(const filename of new Set([...Object.keys(old?.targets ?? {}),...material.keys()])) {
    if(!absolute(filename) || !managedTarget(filename)) fail('installation_manifest_target_invalid');
    if(filename===unitPath) directory(unitDirectory,{privateRequired:false,ownedRequired:true});
    else {let cursor=path.dirname(filename);while(cursor===runtimeRoot || within(cursor,runtimeRoot)) {directory(cursor);cursor=path.dirname(cursor);}}
    const bytes=readFile(filename,{privateRequired:true,optional:true});observed[filename]=bytes ? sha(bytes) : null;
    const previous=old?.targets[filename];
    if(previous!==undefined && (!/^[a-f0-9]{64}$/.test(previous) || observed[filename]!==previous)) fail('managed_target_drift');
    if(previous===undefined && bytes!==null) fail('unowned_target_exists');
  }
  // Validate private parents without reading the bearer token or opening the DB.
  for(const filename of [config.tokenFile,config.databasePath]) {let cursor=path.dirname(filename);while(cursor===runtimeRoot || within(cursor,runtimeRoot)) {directory(cursor);cursor=path.dirname(cursor);}}
  const token=tokenState(config.tokenFile);
  const targets={...(old?.targets ?? {})};for(const [filename,bytes] of material) targets[filename]=sha(bytes);
  const manifest={schema:'amf.host-admin-installation/v1',runtimeRoot,unitPath,revision,targets};
  const manifestBytes=Buffer.from(`${JSON.stringify(manifest,null,2)}\n`);
  material.set(manifestPath,manifestBytes);observed[manifestPath]=oldBytes ? sha(oldBytes) : null;
  const changes=[...material].filter(([filename,bytes])=>observed[filename]!==sha(bytes)).map(([filename,bytes])=>({path:filename,sha256:sha(bytes)}));
  const plan={schema:'amf.host-admin-install-plan/v1',repo,revision,runtimeRoot,release,unitPath,unitName:UNIT,nodePath:process.execPath,activation:'not-requested',canonicalAncestryRequired:'refs/remotes/origin/main',blobs,configSource:{path:configSource,sha256:sha(configBytes)},policySource:{path:policySource,sha256:sha(policyBytes)},observed,token,changes,noOp:changes.length===0 && token.present};
  plan.planDigest=sha(canonical(plan));
  return {plan,material,config};
}
export function planHostAdminInstall(options) { return build(options).plan; }
function atomicWrite(filename,bytes,expected) {
  at(filename,target=>{
    const current=readFile(filename,{privateRequired:true,optional:true});
    if((current ? sha(current) : null)!==expected) fail('install_target_changed');
    const temporary=`${target}.tmp-${crypto.randomBytes(12).toString('hex')}`;
    const fd=fs.openSync(temporary,fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,0o600);
    try { fs.writeFileSync(fd,bytes);fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const recheck=readFile(filename,{privateRequired:true,optional:true});
    if((recheck ? sha(recheck) : null)!==expected) fail('install_target_changed');
    fs.renameSync(temporary,target);
  });
}
export function applyHostAdminInstall(options) {
  if(!/^[a-f0-9]{64}$/.test(options.planDigest ?? '')) fail('plan_digest_required');
  const {plan,material,config}=build(options);
  if(plan.planDigest!==options.planDigest) fail('stale_install_plan');
  try { git(options.repo,['merge-base','--is-ancestor',options.revision,'refs/remotes/origin/main']); } catch { fail('revision_not_on_origin_main'); }
  if(plan.noOp) return {schema:'amf.host-admin-install-result/v1',revision:plan.revision,unitName:UNIT,changed:false,activation:'not-requested'};
  directory(options.runtimeRoot,{create:true});directory(options.unitDirectory,{create:true,privateRequired:false,ownedRequired:true});
  for(const filename of material.keys()) {
    // Check every owned directory inside runtimeRoot, including pre-existing
    // intermediate release parents, rather than chmod shared ancestors.
    let cursor=path.dirname(filename);
    const directories=[];
    while(cursor!==path.dirname(options.runtimeRoot) && (cursor===options.runtimeRoot || within(cursor,options.runtimeRoot))) { directories.unshift(cursor);cursor=path.dirname(cursor); }
    for(const dir of directories) directory(dir,{create:true});
  }
  for(const filename of [config.tokenFile,config.databasePath]) {
    const directories=[];let cursor=path.dirname(filename);
    while(cursor===options.runtimeRoot || within(cursor,options.runtimeRoot)) {directories.unshift(cursor);cursor=path.dirname(cursor);}
    for(const dir of directories) directory(dir,{create:true});
  }
  if(canonical(tokenState(config.tokenFile))!==canonical(plan.token)) fail('install_token_state_changed');
  if(!plan.token.present) at(config.tokenFile,target=>{
    const fd=fs.openSync(target,fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,0o600);
    try {fs.writeFileSync(fd,`${crypto.randomBytes(32).toString('base64url')}\n`);fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
  });
  for(const [filename,bytes] of material) if(plan.observed[filename]!==sha(bytes)) atomicWrite(filename,bytes,plan.observed[filename]);
  return {schema:'amf.host-admin-install-result/v1',revision:plan.revision,unitName:UNIT,changed:true,activation:'not-requested'};
}
export function main(args=process.argv.slice(2)) {
  const values={},names={'--repo':'repo','--revision':'revision','--runtime-root':'runtimeRoot','--config-source':'configSource','--policy-source':'policySource','--unit-directory':'unitDirectory','--plan-digest':'planDigest'};let apply=false;
  for(let i=0;i<args.length;i++) {
    if(args[i]==='--apply' && !apply) {apply=true;continue;}
    const name=names[args[i]];
    if(!name || values[name]!==undefined || i+1>=args.length) fail('invalid_install_arguments');
    values[name]=args[++i];
  }
  const result=apply ? applyHostAdminInstall(values) : planHostAdminInstall(values);
  process.stdout.write(`${JSON.stringify(result)}\n`);return result;
}
if(process.argv[1] && import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  try {main();} catch(error) { process.stderr.write(`${JSON.stringify({error:error.message?.match(/^[a-z_]+$/) ? error.message : 'host_admin_install_failed'})}\n`);process.exitCode=1; }
}
