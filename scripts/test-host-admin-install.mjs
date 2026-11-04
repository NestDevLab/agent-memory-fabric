import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync, spawn } from 'node:child_process';
import net from 'node:net';
import { once } from 'node:events';
import { planHostAdminInstall, applyHostAdminInstall } from './amf-install-host-admin.mjs';

const codeSources=['src/host-file-catalog.mjs','src/host-catalog-path-index.mjs','src/host-admin-server.mjs','scripts/amf-host-admin.mjs','scripts/amf-host-catalog.mjs'];
const template='deploy/systemd/amf-host-admin.service.in';
const sources=[...codeSources,template];
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function git(repo,args) {return execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();}
function commit(repo) {git(repo,['add','.']);git(repo,['-c','user.name=Example','-c','user.email=example@example.invalid','commit','-qm','Synthetic installer fixture']);return git(repo,['rev-parse','HEAD']);}
function fixture(t) {
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'amf-install-test-'));
  t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
  const repo=path.join(base,'repo'),runtimeRoot=path.join(base,'runtime % example'),unitDirectory=path.join(base,'units');
  fs.mkdirSync(repo);fs.mkdirSync(unitDirectory,{mode:0o755});git(repo,['init','-q','--initial-branch=main']);
  for(const source of sources) {const dest=path.join(repo,source);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(source,dest);}
  const revision=commit(repo);git(repo,['update-ref','refs/remotes/origin/main',revision]);
  const configSource=path.join(base,'config-source.json'),policySource=path.join(base,'policy-source.json');
  const config={schema:'amf.host-admin-config/v1',bind:'127.0.0.1',port:8127,policyPath:path.join(runtimeRoot,'catalog-policy.json'),databasePath:path.join(runtimeRoot,'database','catalog.sqlite'),tokenFile:path.join(runtimeRoot,'auth','bearer.token')};
  const policy={schema:'amf.host-file-catalog-policy/v1',hostId:'example-host',roots:[path.join(base,'documents')],excludePrefixes:[runtimeRoot],metadataOnlyPrefixes:[],metadataOnlyDirectoryNames:['node_modules'],domains:[{id:'alpha',prefixes:[],nameHints:['alpha','alpha-team'],destination:path.join(base,'organized-alpha')}],content:{enabled:false,maxBytes:1024,extensions:['.txt']}};
  fs.writeFileSync(configSource,JSON.stringify(config),{mode:0o644});fs.writeFileSync(policySource,JSON.stringify(policy),{mode:0o644});
  return {base,repo,revision,runtimeRoot,unitDirectory,configSource,policySource,config,policy};
}
function snapshot(root) {
  const result={};
  const walk=dir=>{for(const name of fs.readdirSync(dir).sort()) {const file=path.join(dir,name),stat=fs.lstatSync(file,{bigint:true});result[path.relative(root,file)]={mode:String(stat.mode),mtimeNs:String(stat.mtimeNs),hash:stat.isFile()?hash(fs.readFileSync(file)):null};if(stat.isDirectory())walk(file);}};
  walk(root);return result;
}

test('plan is read-only; apply installs immutable blobs, private state, quoted unit, and repeats without writes',t=>{
  const f=fixture(t),before=snapshot(f.base);
  const plan=planHostAdminInstall(f);
  assert.deepEqual(snapshot(f.base),before);assert.equal(plan.noOp,false);assert.equal(fs.existsSync(f.runtimeRoot),false);
  // A dirty checkout must never alter the installed revision's immutable bytes.
  fs.writeFileSync(path.join(f.repo,sources[0]),'working tree poison');
  const result=applyHostAdminInstall({...f,planDigest:plan.planDigest});
  assert.equal(result.changed,true);assert.equal(result.activation,'not-requested');assert.equal(result.unitName,'amf-host-admin.service');
  for(const source of codeSources) {
    const target=path.join(f.runtimeRoot,'releases',f.revision,source);
    assert.equal(fs.readFileSync(target,'utf8'),git(f.repo,['show',`${f.revision}:${source}`])+'\n');
    assert.equal(fs.statSync(target).mode & 0o777,0o600);
    assert.equal(fs.statSync(path.dirname(target)).mode & 0o777,0o700);
  }
  const unitPath=path.join(f.unitDirectory,'amf-host-admin.service'),unit=fs.readFileSync(unitPath,'utf8');
  assert.match(unit,/Restart=on-failure/);assert.match(unit,/NoNewPrivileges=true/);assert.match(unit,/UMask=0077/);assert.ok(unit.includes('runtime %% example'));assert.ok(unit.includes(`ExecStart="${process.execPath}"`));
  assert.equal(fs.statSync(f.unitDirectory).mode & 0o777,0o755);
  assert.equal(fs.statSync(f.runtimeRoot).mode & 0o777,0o700);assert.equal(fs.statSync(f.config.tokenFile).mode & 0o777,0o600);
  assert.equal(fs.statSync(path.dirname(f.config.databasePath)).mode & 0o777,0o700);
  const token=fs.readFileSync(f.config.tokenFile,'utf8').trim();assert.match(token,/^[A-Za-z0-9_-]{43}$/);
  const second=planHostAdminInstall(f),installed=snapshot(f.runtimeRoot);assert.equal(second.noOp,true);
  const repeated=applyHostAdminInstall({...f,planDigest:second.planDigest});assert.equal(repeated.changed,false);assert.deepEqual(snapshot(f.runtimeRoot),installed);
  const output=JSON.stringify([plan,result,second,repeated]);assert.ok(!output.includes(token));assert.ok(!output.includes(hash(token)));assert.ok(!output.includes(hash(`${token}\n`)));
});

test('stale plan, managed drift and unowned targets fail before replacing files',t=>{
  const f=fixture(t),plan=planHostAdminInstall(f);
  fs.writeFileSync(f.configSource,JSON.stringify({...f.config,port:8128}));
  assert.throws(()=>applyHostAdminInstall({...f,planDigest:plan.planDigest}),/stale_install_plan/);assert.equal(fs.existsSync(f.runtimeRoot),false);
  const fresh=planHostAdminInstall(f);applyHostAdminInstall({...f,planDigest:fresh.planDigest});
  const target=path.join(f.runtimeRoot,'releases',f.revision,sources[0]);fs.appendFileSync(target,'\n// changed\n');
  assert.throws(()=>planHostAdminInstall(f),/managed_target_drift/);
  const other=fixture(t);fs.mkdirSync(other.runtimeRoot,{mode:0o700});fs.writeFileSync(path.join(other.runtimeRoot,'config.json'),'unowned',{mode:0o600});
  assert.throws(()=>planHostAdminInstall(other),/unowned_target_exists/);
});

test('apply requires revision reachable from origin/main and does not delete previous releases',t=>{
  const f=fixture(t),first=planHostAdminInstall(f);applyHostAdminInstall({...f,planDigest:first.planDigest});
  fs.appendFileSync(path.join(f.repo,sources[0]),'\n// second revision\n');const secondRevision=commit(f.repo);
  const options={...f,revision:secondRevision},second=planHostAdminInstall(options),before=snapshot(f.runtimeRoot);
  assert.throws(()=>applyHostAdminInstall({...options,planDigest:second.planDigest}),/revision_not_on_origin_main/);assert.deepEqual(snapshot(f.runtimeRoot),before);
  git(f.repo,['update-ref','refs/remotes/origin/main',secondRevision]);
  applyHostAdminInstall({...options,planDigest:second.planDigest});
  assert.ok(fs.existsSync(path.join(f.runtimeRoot,'releases',f.revision,sources[0])));assert.ok(fs.existsSync(path.join(f.runtimeRoot,'releases',secondRevision,sources[0])));
});

test('remote bind, escaping config paths, source symlinks, unsafe directories and oversized sources are rejected',t=>{
  const f=fixture(t);
  const setConfig=config=>fs.writeFileSync(f.configSource,JSON.stringify(config));
  setConfig({...f.config,bind:'0.0.0.0'});assert.throws(()=>planHostAdminInstall(f),/admin_config_invalid/);
  setConfig({...f.config,tokenFile:path.join(f.base,'outside.token')});assert.throws(()=>planHostAdminInstall(f),/runtime_config_path_forbidden/);
  setConfig({...f.config,databasePath:path.join(f.runtimeRoot,'elsewhere.sqlite')});assert.throws(()=>planHostAdminInstall(f),/runtime_config_path_forbidden/);
  setConfig({...f.config,tokenFile:path.join(f.runtimeRoot,'config.json','token')});assert.throws(()=>planHostAdminInstall(f),/token_path_forbidden/);
  setConfig(f.config);
  const linked=path.join(f.base,'linked.json');fs.symlinkSync(f.configSource,linked);assert.throws(()=>planHostAdminInstall({...f,configSource:linked}));
  const linkedDir=path.join(f.base,'linked-dir');fs.symlinkSync(f.base,linkedDir);assert.throws(()=>planHostAdminInstall({...f,configSource:path.join(linkedDir,path.basename(f.configSource))}));
  fs.mkdirSync(f.runtimeRoot,{mode:0o755});assert.throws(()=>planHostAdminInstall(f),/unsafe_install_directory/);fs.chmodSync(f.runtimeRoot,0o700);
  fs.chmodSync(f.unitDirectory,0o777);assert.throws(()=>planHostAdminInstall(f),/unsafe_install_directory/);fs.chmodSync(f.unitDirectory,0o755);
  fs.writeFileSync(f.policySource,JSON.stringify({...f.policy,metadataOnlyDirectoryNames:['../escape']}));assert.throws(()=>planHostAdminInstall(f),/invalid_catalog_policy/);fs.writeFileSync(f.policySource,JSON.stringify(f.policy));
  for(const hint of ['../alpha','alpha\n']) {fs.writeFileSync(f.policySource,JSON.stringify({...f.policy,domains:[{id:'alpha',prefixes:[],nameHints:[hint]}]}));assert.throws(()=>planHostAdminInstall(f),/invalid_catalog_policy/);}fs.writeFileSync(f.policySource,JSON.stringify(f.policy));
  fs.writeFileSync(f.configSource,'x'.repeat(1024*1024+1));assert.throws(()=>planHostAdminInstall(f),/unsafe_install_file/);
});

test('CLI emits only safe plans/results and rejects absent apply digest',t=>{
  const f=fixture(t),flags=['--repo',f.repo,'--revision',f.revision,'--runtime-root',f.runtimeRoot,'--config-source',f.configSource,'--policy-source',f.policySource,'--unit-directory',f.unitDirectory];
  const run=args=>spawnSync(process.execPath,['scripts/amf-install-host-admin.mjs',...flags,...args],{encoding:'utf8'});
  const initial=run([]);assert.equal(initial.status,0,initial.stderr);const plan=JSON.parse(initial.stdout);
  assert.equal(run(['--apply']).status,1);
  const applied=run(['--apply','--plan-digest',plan.planDigest]);assert.equal(applied.status,0,applied.stderr);assert.equal(JSON.parse(applied.stdout).activation,'not-requested');
  const token=fs.readFileSync(f.config.tokenFile,'utf8').trim();const repeated=run([]);assert.equal(repeated.status,0,repeated.stderr);assert.ok(!repeated.stdout.includes(token));assert.ok(!repeated.stdout.includes(hash(token)));
});

test('pinned symlink code and extra unit commands are rejected before installation',t=>{
  const f=fixture(t),source=path.join(f.repo,sources[0]);
  fs.unlinkSync(source);fs.symlinkSync('host-admin-server.mjs',source);const linkedRevision=commit(f.repo);
  assert.throws(()=>planHostAdminInstall({...f,revision:linkedRevision}),/git_source_mode_invalid/);
  const other=fixture(t);fs.appendFileSync(path.join(other.repo,template),'\n[Service]\nExecStartPre=/bin/false\n');const badTemplate=commit(other.repo);
  assert.throws(()=>planHostAdminInstall({...other,revision:badTemplate}),/unit_template_invalid/);
  assert.equal(fs.existsSync(other.runtimeRoot),false);
});

test('rendered unit passes systemd verification with an unquoted absolute working directory',t=>{
  const available=spawnSync('systemd-analyze',['--version'],{encoding:'utf8'});
  if(available.error?.code==='ENOENT') {t.skip('systemd-analyze is unavailable');return;}
  assert.equal(available.status,0,available.stderr);
  const f=fixture(t),plan=planHostAdminInstall(f);applyHostAdminInstall({...f,planDigest:plan.planDigest});
  const unitPath=path.join(f.unitDirectory,'amf-host-admin.service'),unit=fs.readFileSync(unitPath,'utf8');
  // Reproduce the old renderer: systemd treats quotes in WorkingDirectory as
  // part of this scalar path, unlike the quoted ExecStart argument list.
  const brokenPath=path.join(f.unitDirectory,'amf-host-admin-old.service');
  const broken=unit.replace(/^WorkingDirectory=.*$/m,`WorkingDirectory="${plan.release.replaceAll('%','%%')}"`);
  fs.writeFileSync(brokenPath,broken,{mode:0o600});
  const rejected=spawnSync('systemd-analyze',['verify',brokenPath],{encoding:'utf8'});
  assert.notEqual(rejected.status,0);assert.match(rejected.stderr,/WorkingDirectory=.*(?:not absolute|non.absolute)/i);
  assert.match(unit,/^WorkingDirectory=\/$/m);
  assert.ok(unit.includes(`ExecStart="${process.execPath}"`));
  const accepted=spawnSync('systemd-analyze',['verify',unitPath],{encoding:'utf8'});
  assert.equal(accepted.status,0,accepted.stderr);
});


test('installed release starts independently, holds catalog lock, and supports offline backfill without a token',async t=>{
  const f=fixture(t);
  const reservation=net.createServer(); reservation.listen(0,'127.0.0.1'); await once(reservation,'listening');
  f.config.port=reservation.address().port; await new Promise(resolve=>reservation.close(resolve));
  fs.writeFileSync(f.configSource,JSON.stringify(f.config));
  fs.mkdirSync(f.policy.roots[0]); fs.writeFileSync(path.join(f.policy.roots[0],'memory-example.txt'),'example');
  const plan=planHostAdminInstall(f); applyHostAdminInstall({...f,planDigest:plan.planDigest});
  const release=path.join(f.runtimeRoot,'releases',f.revision), cli=path.join(release,'scripts/amf-host-catalog.mjs');
  const run=command=>spawnSync(process.execPath,[cli,'--config',f.config.policyPath,'--database',f.config.databasePath,command,'--max-entries',command==='scan'?'100':'1'],{cwd:'/',encoding:'utf8',timeout:15000});
  // The copied release resolves every import without the repository or cwd.
  for(let i=0;i<20;i++) {const result=run('scan');assert.equal(result.status,0,result.stderr);if(JSON.parse(result.stdout).scan.state==='complete')break;assert.ok(i<19);}
  const first=run('index-paths'); assert.equal(first.status,0,first.stderr); assert.equal(JSON.parse(first.stdout).complete,false);
  const tokenBefore=fs.statSync(f.config.tokenFile,{bigint:true});
  const child=spawn(process.execPath,[path.join(release,'scripts/amf-host-admin.mjs'),'--config',path.join(f.runtimeRoot,'config.json')],{cwd:'/',stdio:['ignore','pipe','pipe']});
  let stderr='';child.stderr.setEncoding('utf8');child.stderr.on('data',value=>{stderr+=value;});
  t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL');});
  await new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>{child.kill('SIGKILL');reject(Error('Installed service startup timed out'));},10000);
    child.stdout.once('data',value=>{clearTimeout(timeout);try {assert.equal(JSON.parse(String(value)).state,'listening');resolve();}catch(error){reject(error);}});
    child.once('error',error=>{clearTimeout(timeout);reject(error);});
    child.once('exit',()=>{clearTimeout(timeout);reject(Error(`Installed service exited before listening: ${stderr}`));});
  });
  assert.equal((await fetch(`http://127.0.0.1:${f.config.port}/v1/files?query=memory`)).status,401);
  const locked=run('index-paths'); assert.equal(locked.status,1); assert.match(JSON.parse(locked.stderr.trim().split('\n').at(-1)).message,/Catalog operation failed/);
  const exited=once(child,'exit'); child.kill('SIGTERM'); await exited;
  let complete=false;
  for(let i=0;i<20;i++){const result=run('index-paths');assert.equal(result.status,0,result.stderr);if(JSON.parse(result.stdout).complete){complete=true;break;}}
  assert.equal(complete,true);
  const search=spawnSync(process.execPath,[cli,'--config',f.config.policyPath,'--database',f.config.databasePath,'search','--query','memory'],{cwd:'/',encoding:'utf8',timeout:15000});
  assert.equal(search.status,0,search.stderr);assert.equal(JSON.parse(search.stdout).total,1);
  const tokenAfter=fs.statSync(f.config.tokenFile,{bigint:true});
  assert.deepEqual([tokenAfter.ino,tokenAfter.mtimeNs,tokenAfter.size],[tokenBefore.ino,tokenBefore.mtimeNs,tokenBefore.size]);
});

test('legacy installation receipt with only original release paths upgrades and retains old files',t=>{
  const f=fixture(t),plan=planHostAdminInstall(f);applyHostAdminInstall({...f,planDigest:plan.planDigest});
  const manifestPath=path.join(f.runtimeRoot,'.installation.json'),manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
  const original=['src/host-file-catalog.mjs','src/host-admin-server.mjs','scripts/amf-host-admin.mjs'];
  for(const source of codeSources.filter(source=>!original.includes(source))) {
    const filename=path.join(plan.release,source);fs.unlinkSync(filename);delete manifest.targets[filename];
  }
  fs.writeFileSync(manifestPath,JSON.stringify(manifest),{mode:0o600});
  const before=original.map(source=>fs.statSync(path.join(plan.release,source),{bigint:true}).mtimeNs);
  const upgrade=planHostAdminInstall(f);assert.equal(upgrade.noOp,false);
  applyHostAdminInstall({...f,planDigest:upgrade.planDigest});
  for(const [i,source] of original.entries()) assert.equal(fs.statSync(path.join(plan.release,source),{bigint:true}).mtimeNs,before[i]);
  for(const source of codeSources) assert.ok(fs.existsSync(path.join(plan.release,source)));
  assert.equal(planHostAdminInstall(f).noOp,true);
});


test('historical revisions remain installable; imported path-index dependency cannot be omitted',t=>{
  const historical=fixture(t);
  fs.writeFileSync(path.join(historical.repo,'src/host-file-catalog.mjs'),'export class HostFileCatalog {}\n');
  for(const source of ['src/host-catalog-path-index.mjs','scripts/amf-host-catalog.mjs']) fs.unlinkSync(path.join(historical.repo,source));
  const revision=commit(historical.repo);git(historical.repo,['update-ref','refs/remotes/origin/main',revision]);
  const options={...historical,revision},plan=planHostAdminInstall(options);
  assert.equal(Object.hasOwn(plan.blobs,'src/host-catalog-path-index.mjs'),false);
  applyHostAdminInstall({...options,planDigest:plan.planDigest});assert.equal(planHostAdminInstall(options).noOp,true);
  const broken=fixture(t);fs.unlinkSync(path.join(broken.repo,'src/host-catalog-path-index.mjs'));
  const incomplete=commit(broken.repo);
  assert.throws(()=>planHostAdminInstall({...broken,revision:incomplete}),/git_source_mode_invalid/);
  assert.equal(fs.existsSync(broken.runtimeRoot),false);
});
