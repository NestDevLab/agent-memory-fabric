import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync, spawn } from 'node:child_process';
import { HostFileCatalog } from '../src/host-file-catalog.mjs';

function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(),'amf-catalog-test-'));
  const source = path.join(base,'source'), state = path.join(base,'state');
  fs.mkdirSync(source); fs.mkdirSync(state,{mode:0o700});
  const policy = {schema:'amf.host-file-catalog-policy/v1',hostId:'test-host',roots:[source],excludePrefixes:[],metadataOnlyPrefixes:[],domains:[{id:'docs',prefixes:[path.join(source,'docs')],destination:path.join(base,'proposed')}],content:{enabled:true,maxBytes:1024,extensions:['.txt','.md']}};
  t.after(() => fs.rmSync(base,{recursive:true,force:true}));
  return {base,source,state,policy,databasePath:path.join(state,'catalog.sqlite')};
}
async function finish(c,options={}) { let r; for (let i=0;i<10000;i++) { r=await c.scan({maxEntries:3,budgetMs:1000,...options}); options={}; if(r.scan.state==='complete') return r; } throw new Error('Scan did not finish'); }

test('restart/resume, unchanged text, literal FTS, prefix boundaries and conservative freshness',async t => {
  const f=fixture(t); fs.mkdirSync(path.join(f.source,'docs')); fs.mkdirSync(path.join(f.source,'docs-extra'));
  fs.writeFileSync(path.join(f.source,'docs','one.md'),'uniquealpha useful text');
  fs.writeFileSync(path.join(f.source,'docs-extra','two.txt'),'uniquebeta');
  let c=new HostFileCatalog(f);
  assert.equal((await c.scan({maxEntries:2})).scan.state,'running'); c.close();
  c=new HostFileCatalog(f); t.after(()=>c.close()); await finish(c);
  assert.equal(c.search({query:'uniquealpha'}).total,1);
  assert.equal(c.search({query:'uniquealpha'}).items[0].domain,'docs');
  assert.equal(c.search({query:'uniquebeta'}).items[0].domain,'unknown');
  assert.equal(c.search({query:"' OR 1=1 --"}).total,0);
  const status=c.status(); assert.equal((await c.scan()).processed,0);
  const originalRead=fs.readSync; let reads=0;
  fs.readSync=(...args)=>{reads++; return originalRead(...args);};
  try { await finish(c,{restart:true}); } finally {fs.readSync=originalRead;}
  assert.equal(reads,0); assert.equal(c.status().counts.total,status.counts.total);
  fs.unlinkSync(path.join(f.source,'docs','one.md'));
  await finish(c,{restart:true});
  assert.equal(c.search({query:'uniquealpha'}).items[0].currentGeneration,0);
  assert.equal(c.status().freshness.unverified,1);
  assert.equal(fs.statSync(f.databasePath).mode & 0o777,0o600);
  assert.equal(c.suggestions().find(x=>x.domain==='docs').action,'review-only');
});

test('sensitive paths/content, invalid text, symlinks and special files never indexed',async t => {
  const f=fixture(t);
  fs.writeFileSync(path.join(f.source,'password.txt'),'do-not-read-this');
  fs.writeFileSync(path.join(f.source,'normal.txt'),'api_key = abcdefghijklmnop');
  fs.writeFileSync(path.join(f.source,'binary.txt'),Buffer.from([0xff,0x00]));
  fs.writeFileSync(path.join(f.source,'big.txt'),'a'.repeat(2000));
  fs.writeFileSync(path.join(f.source,'safe.txt'),'publicword');
  fs.symlinkSync(path.join(f.source,'safe.txt'),path.join(f.source,'link.txt'));
  fs.mkdirSync(path.join(f.source,'cache')); fs.writeFileSync(path.join(f.source,'cache','a.txt'),'cachedword');
  f.policy.metadataOnlyPrefixes=[path.join(f.source,'cache')];
  execFileSync('mkfifo',[path.join(f.source,'pipe.txt')]);
  const c=new HostFileCatalog(f); t.after(()=>c.close()); await finish(c);
  const items=c.search({limit:100}).items;
  for (const [name,state] of [['password.txt','sensitive-path'],['normal.txt','sensitive-content'],['binary.txt','invalid-utf8'],['big.txt','too-large'],['link.txt','metadata-only'],['pipe.txt','metadata-only']]) assert.equal(items.find(x=>x.path.endsWith('/'+name)).contentState,state,name);
  assert.equal(c.search({query:'publicword'}).total,1);
  assert.equal(c.search({query:'cachedword'}).total,0);
  const linkedRoot={...f.policy,roots:[path.join(f.base,'linked','safe.txt')]};
  fs.symlinkSync(f.source,path.join(f.base,'linked'));
  c.close();
  const other=new HostFileCatalog({...f,databasePath:path.join(f.state,'other.sqlite'),policy:linkedRoot}); t.after(()=>other.close());
  await finish(other); assert.equal(other.status().counts.total,0); assert.equal(other.status().coverage.summary.find(x=>x.kind==='error').count,1);
});

test('bounded traversal, exclusions, inaccessible root retain old observations, cooperative lock',async t => {
  const f=fixture(t); for(let i=0;i<10;i++) fs.writeFileSync(path.join(f.source,`${i}.txt`),'boundedword');
  const c=new HostFileCatalog(f); t.after(()=>c.close());
  assert.throws(()=>new HostFileCatalog(f),/database is locked/);
  const first=await c.scan({maxEntries:1,budgetMs:1}); assert.ok(first.processed<=1); assert.equal(first.scan.state,'running');
  await finish(c); const count=c.status().counts.total;
  fs.renameSync(f.source,`${f.source}-unavailable`);
  await finish(c,{restart:true}); assert.equal(c.status().counts.total,count); assert.equal(c.status().freshness.unverified,count);
  assert.equal(c.status().coverage.summary.find(x=>x.kind==='error').count,1);
  assert.throws(()=>c.search({limit:201}),/Invalid/);
  await assert.rejects(c.scan({maxEntries:0}),/Invalid/);
});

test('explicit directory cap is recorded as incomplete, CLI emits JSON, virtual trees require exclusions',async t => {
  const f=fixture(t); for(let i=0;i<5;i++) fs.writeFileSync(path.join(f.source,`${i}.txt`),'entry');
  f.policy.limits={maxDirectoryEntries:2};
  const c=new HostFileCatalog(f); await finish(c);
  assert.equal(c.status().coverage.summary.find(x=>x.kind==='incomplete').count,1);
  assert.equal(c.search({limit:100}).items.filter(x=>x.kind==='file').length,2); c.close();
  const config=path.join(f.base,'policy.json'); fs.writeFileSync(config,JSON.stringify(f.policy));
  const result=spawnSync(process.execPath,['scripts/amf-host-catalog.mjs','--config',config,'--database',f.databasePath,'status'],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr); assert.equal(JSON.parse(result.stdout).scan.state,'complete');
  assert.throws(()=>new HostFileCatalog({...f,policy:{...f.policy,roots:['/']}}),/Virtual/);
});

test('SIGKILL releases native connection lock and committed queue resumes immediately',async t => {
  const f=fixture(t); for(let i=0;i<5;i++) fs.writeFileSync(path.join(f.source,`${i}.txt`),'resumableword');
  const code=`import { HostFileCatalog } from './src/host-file-catalog.mjs'; const c=new HostFileCatalog(JSON.parse(process.argv[1])); await c.scan({maxEntries:2}); console.log('ready'); setInterval(()=>{},1000);`;
  const child=spawn(process.execPath,['--input-type=module','-e',code,JSON.stringify({databasePath:f.databasePath,policy:f.policy})],{stdio:['ignore','pipe','pipe']});
  t.after(()=>{ if(child.exitCode===null) child.kill('SIGKILL'); });
  await new Promise((resolve,reject)=>{ child.stdout.once('data',resolve); child.once('error',reject); child.once('exit',()=>reject(new Error('Child exited before ready'))); });
  assert.throws(()=>new HostFileCatalog(f),/database is locked/);
  const killed=new Promise(resolve=>child.once('exit',resolve)); child.kill('SIGKILL'); await killed;
  const c=new HostFileCatalog(f); t.after(()=>c.close());
  assert.equal(c.status().scan.state,'running'); await finish(c);
  assert.equal(c.search({query:'resumableword'}).total,5);
  assert.equal(fs.existsSync(`${f.databasePath}.lock`),false);
});

test('protected entries and catalog state are metadata only without content reads',async t => {
  const f=fixture(t); fs.mkdirSync(path.join(f.source,'.ssh')); fs.writeFileSync(path.join(f.source,'.ssh','note.txt'),'never-read');
  fs.writeFileSync(path.join(f.source,'.npmrc'),'never-read');
  f.policy.content.extensions.push('.npmrc');
  f.policy.roots.push(f.state);
  const c=new HostFileCatalog(f); t.after(()=>c.close());
  const original=fs.readSync; let reads=0;
  fs.readSync=(...args)=>{reads++; return original(...args);};
  try { await finish(c); } finally { fs.readSync=original; }
  assert.equal(reads,0);
  assert.equal(c.search({query:'never-read'}).total,0);
  assert.ok(c.status().coverage.recent.some(x=>x.path===f.state && x.kind==='excluded'));
});


test('suggestions filter before LIMIT and metadata search includes non-indexed names',async t => {
  const f=fixture(t);
  f.policy.domains=[{id:'system',prefixes:[f.source]},{id:'project',prefixes:[path.join(f.source,'zz-project')],destination:path.join(f.base,'proposed')}];
  for(let i=0;i<205;i++) fs.writeFileSync(path.join(f.source,`a-${i}.pdf`),'metadata only');
  fs.mkdirSync(path.join(f.source,'zz-project')); const report=path.join(f.source,'zz-project','report_100%.pdf'); fs.writeFileSync(report,'not indexed');
  const c=new HostFileCatalog(f); t.after(()=>c.close()); await finish(c,{maxEntries:10000});
  assert.equal(c.suggestions({limit:1})[0].path,report);
  assert.equal(c.search({query:report}).items[0].path,report);
  assert.equal(c.search({query:'report_100%.pdf'}).total,1);
  assert.equal(c.search({query:'not indexed'}).total,0);
  assert.equal(c.search({query:'%'}).total,1);
});

test('configured dependency directory names preserve inventory while refusing text indexing',async t=>{
  const f=fixture(t);f.policy.metadataOnlyDirectoryNames=['node_modules','.cache'];
  fs.mkdirSync(path.join(f.source,'node_modules','example'),{recursive:true});
  const dependency=path.join(f.source,'node_modules','example','README.md');fs.writeFileSync(dependency,'dependencyword');
  fs.writeFileSync(path.join(f.source,'notes.md'),'regularword');
  const c=new HostFileCatalog(f);t.after(()=>c.close());await finish(c);
  assert.equal(c.search({query:'dependencyword'}).total,0);
  assert.equal(c.search({query:'regularword'}).total,1);
  assert.equal(c.search({query:dependency}).items[0].contentState,'metadata-only-policy');
  assert.deepEqual(c.status().coverage.metadataOnlyDirectoryNames,['node_modules','.cache']);
  c.close();
  for(const name of ['.','..','../escape','foo/bar','foo\\bar','']) assert.throws(()=>new HostFileCatalog({...f,policy:{...f.policy,metadataOnlyDirectoryNames:[name]}}),/Invalid metadataOnlyDirectoryNames/);
});
