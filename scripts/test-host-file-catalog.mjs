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

test('filename hints propose real targets, preserve prefix authority and prioritize organization over unknown review',async t=>{
  const f=fixture(t);
  const inbox=path.join(f.source,'inbox'),alpha=path.join(f.source,'organized-alpha'),beta=path.join(f.source,'organized-beta');
  fs.mkdirSync(inbox);fs.mkdirSync(alpha);fs.mkdirSync(beta);
  f.policy.domains=[{id:'alpha',prefixes:[alpha],nameHints:['alpha'],destination:alpha},{id:'beta',prefixes:[beta],nameHints:['beta'],destination:beta}];
  const files=['alpha-plan.pdf','alpha-beta.pdf','alphabets.pdf','ALPHA-notes.pdf','beta-report.pdf','alpha-secret.pdf','alpha-plan.txt'];
  for(const name of files) fs.writeFileSync(path.join(inbox,name),name==='alpha-plan.txt'?'api_key = abcdefghijklmnop':'ordinary');
  fs.writeFileSync(path.join(alpha,'alpha-ready.pdf'),'organized');
  fs.writeFileSync(path.join(alpha,'beta-owned.pdf'),'prefix wins');
  for(let i=0;i<205;i++) fs.writeFileSync(path.join(f.source,`a-unknown-${i}.pdf`),'unknown');
  const sourceSnapshot=()=>{
    const result={};const walk=dir=>{for(const name of fs.readdirSync(dir).sort()) {const p=path.join(dir,name),s=fs.lstatSync(p,{bigint:true});result[p]={mode:String(s.mode),mtime:String(s.mtimeNs),contents:s.isFile()?fs.readFileSync(p,'utf8'):null};if(s.isDirectory())walk(p);}};walk(f.source);return result;
  };
  const before=sourceSnapshot(),c=new HostFileCatalog(f);t.after(()=>c.close());await finish(c,{maxEntries:10000});
  const item=name=>c.search({query:path.join(inbox,name)}).items[0];
  assert.equal(item('alpha-plan.pdf').domain,'alpha');assert.equal(item('alpha-plan.pdf').confidence,0.5);assert.equal(item('alpha-plan.pdf').classificationPrefix,null);assert.equal(item('alpha-plan.pdf').classificationBasis,'filename-hint');
  assert.equal(item('ALPHA-notes.pdf').domain,'alpha');
  assert.equal(item('alpha-beta.pdf').domain,'unknown');assert.equal(item('alphabets.pdf').domain,'unknown');
  assert.equal(c.search({query:path.join(alpha,'beta-owned.pdf')}).items[0].domain,'alpha');
  const first=c.suggestions({limit:1})[0];assert.equal(first.reviewKind,'organization-proposal');assert.ok(first.suggestedDestination.startsWith(alpha+'/') || first.suggestedDestination.startsWith(beta+'/'));
  const proposed=c.suggestions({limit:200});
  const plan=proposed.find(x=>x.path===path.join(inbox,'alpha-plan.pdf'));
  assert.equal(plan.suggestedDestination,path.join(alpha,'alpha-plan.pdf'));assert.equal(plan.evidence.basis,'filename-hint');assert.deepEqual(plan.evidence.matchedNameHints,['alpha']);assert.equal(plan.action,'review-only');assert.match(plan.uncertainty,/collisions.*unknown/);
  assert.ok(!proposed.some(x=>x.path.startsWith(alpha+'/')));assert.ok(!proposed.some(x=>x.path.endsWith('alpha-secret.pdf') || x.path.endsWith('alpha-plan.txt')));
  assert.ok(proposed.some(x=>x.reviewKind==='classification-review' && x.suggestedDestination===null));
  assert.deepEqual(sourceSnapshot(),before);
  assert.deepEqual(c.classification(path.join(inbox,'alphabet-plan.pdf')),{domain:'unknown',prefix:null,confidence:0});
  assert.equal(c.classification(path.join(inbox,'alpha-team-plan.pdf')).domain,'alpha');
  const grouped=filename=>HostFileCatalog.prototype.classification.call({policy:{domains:[{id:'alpha',prefixes:[],nameHints:['alpha-team']}]}},filename);
  assert.equal(grouped('/inbox/ALPHA-team-plan.pdf').domain,'alpha');
  assert.equal(grouped('/inbox/alphateam-plan.pdf').domain,'unknown');
  assert.equal(grouped('/inbox/alpha-plan.pdf').domain,'unknown');
  c.close();
  for(const hint of ['', '../alpha','alpha beta','alpha/plan','-alpha','alpha-','alpha--beta','alpha\n','x'.repeat(65)]) assert.throws(()=>new HostFileCatalog({...f,policy:{...f.policy,domains:[{id:'alpha',prefixes:[],nameHints:[hint]}]}}),/Invalid domain/);
});

test('known prefix suggestions append basename, respect destination boundaries and never inspect collisions',async t=>{
  const f=fixture(t),destination=path.join(f.source,'organized');
  fs.mkdirSync(path.join(f.source,'known'));fs.mkdirSync(destination);fs.mkdirSync(destination+'-neighbor');
  fs.writeFileSync(path.join(f.source,'known','report.pdf'),'outside');fs.writeFileSync(path.join(destination,'report.pdf'),'existing collision');fs.writeFileSync(path.join(destination+'-neighbor','other.pdf'),'boundary');
  f.policy.domains=[{id:'alpha',prefixes:[f.source],destination}];
  const c=new HostFileCatalog(f);t.after(()=>c.close());await finish(c);
  const originalStat=fs.statSync,originalLstat=fs.lstatSync;
  fs.statSync=()=>{throw new Error('No filesystem collision checks allowed');};fs.lstatSync=fs.statSync;
  let items;try {items=c.suggestions();} finally {fs.statSync=originalStat;fs.lstatSync=originalLstat;}
  assert.equal(items.length,2);
  assert.equal(items.find(x=>x.path.endsWith('/known/report.pdf')).suggestedDestination,path.join(destination,'report.pdf'));
  assert.ok(items.some(x=>x.path.endsWith('/organized-neighbor/other.pdf')));
  assert.ok(items.every(x=>x.evidence.basis==='configured-prefix' && x.evidence.confidence===1));
});

test('hardlinked innocuous aliases of protected files remain metadata-only without reads or proposals',async t=>{
  const f=fixture(t),protectedPath=path.join(f.source,'credentials.txt'),alias=path.join(f.source,'alpha-plan.txt');
  fs.writeFileSync(protectedPath,'unlabelled credential value');fs.linkSync(protectedPath,alias);
  f.policy.domains=[{id:'alpha',prefixes:[],nameHints:['alpha'],destination:path.join(f.source,'organized')}];
  const c=new HostFileCatalog(f);t.after(()=>c.close());
  const originalRead=fs.readSync;let reads=0;fs.readSync=(...args)=>{reads++;return originalRead(...args);};
  try {await finish(c);} finally {fs.readSync=originalRead;}
  assert.equal(reads,0);assert.equal(c.search({query:alias}).items[0].contentState,'metadata-only-hardlink');
  assert.equal(c.search({query:'unlabelled'}).total,0);assert.deepEqual(c.suggestions(),[]);
});
