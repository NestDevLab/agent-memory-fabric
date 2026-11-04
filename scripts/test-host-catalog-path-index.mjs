import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { HostFileCatalog } from '../src/host-file-catalog.mjs';
import { initializePathIndex, buildPathIndex, pathCandidateMatch } from '../src/host-catalog-path-index.mjs';

function fixture(t) {
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'amf-path-index-'));
  fs.mkdirSync(path.join(base,'state'),{mode:0o700});
  const options={databasePath:path.join(base,'state','catalog.sqlite'),policy:{schema:'amf.host-file-catalog-policy/v1',hostId:'example',roots:[base],excludePrefixes:[],metadataOnlyPrefixes:[],domains:[],content:{enabled:false,maxBytes:1024,extensions:[]}}};
  const c=new HostFileCatalog(options);
  t.after(()=>{c.close();fs.rmSync(base,{recursive:true,force:true});});
  return {c,options};
}
function add(c,p,body='',domain='docs') {
  c.db.prepare('INSERT INTO files(path,kind,domain,generation) VALUES(?,?,?,0)').run(p,'file',domain);
  if(body) c.db.prepare('INSERT INTO texts(path,body) VALUES(?,?)').run(p,body);
}
function finish(c) { for(let n=0;n<10000;n++) if(c.buildPathIndex({maxEntries:3,budgetMs:1000}).complete) return; throw Error('Unfinished'); }
function legacy(c,options) {
  const state=c.pathIndexState();
  c.db.exec('UPDATE catalog_path_index_v1_state SET complete=0');
  try { return c.search(options); }
  finally { c.db.prepare('UPDATE catalog_path_index_v1_state SET complete=?').run(state.complete); }
}

test('exact path/content union, literal escaping, Unicode, totals, domains and pages',t=>{
  const {c}=fixture(t);
  const names=['memory','MEMORY','memory-both','body-only','100%_! literal','quote"here','back\\slash','punct ...','a-b_c','café','CAFÉ','東京記憶','emoji😀x','abc\ndef','abc\tdef','İmemory','Kmemory','x/y/z','with spaces'];
  for(const [i,name] of names.entries()) add(c,`/example/${name}`,name==='body-only'||name==='memory-both'?'memory useful café 東京記憶':'',i%2?'docs':'other');
  finish(c);
  c.db.exec('BEGIN');
  for(const query of ['', 'memory','MEMORY','body-only','100%_!','%','_','!','quote"','back\\','...','a-b_c','café','CAFÉ','東京記憶','😀x','abc\n','abc\t','İme','Kme','x/y/z','with spaces', '" OR *', 'missing','a','ab','abc','\0']) {
    for(const domain of [null,'docs','other','absent']) for(const offset of [0,1,3,20]) {
      const options={query,domain,offset,limit:2};
      assert.deepEqual(c.search(options),legacy(c,options),JSON.stringify(options));
    }
  }
  assert.equal(c.search({query:'memory'}).total,6);
  assert.equal(pathCandidateMatch(c.db,'東京記憶'),null);
  assert.equal(pathCandidateMatch(c.db,'ab'),null);
  assert.notEqual(pathCandidateMatch(c.db,'memory'),null);
  c.db.exec('ROLLBACK');
});

test('existing inventory resumes bounded backfill across reconnect, with insert/update/delete and rollback',t=>{
  const {c,options}=fixture(t);
  // Simulate a pre-migration database without assuming a files rowid layout.
  c.db.exec('DROP TRIGGER catalog_path_index_v1_file_insert');
  for(let i=0;i<12;i++) add(c,`/old/memory-${String(i).padStart(2,'0')}`);
  initializePathIndex(c.db);
  const expected=legacy(c,{query:'memory'});
  assert.equal(c.buildPathIndex({maxEntries:2,budgetMs:1000}).processed,2);
  assert.equal(c.pathIndexState().complete,0);
  assert.deepEqual(c.search({query:'memory'}),expected);
  c.close();
  const resumed=new HostFileCatalog(options); t.after(()=>resumed.close());
  assert.equal(resumed.pathIndexState().cursor,'/old/memory-01');
  add(resumed,'/aaa/memory-insert');
  resumed.db.prepare('DELETE FROM files WHERE path=?').run('/old/memory-00');
  resumed.db.prepare('UPDATE files SET path=?,domain=? WHERE path=?').run('/aaa/memory-renamed','other','/old/memory-08');
  resumed.db.exec(`CREATE TRIGGER fail_path_batch BEFORE INSERT ON catalog_path_index_v1_keys WHEN new.path='/old/memory-04' BEGIN SELECT RAISE(ABORT,'batch-fault'); END`);
  const before=resumed.pathIndexState(), count=resumed.db.prepare('SELECT count(*) n FROM catalog_path_index_v1_keys').get().n;
  assert.throws(()=>resumed.buildPathIndex({maxEntries:10,budgetMs:1000}),/batch-fault/);
  assert.deepEqual(resumed.pathIndexState(),before);
  assert.equal(resumed.db.prepare('SELECT count(*) n FROM catalog_path_index_v1_keys').get().n,count);
  assert.deepEqual(resumed.search({query:'memory'}),legacy(resumed,{query:'memory'}));
  resumed.db.exec('DROP TRIGGER fail_path_batch'); finish(resumed);
  for(const domain of [null,'docs','other']) assert.deepEqual(resumed.search({query:'memory',domain}),legacy(resumed,{query:'memory',domain}));
  resumed.db.exec('BEGIN IMMEDIATE'); add(resumed,'/rolled/memory'); resumed.db.exec('ROLLBACK');
  assert.equal(resumed.search({query:'rolled/memory'}).total,0);
  add(resumed,'/new/memory'); resumed.db.prepare('UPDATE files SET path=? WHERE path=?').run('/renamed/memory','/new/memory');
  resumed.db.prepare('DELETE FROM files WHERE path=?').run('/renamed/memory');
  assert.deepEqual(resumed.search({query:'memory'}),legacy(resumed,{query:'memory'}));
  assert.equal(resumed.db.prepare('SELECT count(*) n FROM catalog_path_index_v1_keys WHERE path NOT IN (SELECT path FROM files)').get().n,0);
});

test('derived integer identities work with WITHOUT ROWID inventory; bounded batch validation',()=>{
  const db=new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE files(path TEXT PRIMARY KEY) WITHOUT ROWID; INSERT INTO files VALUES(\'/example/memory\')');
    initializePathIndex(db);
    assert.throws(()=>buildPathIndex(db,{maxEntries:0}),/Invalid/);
    assert.equal(buildPathIndex(db,{maxEntries:1,budgetMs:1000}).complete,false);
    assert.equal(buildPathIndex(db).complete,true);
    assert.equal(db.prepare('SELECT path FROM catalog_path_index_v1 WHERE catalog_path_index_v1 MATCH ?').get('"memory"').path,'/example/memory');
    db.exec("UPDATE files SET path='/example/updated'; DELETE FROM files");
    assert.equal(db.prepare('SELECT count(*) n FROM catalog_path_index_v1').get().n,0);
  } finally {db.close();}
});

test('SIGKILL during backfill rolls back keys, FTS and cursor; reconnect completes exact search',t=>{
  const {c,options}=fixture(t);
  c.db.exec('DROP TRIGGER catalog_path_index_v1_file_insert; BEGIN');
  for(let i=0;i<20;i++) add(c,`/crash/memory-${i}`);
  c.db.exec('COMMIT'); initializePathIndex(c.db); c.close();
  const code=`import { HostFileCatalog } from './src/host-file-catalog.mjs';
    const c=new HostFileCatalog(JSON.parse(process.argv[1]));
    const prepare=c.db.prepare.bind(c.db); let inserted=0;
    c.db.prepare=sql=>{ const statement=prepare(sql); if(sql.startsWith('INSERT OR IGNORE INTO catalog_path_index_v1_keys')) {
      const run=statement.run.bind(statement); statement.run=(...args)=>{const value=run(...args);if(++inserted===5)process.kill(process.pid,'SIGKILL');return value;};
    } return statement;}; c.buildPathIndex({maxEntries:10,budgetMs:1000});`;
  const child=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(options)],{encoding:'utf8',timeout:10000});
  assert.equal(child.signal,'SIGKILL',child.stderr);
  const recovered=new HostFileCatalog(options); t.after(()=>recovered.close());
  assert.deepEqual(recovered.pathIndexState(),{cursor:null,complete:0});
  assert.equal(recovered.db.prepare('SELECT count(*) n FROM catalog_path_index_v1_keys').get().n,0);
  assert.equal(recovered.db.prepare('SELECT count(*) n FROM catalog_path_index_v1').get().n,0);
  assert.equal(recovered.search({query:'memory'}).total,20);
  finish(recovered); assert.deepEqual(recovered.search({query:'memory'}),legacy(recovered,{query:'memory'}));
});

test('completed accelerator remains exact across filesystem rescans and content changes',async t=>{
  const {c,options}=fixture(t); c.close();
  options.policy.content={enabled:true,maxBytes:1024,extensions:['.md']};
  const active=new HostFileCatalog(options); t.after(()=>active.close());
  finish(active);
  const document=path.join(options.policy.roots[0],'memory-both.md');
  const contentOnly=path.join(options.policy.roots[0],'other.md');
  fs.writeFileSync(document,'memory'); fs.writeFileSync(contentOnly,'memory');
  const scan=async restart=>{for(let i=0;i<100;i++){const result=await active.scan({restart:i===0&&restart,maxEntries:10,budgetMs:1000,includeStatus:false});if(result.scan.state==='complete')return;}throw Error('Unfinished scan');};
  await scan(false);
  assert.equal(active.search({query:'memory'}).total,2);
  assert.deepEqual(active.search({query:'memory'}),legacy(active,{query:'memory'}));
  fs.writeFileSync(contentOnly,'changed text'); fs.unlinkSync(document);
  await scan(true);
  // Retained, unverified observations retain their original search semantics.
  assert.equal(active.search({query:'memory'}).total,1);
  assert.deepEqual(active.search({query:'memory'}),legacy(active,{query:'memory'}));
  const changed={...options,policy:{...options.policy,metadataOnlyPrefixes:[options.policy.roots[0]]}};
  active.close(); assert.throws(()=>new HostFileCatalog(changed),/Policy changed/);
});
