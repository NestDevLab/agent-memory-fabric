// Synthetic, in-memory benchmark; never opens a host inventory or source tree.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { HostFileCatalog } from '../src/host-file-catalog.mjs';
import { initializePathIndex, buildPathIndex } from '../src/host-catalog-path-index.mjs';
const rows=Number(process.argv[2]??100000);
if(!Number.isInteger(rows)||rows<1000||rows>500000) throw Error('Rows must be 1000..500000');
const db=new DatabaseSync(':memory:');
try {
  db.exec(`CREATE TABLE files(path TEXT PRIMARY KEY,kind TEXT,size INTEGER,domain TEXT,classification_prefix TEXT,confidence REAL,content_state TEXT,observed_at TEXT,generation INTEGER);
    CREATE TABLE state(generation INTEGER); INSERT INTO state VALUES(0);
    CREATE VIRTUAL TABLE texts USING fts5(path UNINDEXED,body); BEGIN`);
  const insert=db.prepare("INSERT INTO files(path,kind,domain,generation) VALUES(?,'file',?,0)");
  for(let n=0;n<rows;n++) insert.run(`/example/tree/${n%1000===0?'memory':'document'}-${String(n).padStart(8,'0')}.md`,n%2?'notes':'docs');
  db.exec('COMMIT'); initializePathIndex(db);
  const catalog={db};
  const search=()=>HostFileCatalog.prototype.search.call(catalog,{query:'memory',limit:50,offset:1,domain:'docs'});
  const measure=()=>{const times=[];let result;for(let n=0;n<5;n++){const start=performance.now();result=search();times.push(performance.now()-start);}times.sort((a,b)=>a-b);return {medianMs:times[2],result};};
  const legacy=measure(), started=performance.now();let batches=0;
  while(!buildPathIndex(db,{maxEntries:1000,budgetMs:50}).complete) batches++;
  const buildMs=performance.now()-started, indexed=measure();
  assert.deepEqual(indexed.result,legacy.result);
  const plan=db.prepare('EXPLAIN QUERY PLAN SELECT rowid FROM catalog_path_index_v1 WHERE catalog_path_index_v1 MATCH ?').all('"memory"').map(x=>x.detail);
  assert.ok(plan.some(x=>x.includes('VIRTUAL TABLE INDEX')));
  console.log(JSON.stringify({rows,legacyMedianMs:legacy.medianMs,indexedMedianMs:indexed.medianMs,speedup:legacy.medianMs/indexed.medianMs,total:indexed.result.total,buildMs,batches,databaseBytes:db.prepare('PRAGMA page_count').get().page_count*db.prepare('PRAGMA page_size').get().page_size,plan}));
} finally {db.close();}
