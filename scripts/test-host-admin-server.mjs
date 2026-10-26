import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,mkdir,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHostAdminServer,normalizeHealth,normalizeQuality,readPrivateFile,validateHostAdminConfig,runHealthProbe,startHostAdmin} from '../src/host-admin-server.mjs';

const token = 'x'.repeat(48);
test('every admin route refuses unauthenticated calls and writes; query input cannot select upstream resources',async () => {
  const calls = [];
  const catalog = {status:() => ({scan:{state:'complete'}}),search:value => {calls.push(value);return {items:[],total:0};},suggestions:() => []};
  const api = createHostAdminServer({catalog,token});
  await new Promise(resolve => api.server.listen(0,'127.0.0.1',resolve));
  const origin = `http://127.0.0.1:${api.server.address().port}`;
  try {
    for (const path of ['/v1/status','/v1/files','/v1/suggestions']) assert.equal((await fetch(origin+path)).status,401);
    const headers = {Authorization:`Bearer ${token}`};
    assert.equal((await fetch(origin+'/v1/status',{method:'POST',headers})).status,405);
    for (const path of ['/v1/files?limit=-1','/v1/files?limit=101','/v1/files?offset=NaN','/v1/files?query=a&query=b','/v1/status?url=http://foreign','/v1/files?domain=../secret']) assert.equal((await fetch(origin+path,{headers})).status,400,path);
    const status = await (await fetch(origin+'/v1/status',{headers})).json();
    assert.equal(status.overall,'degraded');assert.equal(status.quality.overall,'unknown');
    assert.equal((await fetch(origin+'/v1/files?query=%22%3BOR%201%3D1&domain=example',{headers})).status,200);
    assert.equal(calls[0].query,'";OR 1=1');
    assert.equal((await fetch(origin+'/unknown',{headers})).status,404);
  } finally {await new Promise(resolve => {api.server.close(resolve);api.server.closeAllConnections();});}
});
test('health and quality require valid fresh evidence and omit private payload fields',() => {
  const now = Date.now(),generatedAt = new Date(now).toISOString();
  const result = normalizeHealth({schema:'amf.health-report/v1',generatedAt,overall:'healthy',checks:[{id:'capture',status:'healthy',summary:'ready',evidence:{pending:0,secret:'not exported'}}]},now);
  assert.equal(result.overall,'healthy');assert.equal(result.checks[0].evidence.secret,undefined);
  assert.equal(normalizeHealth({...result,generatedAt:new Date(now-400000).toISOString()},now).overall,'unknown');
  assert.equal(normalizeQuality(null).overall,'unknown');
  const quality = normalizeQuality({schema:'amf.memory-quality-report/v1',generatedAt,overall:'healthy',checks:[{id:'precision',status:'healthy',metric:1,unit:'ratio',text:'not exported'}]},now);
  assert.equal(quality.checks[0].text,undefined);
});
test('private file reader rejects links, broad permissions and oversized files',async () => {
  const root = await mkdtemp(join(tmpdir(),'amf-private-'));
  try {
    await mkdir(join(root,'private'),{mode:0o700});const path = join(root,'private','config');
    await writeFile(path,'{}',{mode:0o600});assert.equal(await readPrivateFile(path),'{}');
    await symlink(path,join(root,'private','alias'));await assert.rejects(readPrivateFile(join(root,'private','alias')));
    await assert.rejects(readPrivateFile(path,1));
    await writeFile(join(root,'private','broad'),'{}',{mode:0o644});await assert.rejects(readPrivateFile(join(root,'private','broad')));
  } finally {await rm(root,{recursive:true,force:true});}
});
test('configuration refuses nonloopback binding and arbitrary probe values',() => {
  const config = {schema:'amf.host-admin-config/v1',bind:'127.0.0.1',port:15001,policyPath:'/example/policy',databasePath:'/example/catalog',tokenFile:'/example/token'};
  assert.equal(validateHostAdminConfig(config).scanBudgetMs,1000);
  assert.throws(() => validateHostAdminConfig({...config,bind:'0.0.0.0'}));
  assert.throws(() => validateHostAdminConfig({...config,healthProbe:{command:'sh',args:[],intervalMs:60000,timeoutMs:1000}}));
});
test('probe degraded exit status is preserved and malformed output stays unknown',async () => {
  const value = await runHealthProbe({command:process.execPath,args:['-e',`process.stdout.write(JSON.stringify({schema:'amf.health-report/v1',overall:'degraded'}));process.exitCode=1`],timeoutMs:1000});
  assert.equal(value.overall,'degraded');
  assert.equal(await runHealthProbe({command:process.execPath,args:['-e',`process.stdout.write('invalid')`],timeoutMs:1000}),null);
});


test('background scan ticks request minimal results without aggregate status',async ()=>{
  const {HostFileCatalog}=await import('../src/host-file-catalog.mjs');
  const root=await mkdtemp(join(tmpdir(),'amf-admin-tick-'));
  await mkdir(join(root,'private'),{mode:0o700});await mkdir(join(root,'source'));
  await writeFile(join(root,'source','one.txt'),'example');
  const privateRoot=join(root,'private'),policyPath=join(privateRoot,'policy'),tokenFile=join(privateRoot,'token');
  await writeFile(policyPath,JSON.stringify({schema:'amf.host-file-catalog-policy/v1',hostId:'test-host',roots:[join(root,'source')],excludePrefixes:[],metadataOnlyPrefixes:[],domains:[],content:{enabled:false,maxBytes:1024,extensions:[]}}),{mode:0o600});
  await writeFile(tokenFile,token,{mode:0o600});
  // Reserve an ephemeral loopback port, then use the production config validator.
  const {createServer}=await import('node:net');const reservation=createServer();
  await new Promise(resolve=>reservation.listen(0,'127.0.0.1',resolve));const port=reservation.address().port;
  await new Promise(resolve=>reservation.close(resolve));
  const originalStatus=HostFileCatalog.prototype.status,originalScan=HostFileCatalog.prototype.scan;
  let aggregates=0;const calls=[];
  HostFileCatalog.prototype.status=function(){aggregates++;return originalStatus.call(this);};
  HostFileCatalog.prototype.scan=function(options){calls.push(options);return originalScan.call(this,options);};
  let service;
  try {
    service=await startHostAdmin({schema:'amf.host-admin-config/v1',bind:'127.0.0.1',port,policyPath,tokenFile,databasePath:join(privateRoot,'catalog.sqlite'),scanIntervalMs:100,scanMaxEntries:1});
    const deadline=Date.now()+5000;
    while((calls.length<4) && Date.now()<deadline) await new Promise(resolve=>setTimeout(resolve,25));
    assert.ok(calls.length>=4);assert.ok(calls.every(options=>options.includeStatus===false));assert.equal(aggregates,0);
    const report=await (await fetch(`http://127.0.0.1:${port}/v1/status`,{headers:{Authorization:`Bearer ${token}`}})).json();
    assert.equal(aggregates,1);assert.equal(report.catalog.scan.state,'complete');
  } finally {
    await service?.close();HostFileCatalog.prototype.status=originalStatus;HostFileCatalog.prototype.scan=originalScan;
    await rm(root,{recursive:true,force:true});
  }
});
