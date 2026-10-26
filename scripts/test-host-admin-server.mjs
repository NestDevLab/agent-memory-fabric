import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,mkdir,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHostAdminServer,normalizeHealth,normalizeQuality,readPrivateFile,validateHostAdminConfig,runHealthProbe} from '../src/host-admin-server.mjs';

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
