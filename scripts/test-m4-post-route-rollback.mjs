import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { M4_CUTOVER_CANARY_FAILURE_CATEGORIES } from '../src/migration/m4-cutover-canary.mjs';
import { createM4PostRouteObservation } from '../src/migration/m4-post-route-observation.mjs';
import { planM4PostRouteRollback, runM4PostRouteRollback, verifyM4PostRouteRollbackResult } from '../src/operator/m4-post-route-rollback.mjs';
import { runM4PostRouteRollbackCli } from './amf-m4-post-route-rollback.mjs';
const sha=v=>`sha256:${crypto.createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:canonicalJson(v)).digest('hex')}`; const key={schema:'amf.migration-signing-key/v1',keyId:'rollback-observation-key',key:Buffer.alloc(32,7).toString('base64')}; const dg=`sha256:${'a'.repeat(64)}`; const cp=id=>({id,digest:dg}); const ev=id=>({manifestId:id,digest:dg,signature:'A'.repeat(43)});
function fixture(t, hooks={rollback:async()=>{},readiness:async()=>true}) { const root=fs.mkdtempSync(path.join(os.homedir(),'.amf-m4-rollback-test-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const artifacts=path.join(root,'artifacts'), backups=path.join(root,'backups');fs.mkdirSync(artifacts,{mode:0o700});fs.mkdirSync(backups,{mode:0o700});const before=Buffer.from('AMF_CONVERSATION_READER_MODE=shadow\nAMF_CONVERSATION_EXTRACTOR_MODE=legacy\n'), after=Buffer.from('AMF_CONVERSATION_READER_MODE=active\nAMF_CONVERSATION_EXTRACTOR_MODE=v3\n'), write=(name,value)=>{const target=path.join(root,name);fs.writeFileSync(target,value,{mode:0o600});return target;};const runtime=write('runtime.env',after);const body={schema:'amf.m4-route-execution-result/v1',executionId:'route-execution-one',revision:1,state:'active',planDigest:dg,authorization:ev('route-authorization'),selectorEvidence:ev('selector-scope'),targetRouteRevisions:{publicReader:cp('public-reader'),extractorReader:cp('extractor-reader')},rollbackRevision:cp('route-rollback'),beforeDigest:sha(before),afterDigest:sha(after),backup:{id:'route-execution-one-r1',digest:sha(before)},postCommit:{state:'passed'},readiness:{state:'passed'},rollback:{state:'not_needed'}};const route={...body,integrity:{algorithm:'sha256',payloadDigest:sha(body)}};const observation=createM4PostRouteObservation({manifestId:'failed-observation',revision:1,routeExecutionResult:route,policy:{start:'2026-07-23T00:00:00Z',end:'2026-07-23T01:00:00Z',maxSamples:1,queue:{maxDepth:0,maxOldestAgeMs:0},latency:{maxP95Ms:0,maxP99Ms:0,maxRequestMs:0},allowed5xx:0,zeroRequiredCategories:[...M4_CUTOVER_CANARY_FAILURE_CATEGORIES]},observations:{start:'2026-07-23T00:00:00Z',end:'2026-07-23T00:01:00Z',sampleCount:1,queue:{maxDepth:1,maxOldestAgeMs:0},latency:{p95Ms:0,p99Ms:0,maxRequestMs:0},errors:{http5xx:0,...Object.fromEntries(M4_CUTOVER_CANARY_FAILURE_CATEGORIES.map(x=>[x,0]))}},keyDocument:key});const routePath=write('route.json',Buffer.from(`${canonicalJson(route)}\n`)),observationPath=write('observation.json',Buffer.from(`${canonicalJson(observation)}\n`)),keyPath=write('key.json',Buffer.from(`${canonicalJson(key)}\n`));const backup=path.join(backups,'m4','route-execution','route-execution-one-r1');fs.mkdirSync(backup,{recursive:true,mode:0o700});fs.chmodSync(path.join(backups,'m4'),0o700);fs.chmodSync(path.join(backups,'m4','route-execution'),0o700);write;fs.writeFileSync(path.join(backup,'runtime-config.before'),before,{mode:0o600});fs.writeFileSync(path.join(backup,'metadata.json'),`${canonicalJson({schema:'amf.m4-route-backup/v1',backupId:'route-execution-one-r1',beforeDigest:sha(before),size:before.length})}\n`,{mode:0o600});const configPath=write('config.json',Buffer.from(`${canonicalJson({schema:'amf.m4-post-route-rollback-input/v1',rollbackId:'post-route-rollback',revision:1,artifactRoot:artifacts,routeExecutionResultPath:routePath,observationManifestPath:observationPath,observationKeyPath:keyPath,runtimeConfigPath:runtime,backupRoot:backups,deploymentAdapter:'test-adapter',rollbackHook:'rollback-hook',readinessHook:'readiness-hook'})}\n`));return {root,before,after,runtime,routePath,observationPath,configPath,artifacts,backup,deps:{adapters:{'test-adapter':{rollback:{'rollback-hook':hooks.rollback},readiness:{'readiness-hook':hooks.readiness}}}}}; }
function privateJson(target, value) { fs.writeFileSync(target, `${canonicalJson(value)}\n`, { mode: 0o600 }); }
function resealRoute(value) { const { integrity, ...body } = value; void integrity; return { ...body, integrity: { algorithm: 'sha256', payloadDigest: sha(body) } }; }
function resealRollbackResult(value) { const { integrity, ...body } = value; void integrity; return { ...body, integrity: { algorithm: 'sha256', payloadDigest: sha(body) } }; }
function observationForRoute(route, { failed = true, manifestId = 'alternate-observation' } = {}) {
  return createM4PostRouteObservation({
    manifestId, revision: 1, routeExecutionResult: route,
    policy: { start: '2026-07-23T00:00:00Z', end: '2026-07-23T01:00:00Z', maxSamples: 1,
      queue: { maxDepth: 0, maxOldestAgeMs: 0 }, latency: { maxP95Ms: 0, maxP99Ms: 0, maxRequestMs: 0 },
      allowed5xx: 0, zeroRequiredCategories: [...M4_CUTOVER_CANARY_FAILURE_CATEGORIES] },
    observations: { start: '2026-07-23T00:00:00Z', end: '2026-07-23T00:01:00Z', sampleCount: 1,
      queue: { maxDepth: failed ? 1 : 0, maxOldestAgeMs: 0 }, latency: { p95Ms: 0, p99Ms: 0, maxRequestMs: 0 },
      errors: { http5xx: 0, ...Object.fromEntries(M4_CUTOVER_CANARY_FAILURE_CATEGORIES.map(name => [name, 0])) } },
    keyDocument: key
  });
}
function outputPath(value) { return path.join(value.artifacts, 'm4', 'post-route-rollback', 'post-route-rollback-r1.json'); }
function lockPath(value) { return `${value.runtime}.m4-route-executor.lock`; }
function tree(root) {
  const visit = directory => fs.readdirSync(directory).sort().flatMap(name => {
    const target = path.join(directory, name); const stat = fs.lstatSync(target);
    return [`${path.relative(root, target)}:${stat.mode & 0o777}:${stat.size}`, ...(stat.isDirectory() ? visit(target) : [])];
  });
  return visit(root);
}
test('plans with zero writes then restores exact bytes and writes verified result in hook order',async t=>{const calls=[];const f=fixture(t,{rollback:async()=>calls.push('rollback'),readiness:async()=>{calls.push('readiness');return true;}});const before=tree(f.root);const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);assert.equal(plan.state,'planned');assert.deepEqual(tree(f.root),before);const result=await runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps);assert.equal(result.state,'rolled_back');assert.deepEqual(calls,['rollback','readiness']);assert.deepEqual(fs.readFileSync(f.runtime),f.before);assert.deepEqual(verifyM4PostRouteRollbackResult(result),result);assert.equal(fs.existsSync(`${f.runtime}.m4-route-executor.lock`),false);});
test('binding, config/backup drift, collisions and failures fail closed or retain lock',async t=>{for(const mutate of [f=>fs.writeFileSync(f.runtime,'changed',{mode:0o600}),f=>fs.writeFileSync(path.join(f.backup,'metadata.json'),'{}',{mode:0o600}),f=>fs.linkSync(f.routePath,`${f.routePath}.link`)]){const f=fixture(t);mutate(f);assert.throws(()=>planM4PostRouteRollback({configPath:f.configPath},f.deps),/m4_post_route_rollback_/);}const failed=fixture(t,{rollback:async()=>{throw new Error('fail')},readiness:async()=>true});const plan=planM4PostRouteRollback({configPath:failed.configPath},failed.deps);const result=await runM4PostRouteRollback({configPath:failed.configPath,confirmedPlanDigest:plan.confirmationDigest},failed.deps);assert.equal(result.state,'rollback_failed');assert.equal(fs.existsSync(`${failed.runtime}.m4-route-executor.lock`),true);});
test('result verifier rejects digest tampering',async t=>{const f=fixture(t);const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);const result=await runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps);result.integrity.payloadDigest=dg;assert.throws(()=>verifyM4PostRouteRollbackResult(result),/m4_post_route_rollback_result_digest_mismatch/);});
test('pre-mutation fault releases only its pinned lock',async t=>{const f=fixture(t);f.deps.faultAt=label=>{if(label==='before-restore-write')throw new Error('fault');};const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);await assert.rejects(runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps),/m4_post_route_rollback_run_failed/);assert.equal(fs.existsSync(`${f.runtime}.m4-route-executor.lock`),false);assert.deepEqual(fs.readFileSync(f.runtime),f.after);});
test('post-mutation fault retains its pinned lock',async t=>{const f=fixture(t);f.deps.faultAt=label=>{if(label==='after-restore-write')throw new Error('fault');};const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);const result=await runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps);assert.equal(result.state,'rollback_failed');assert.equal(fs.existsSync(`${f.runtime}.m4-route-executor.lock`),true);});
test('plan, result, and normalized errors never leak paths or configuration bytes',async t=>{const f=fixture(t);const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);const result=await runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps);for(const value of [plan,result]){const text=canonicalJson(value);assert.equal(text.includes(f.root),false);assert.equal(text.includes('AMF_CONVERSATION_READER_MODE'),false);assert.equal(text.includes('AMF_CONVERSATION_EXTRACTOR_MODE'),false);}const bad=fixture(t);fs.chmodSync(bad.observationPath,0o640);assert.throws(()=>planM4PostRouteRollback({configPath:bad.configPath},bad.deps),error=>error.code==='m4_post_route_rollback_input_invalid'&&!error.message.includes(bad.root));});
test('confirmation rejects config byte drift before lock',async t=>{const f=fixture(t);const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);fs.appendFileSync(f.configPath,' ');await assert.rejects(runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps),/confirmation|input/);assert.equal(fs.existsSync(`${f.runtime}.m4-route-executor.lock`),false);});
test('same R1 lock collision fails without mutation',async t=>{const f=fixture(t);const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);fs.writeFileSync(`${f.runtime}.m4-route-executor.lock`,'other',{mode:0o600});await assert.rejects(runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps),/lock_exists/);assert.deepEqual(fs.readFileSync(f.runtime),f.after);});
test('existing rollback artifact collision fails closed',t=>{const f=fixture(t);const output=path.join(f.artifacts,'m4','post-route-rollback');fs.mkdirSync(output,{recursive:true,mode:0o700});fs.chmodSync(path.join(f.artifacts,'m4'),0o700);fs.writeFileSync(path.join(output,'post-route-rollback-r1.json'),'x',{mode:0o600});assert.throws(()=>planM4PostRouteRollback({configPath:f.configPath},f.deps),/artifact_exists/);});
test('unsafe input mode and hardlink are rejected',t=>{const f=fixture(t);fs.chmodSync(f.observationPath,0o640);assert.throws(()=>planM4PostRouteRollback({configPath:f.configPath},f.deps),/input_invalid/);const g=fixture(t);fs.linkSync(g.routePath,`${g.routePath}.link`);assert.throws(()=>planM4PostRouteRollback({configPath:g.configPath},g.deps),/input_invalid/);});
test('symlinked input and broad backup root are rejected',t=>{const f=fixture(t);const linked=`${f.routePath}.sym`;fs.symlinkSync(f.routePath,linked);const config=JSON.parse(fs.readFileSync(f.configPath));config.routeExecutionResultPath=linked;fs.writeFileSync(f.configPath,`${canonicalJson(config)}\n`,{mode:0o600});assert.throws(()=>planM4PostRouteRollback({configPath:f.configPath},f.deps),/input_invalid/);const g=fixture(t);fs.chmodSync(g.backup,0o755);assert.throws(()=>planM4PostRouteRollback({configPath:g.configPath},g.deps),/backup_invalid/);});
test('hostile adapter getter and fault accessor are rejected',t=>{const f=fixture(t);Object.defineProperty(f.deps,'adapters',{get(){return {};}});assert.throws(()=>planM4PostRouteRollback({configPath:f.configPath},f.deps),/adapter_invalid/);const g=fixture(t);Object.defineProperty(g.deps,'faultAt',{get(){return ()=>{};}});assert.throws(()=>planM4PostRouteRollback({configPath:g.configPath},g.deps),/adapter_invalid/);});
test('readiness false produces exact rollback-failed state tuple',async t=>{const f=fixture(t,{rollback:async()=>{},readiness:async()=>false});const plan=planM4PostRouteRollback({configPath:f.configPath},f.deps);const result=await runM4PostRouteRollback({configPath:f.configPath,confirmedPlanDigest:plan.confirmationDigest},f.deps);assert.deepEqual([result.restore.state,result.rollbackHook.state,result.readiness.state],['passed','passed','failed']);assert.equal(fs.existsSync(`${f.runtime}.m4-route-executor.lock`),true);});
test('CLI parser rejects invalid requests and accepts injected fixed registry',async t=>{const f=fixture(t);await assert.rejects(runM4PostRouteRollbackCli(['node','cli','bad'],f.deps),/cli_argument_invalid/);await assert.rejects(runM4PostRouteRollbackCli(['node','cli','plan','--config','relative'],f.deps),/cli_argument_invalid/);const plan=await runM4PostRouteRollbackCli(['node','cli','plan','--config',f.configPath],f.deps);assert.equal(plan.state,'planned');});

test('valid but differently bound R1 and signed R2 evidence is rejected', t => {
  const routeMismatch = fixture(t);
  const route = JSON.parse(fs.readFileSync(routeMismatch.routePath, 'utf8'));
  route.authorization = ev('different-authorization');
  const alternate = resealRoute(route);
  privateJson(routeMismatch.observationPath, observationForRoute(alternate));
  assert.throws(() => planM4PostRouteRollback({ configPath: routeMismatch.configPath }, routeMismatch.deps),
    /m4_post_route_rollback_evidence_invalid/);

  const nonActive = fixture(t);
  const stopped = JSON.parse(fs.readFileSync(nonActive.routePath, 'utf8'));
  stopped.state = 'rolled_back'; stopped.rollback.state = 'passed';
  privateJson(nonActive.routePath, resealRoute(stopped));
  assert.throws(() => planM4PostRouteRollback({ configPath: nonActive.configPath }, nonActive.deps),
    /m4_post_route_rollback_evidence_invalid/);

  const passedObservation = fixture(t);
  const active = JSON.parse(fs.readFileSync(passedObservation.routePath, 'utf8'));
  privateJson(passedObservation.observationPath, observationForRoute(active, { failed: false }));
  assert.throws(() => planM4PostRouteRollback({ configPath: passedObservation.configPath }, passedObservation.deps),
    /m4_post_route_rollback_evidence_invalid/);
});

test('confirmed backup file and directory identity replacement fails before mutation', async t => {
  for (const selected of ['metadata.json', 'runtime-config.before', 'directory']) {
    await t.test(selected, async child => {
      const f = fixture(child); const plan = planM4PostRouteRollback({ configPath: f.configPath }, f.deps);
      if (selected === 'directory') {
        const old = `${f.backup}.old`; fs.renameSync(f.backup, old); fs.mkdirSync(f.backup, { mode: 0o700 });
        for (const name of ['metadata.json', 'runtime-config.before']) {
          fs.copyFileSync(path.join(old, name), path.join(f.backup, name)); fs.chmodSync(path.join(f.backup, name), 0o600);
        }
      } else {
        const target = path.join(f.backup, selected); const bytes = fs.readFileSync(target); fs.unlinkSync(target);
        fs.writeFileSync(target, bytes, { mode: 0o600 });
      }
      await assert.rejects(runM4PostRouteRollback({ configPath: f.configPath, confirmedPlanDigest: plan.confirmationDigest }, f.deps),
        /m4_post_route_rollback_(confirmation|input_changed)/);
      assert.deepEqual(fs.readFileSync(f.runtime), f.after); assert.equal(fs.existsSync(lockPath(f)), false);
    });
  }
});

test('backup wire shape rejects extra entries, unsafe files, hardlinks, and symlinks', t => {
  const extra = fixture(t); fs.writeFileSync(path.join(extra.backup, 'extra'), 'x', { mode: 0o600 });
  assert.throws(() => planM4PostRouteRollback({ configPath: extra.configPath }, extra.deps), /backup_invalid/);

  const broad = fixture(t); fs.chmodSync(path.join(broad.backup, 'metadata.json'), 0o640);
  assert.throws(() => planM4PostRouteRollback({ configPath: broad.configPath }, broad.deps), /backup_invalid/);

  const linked = fixture(t); fs.linkSync(path.join(linked.backup, 'runtime-config.before'), path.join(linked.root, 'backup-link'));
  assert.throws(() => planM4PostRouteRollback({ configPath: linked.configPath }, linked.deps), /backup_invalid/);

  const symbolic = fixture(t); const source = path.join(symbolic.root, 'saved-copy');
  fs.copyFileSync(path.join(symbolic.backup, 'runtime-config.before'), source); fs.chmodSync(source, 0o600);
  fs.unlinkSync(path.join(symbolic.backup, 'runtime-config.before'));
  fs.symlinkSync(source, path.join(symbolic.backup, 'runtime-config.before'));
  assert.throws(() => planM4PostRouteRollback({ configPath: symbolic.configPath }, symbolic.deps), /backup_invalid/);
});

test('nested adapter accessors and throwing proxies fail closed without private errors', t => {
  const getter = fixture(t); Object.defineProperty(getter.deps.adapters['test-adapter'].rollback, 'rollback-hook',
    { enumerable: true, get() { throw new Error(getter.root); } });
  assert.throws(() => planM4PostRouteRollback({ configPath: getter.configPath }, getter.deps),
    error => error.code?.startsWith('m4_post_route_rollback_') && !error.message.includes(getter.root));

  const proxied = fixture(t); proxied.deps.adapters = new Proxy({}, { ownKeys() { throw new Error(proxied.root); } });
  assert.throws(() => planM4PostRouteRollback({ configPath: proxied.configPath }, proxied.deps),
    error => error.code?.startsWith('m4_post_route_rollback_') && !error.message.includes(proxied.root));
});

test('rollback-hook failure and readiness exceptions produce only valid failure tuples', async t => {
  const hookFailure = fixture(t, { rollback: async () => { throw new Error('private'); }, readiness: async () => true });
  const hookPlan = planM4PostRouteRollback({ configPath: hookFailure.configPath }, hookFailure.deps);
  const hookResult = await runM4PostRouteRollback({ configPath: hookFailure.configPath,
    confirmedPlanDigest: hookPlan.confirmationDigest }, hookFailure.deps);
  assert.deepEqual([hookResult.restore.state, hookResult.rollbackHook.state, hookResult.readiness.state],
    ['passed', 'failed', 'not_run']); assert.equal(fs.existsSync(lockPath(hookFailure)), true);

  const readinessFailure = fixture(t, { rollback: async () => {}, readiness: async () => { throw new Error('private'); } });
  const readinessPlan = planM4PostRouteRollback({ configPath: readinessFailure.configPath }, readinessFailure.deps);
  const readinessResult = await runM4PostRouteRollback({ configPath: readinessFailure.configPath,
    confirmedPlanDigest: readinessPlan.confirmationDigest }, readinessFailure.deps);
  assert.deepEqual([readinessResult.restore.state, readinessResult.rollbackHook.state, readinessResult.readiness.state],
    ['passed', 'passed', 'failed']); assert.equal(fs.existsSync(lockPath(readinessFailure)), true);
});

test('post-restore failure preserves the exact pinned lock inode', async t => {
  const f = fixture(t); let pinned;
  f.deps.faultAt = label => {
    if (label === 'after-restore-write') {
      const stat = fs.lstatSync(lockPath(f), { bigint: true }); pinned = [String(stat.dev), String(stat.ino)];
      throw new Error('fault');
    }
  };
  const plan = planM4PostRouteRollback({ configPath: f.configPath }, f.deps);
  const result = await runM4PostRouteRollback({ configPath: f.configPath, confirmedPlanDigest: plan.confirmationDigest }, f.deps);
  const retained = fs.lstatSync(lockPath(f), { bigint: true });
  assert.deepEqual([String(retained.dev), String(retained.ino)], pinned);
  assert.deepEqual([result.restore.state, result.rollbackHook.state, result.readiness.state],
    ['failed', 'not_run', 'not_run']);
});

test('result-write fault and target race retain lock and restored bytes without success evidence', async t => {
  const faulted = fixture(t); faulted.deps.faultAt = label => { if (label === 'before-result-write') throw new Error('fault'); };
  const faultPlan = planM4PostRouteRollback({ configPath: faulted.configPath }, faulted.deps);
  await assert.rejects(runM4PostRouteRollback({ configPath: faulted.configPath,
    confirmedPlanDigest: faultPlan.confirmationDigest }, faulted.deps), /m4_post_route_rollback_run_failed/);
  assert.deepEqual(fs.readFileSync(faulted.runtime), faulted.before);
  assert.equal(fs.existsSync(lockPath(faulted)), true); assert.equal(fs.existsSync(outputPath(faulted)), false);

  let raceTarget;
  const raced = fixture(t, { rollback: async () => {}, readiness: async () => {
    fs.writeFileSync(raceTarget, 'occupied\n', { mode: 0o600 }); return true;
  } });
  raceTarget = outputPath(raced);
  const racePlan = planM4PostRouteRollback({ configPath: raced.configPath }, raced.deps);
  await assert.rejects(runM4PostRouteRollback({ configPath: raced.configPath,
    confirmedPlanDigest: racePlan.confirmationDigest }, raced.deps), /m4_post_route_rollback_result_failed/);
  assert.deepEqual(fs.readFileSync(raced.runtime), raced.before);
  assert.equal(fs.existsSync(lockPath(raced)), true); assert.equal(fs.readFileSync(raceTarget, 'utf8'), 'occupied\n');
});

test('lock replacement is never unlinked before or after mutation', async t => {
  for (const phase of ['before-restore-write', 'hook']) {
    await t.test(phase, async child => {
      let f; const replace = () => {
        fs.unlinkSync(lockPath(f)); fs.writeFileSync(lockPath(f), `replacement-${phase}\n`, { mode: 0o600 });
      };
      f = phase === 'hook'
        ? fixture(child, { rollback: async () => { replace(); throw new Error('fault'); }, readiness: async () => true })
        : fixture(child);
      if (phase !== 'hook') f.deps.faultAt = label => { if (label === phase) { replace(); throw new Error('fault'); } };
      const plan = planM4PostRouteRollback({ configPath: f.configPath }, f.deps);
      await assert.rejects(runM4PostRouteRollback({ configPath: f.configPath,
        confirmedPlanDigest: plan.confirmationDigest }, f.deps), /m4_post_route_rollback_/);
      assert.equal(fs.readFileSync(lockPath(f), 'utf8'), `replacement-${phase}\n`);
    });
  }
});

test('result verifier rejects self-digested impossible evidence and state combinations', async t => {
  const f = fixture(t); const plan = planM4PostRouteRollback({ configPath: f.configPath }, f.deps);
  const result = await runM4PostRouteRollback({ configPath: f.configPath, confirmedPlanDigest: plan.confirmationDigest }, f.deps);
  const mutations = [
    value => { value.routeExecution.executionId = 'different-route'; },
    value => { value.backup.id = 'different-backup'; },
    value => { value.observation.signature = 'A'.repeat(42); },
    value => { value.activeDigest = value.restoredDigest; },
    value => { value.state = 'rollback_failed'; },
    value => { value.state = 'rolled_back'; value.readiness.state = 'failed'; },
    value => { value.restore.state = 'failed'; value.rollbackHook.state = 'passed'; value.readiness.state = 'not_run'; },
    value => { value.rollbackId = 'a'.repeat(80); },
    value => { value.extra = true; }
  ];
  for (const mutate of mutations) {
    const invalid = structuredClone(result); mutate(invalid); const resealed = resealRollbackResult(invalid);
    assert.throws(() => verifyM4PostRouteRollbackResult(resealed), /m4_post_route_rollback_result_invalid/);
  }
  assert.throws(() => verifyM4PostRouteRollbackResult(new Proxy({}, {
    ownKeys() { throw new Error('private'); }
  })), /m4_post_route_rollback_result_invalid/);
});

test('derived rollback artifact identifier overflow fails before filesystem writes', t => {
  const f = fixture(t); const config = JSON.parse(fs.readFileSync(f.configPath, 'utf8'));
  config.rollbackId = 'a'.repeat(80); privateJson(f.configPath, config);
  assert.throws(() => planM4PostRouteRollback({ configPath: f.configPath }, f.deps),
    /m4_post_route_rollback_input_invalid/);
  assert.equal(fs.existsSync(path.join(f.artifacts, 'm4')), false);
});

test('CLI parser rejects missing, duplicate, and extra flags', async t => {
  const f = fixture(t);
  for (const argv of [
    ['node', 'cli', 'plan'],
    ['node', 'cli', 'plan', '--config', f.configPath, '--config', f.configPath],
    ['node', 'cli', 'plan', '--extra', f.configPath],
    ['node', 'cli', 'run', '--config', f.configPath],
    ['node', 'cli', 'run', '--config', f.configPath, '--confirmed-plan-digest', dg, '--extra', 'x']
  ]) await assert.rejects(runM4PostRouteRollbackCli(argv, f.deps), /cli_argument_invalid/);
});
