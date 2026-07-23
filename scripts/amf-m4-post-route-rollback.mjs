#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planM4PostRouteRollback, runM4PostRouteRollback } from '../src/operator/m4-post-route-rollback.mjs';
function fail(code) { const e = new Error(code); e.code = code; throw e; }
function parse(argv) { const operation=argv[2], allowed=operation==='plan'?new Set(['--config']):operation==='run'?new Set(['--config','--confirmed-plan-digest']):null; if(!allowed)fail('m4_post_route_rollback_cli_argument_invalid'); const values={}; for(let i=3;i<argv.length;i+=2){if(!allowed.has(argv[i])||values[argv[i]]||!argv[i+1])fail('m4_post_route_rollback_cli_argument_invalid');values[argv[i]]=argv[i+1];}if([...allowed].some(k=>!values[k])||!path.isAbsolute(values['--config']))fail('m4_post_route_rollback_cli_argument_invalid');return {operation,configPath:values['--config'],confirmedPlanDigest:values['--confirmed-plan-digest']}; }
export async function runM4PostRouteRollbackCli(argv=process.argv,deps={adapters:{}}){const request=parse(argv);return request.operation==='plan'?planM4PostRouteRollback(request,deps):runM4PostRouteRollback(request,deps);}
if(process.argv[1]&&fileURLToPath(import.meta.url)===path.resolve(process.argv[1]))runM4PostRouteRollbackCli().then(v=>process.stdout.write(`${JSON.stringify({ok:true,...v})}\n`)).catch(e=>{process.stderr.write(`${JSON.stringify({ok:false,error:e?.code??'m4_post_route_rollback_cli_failed'})}\n`);process.exitCode=78;});
