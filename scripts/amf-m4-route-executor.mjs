#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planM4RouteExecutor, runM4RouteExecutor } from '../src/operator/m4-route-executor.mjs';
function fail(code) { const e = new Error(code); e.code = code; throw e; }
function parse(argv) { const operation = argv[2]; const allowed = operation === 'plan' ? new Set(['--config']) : operation === 'run' ? new Set(['--config', '--confirmed-plan-digest']) : null; if (!allowed) fail('m4_route_executor_cli_argument_invalid'); const values = {}; for (let i = 3; i < argv.length; i += 2) { if (!allowed.has(argv[i]) || values[argv[i]] || !argv[i + 1]) fail('m4_route_executor_cli_argument_invalid'); values[argv[i]] = argv[i + 1]; } if ([...allowed].some(k => !values[k]) || !path.isAbsolute(values['--config'])) fail('m4_route_executor_cli_argument_invalid'); return { operation, configPath: values['--config'], confirmedPlanDigest: values['--confirmed-plan-digest'] }; }
export async function runM4RouteExecutorCli(argv = process.argv, dependencies = { adapters: {} }) { const input = parse(argv); return input.operation === 'plan' ? planM4RouteExecutor(input, dependencies) : runM4RouteExecutor(input, dependencies); }
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) runM4RouteExecutorCli().then(v => process.stdout.write(`${JSON.stringify({ ok: true, ...v })}\n`)).catch(e => { process.stderr.write(`${JSON.stringify({ ok: false, error: e?.code ?? 'm4_route_executor_cli_failed' })}\n`); process.exitCode = 78; });
