#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { buildMemoryRecord, createExtractorState, duplicateCanonicalClaim, normalizeState, proposalIdempotencyKey, reserveModelBudget, settleModelBudget, sharedDurableClaim, triageConversation, truncateUtf8ToTokenUpperBound, utf8TokenUpperBound, validateClaims } from '../src/raw-memory-extractor.mjs';

function fail(code) { throw new Error(code); }

function parseArgs(argv) {
  const options = { dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--dry-run') { options.dryRun = true; continue; }
    if (arg === '--session-id') { options.sessionId = argv[++index]; continue; }
    if (arg === '--config') { options.config = argv[++index]; continue; }
    if (arg === '--help') return { help: true };
    fail('extractor_argument_invalid');
  }
  if (!options.config) fail('extractor_config_required');
  if (options.sessionId !== undefined && (typeof options.sessionId !== 'string' || !options.sessionId)) fail('extractor_argument_invalid');
  return options;
}

function readJson(file, missing = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) { if (error?.code === 'ENOENT' && missing !== null) return missing; throw error; }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file); fs.chmodSync(file, 0o600);
}

function writeState(file, value) { writeJson(file, value); }

function configFromFile(file) {
  const value = readJson(file);
  const required = ['baseUrl', 'tokenFile', 'stateFile', 'codexWorkDir', 'model', 'dailyInputTokens', 'dailyOutputTokens', 'maxInputTokensPerConversation', 'maxOutputTokensPerConversation'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(key => value[key] === undefined)
      || typeof value.baseUrl !== 'string' || !/^https:\/\//.test(value.baseUrl) || value.model !== 'gpt-5.6-luna') fail('extractor_config_invalid');
  const config = { ...value, maxClaimsPerConversation: value.maxClaimsPerConversation ?? 2, transcriptItemLimit: value.transcriptItemLimit ?? 100,
    codexBinary: value.codexBinary ?? 'codex', codexTimeoutMs: value.codexTimeoutMs ?? 90000, planMinRemainingPercent: value.planMinRemainingPercent ?? 25,
    codexRateLimitTimeoutMs: value.codexRateLimitTimeoutMs ?? 15000 };
  for (const key of ['maxInputTokensPerConversation', 'maxOutputTokensPerConversation', 'dailyInputTokens', 'dailyOutputTokens', 'codexTimeoutMs', 'planMinRemainingPercent', 'codexRateLimitTimeoutMs']) {
    if (!Number.isSafeInteger(Number(config[key])) || Number(config[key]) < 1) fail('extractor_config_invalid');
  }
  if (Number(config.planMinRemainingPercent) > 100) fail('extractor_config_invalid');
  return config;
}

function privateToken(file) {
  const value = fs.readFileSync(file, 'utf8').trim();
  if (value.length < 16) fail('extractor_token_invalid');
  return value;
}

async function requestJson({ url, token, method = 'GET', body = null, headers = {} }) {
  const response = await fetch(url, { method, headers: { authorization: `Bearer ${token}`, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  const parsed = await response.json().catch(() => null);
  if (!response.ok || !parsed?.ok) fail(`fabric_request_failed:${parsed?.error?.code || response.status}`);
  return parsed.data;
}

function modelInstruction(config) {
  return `Extract only durable shared memories from the redacted conversation below. Return JSON matching the supplied schema. Return an empty claims array for no durable memory. A decision is a chosen reusable policy, a preference is an enduring working preference, an instruction is a repeatable directive, and a summary is a reusable general conclusion. Never emit operational events, failures, metrics, logs, incidents, secrets, people, relationships, transcript summaries, one-off project facts, historical facts, names, titles, locations, source-material inventory, or task status. Do not label a fact as a preference or decision. Maximum ${config.maxClaimsPerConversation} claims.\n\n`;
}

export function buildBoundedModelInput(text, config) {
  const prefix = modelInstruction(config);
  // `--output-schema` is model input too.  Reserve a small fixed envelope for
  // Codex's schema transport so the configured cap covers every input byte the
  // extractor controls, not merely transcript characters.
  const controlledOverhead = utf8TokenUpperBound(prefix) + utf8TokenUpperBound(JSON.stringify(claimsSchema(config))) + 512;
  const remaining = Number(config.maxInputTokensPerConversation) - controlledOverhead;
  if (remaining < 1) fail('extractor_prompt_budget_too_small');
  const transcript = truncateUtf8ToTokenUpperBound(text, remaining);
  const prompt = `${prefix}${transcript}`;
  return { prompt, transcript, inputTokenUpperBound: controlledOverhead + utf8TokenUpperBound(transcript) };
}

function claimsSchema(config) {
  return { type: 'object', additionalProperties: false, required: ['claims'], properties: { claims: { type: 'array', maxItems: config.maxClaimsPerConversation, items: { type: 'object', additionalProperties: false, required: ['claimType', 'claim', 'confidence'], properties: { claimType: { type: 'string', enum: ['decision', 'preference', 'instruction', 'summary'] }, claim: { type: 'string', minLength: 12, maxLength: 280 }, confidence: { type: 'number', minimum: 0, maximum: 1 } } } } } };
}

function usageFromJsonl(value) {
  let usage = null;
  for (const line of String(value || '').split('\n')) {
    try {
      const event = JSON.parse(line);
      if (event.type === 'turn.completed' && event.usage) usage = event.usage;
    } catch { /* Codex stderr and non-JSON diagnostics are not usage. */ }
  }
  const inputTokens = Number(usage?.input_tokens ?? usage?.inputTokens);
  const outputTokens = Number(usage?.output_tokens ?? usage?.outputTokens);
  if (!Number.isSafeInteger(inputTokens) || !Number.isSafeInteger(outputTokens) || inputTokens < 0 || outputTokens < 0) fail('extractor_model_usage_missing');
  return { inputTokens, outputTokens };
}

function runProcess(command, args, { input = '', timeoutMs, cwd, env }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = ''; let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM'); }, timeoutMs);
    child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr, timedOut }); });
    child.stdin.end(input);
  });
}

async function rateLimitSnapshot(config) {
  const child = spawn(config.codexBinary, ['app-server', '--listen', 'stdio://'], { cwd: config.codexWorkDir, stdio: ['pipe', 'pipe', 'pipe'] });
  return await new Promise((resolve, reject) => {
    let stdout = ''; let stderr = ''; let sentRead = false; let complete = false;
    const finish = (error, value = null) => { if (complete) return; complete = true; clearTimeout(timer); child.kill('SIGTERM'); error ? reject(error) : resolve(value); };
    const timer = setTimeout(() => finish(new Error('extractor_plan_usage_timeout')), Number(config.codexRateLimitTimeoutMs));
    child.on('error', error => finish(error)); child.stderr.on('data', chunk => { stderr += chunk; });
    child.stdout.on('data', chunk => {
      stdout += chunk;
      const lines = stdout.split('\n'); stdout = lines.pop();
      for (const line of lines) {
        let message; try { message = JSON.parse(line); } catch { continue; }
        if (message.id === 1 && message.result && !sentRead) { sentRead = true; child.stdin.write('{"id":2,"method":"account/rateLimits/read"}\n'); }
        if (message.id === 2) return finish(null, message.result);
      }
    });
    child.on('close', code => { if (!complete) finish(new Error(`extractor_plan_usage_failed:${code}:${stderr.slice(0, 120)}`)); });
    child.stdin.write('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"raw-extractor","version":"1"}}}\n');
  });
}

export function evaluatePlanUsage(result, config, now = new Date().toISOString()) {
  const snapshots = [result?.rateLimits, ...Object.values(result?.rateLimitsByLimitId || {})].filter(Boolean);
  const limits = snapshots.flatMap(snapshot => [snapshot.primary, snapshot.secondary].filter(Boolean).map(window => ({ usedPercent: Number(window.usedPercent), resetsAt: Number(window.resetsAt || 0), reached: snapshot.rateLimitReachedType || null })));
  if (!limits.length || limits.some(limit => !Number.isFinite(limit.usedPercent))) throw new Error('extractor_plan_usage_unavailable');
  const constrained = limits.filter(limit => limit.reached || 100 - limit.usedPercent < Number(config.planMinRemainingPercent));
  const pauseUntil = constrained.reduce((latest, limit) => Math.max(latest, limit.resetsAt), 0);
  return { checkedAt: now, constrained: constrained.length > 0, minimumRemainingPercent: Math.min(...limits.map(limit => 100 - limit.usedPercent)), pauseUntil: pauseUntil ? new Date(pauseUntil * 1000).toISOString() : null };
}

export async function planUsageGate(config, now = new Date().toISOString()) {
  return evaluatePlanUsage(await rateLimitSnapshot(config), config, now);
}

async function extractWithCodex(text, config) {
  const bounded = buildBoundedModelInput(text, config);
  fs.mkdirSync(config.codexWorkDir, { recursive: true, mode: 0o700 });
  const schemaFile = path.join(config.codexWorkDir, 'raw-extractor-output.schema.json');
  const outputFile = path.join(config.codexWorkDir, `raw-extractor-output-${process.pid}.json`);
  writeJson(schemaFile, claimsSchema(config));
  try {
    const args = ['exec', '--ephemeral', '--ignore-user-config', '--ignore-rules', '--json', '--skip-git-repo-check', '-C', config.codexWorkDir, '-m', config.model, '-c', 'model_reasoning_effort="none"', '-s', 'read-only', '--output-schema', schemaFile, '--output-last-message', outputFile, '-'];
    const result = await runProcess(config.codexBinary, args, { input: bounded.prompt, timeoutMs: Number(config.codexTimeoutMs), cwd: config.codexWorkDir, env: process.env });
    if (result.timedOut) fail('extractor_model_timeout');
    if (result.code !== 0) fail(`extractor_model_failed:${result.stderr.slice(0, 160) || result.stdout.slice(-160)}`);
    const parsed = readJson(outputFile);
    const claims = validateClaims(parsed?.claims || [], { maxClaims: config.maxClaimsPerConversation }).filter(claim => sharedDurableClaim(claim.claim));
    return { claims, usage: usageFromJsonl(result.stdout), inputTokenUpperBound: bounded.inputTokenUpperBound };
  } finally { try { fs.unlinkSync(outputFile); } catch (error) { if (error?.code !== 'ENOENT') throw error; } }
}

async function tick(config, { dryRun, sessionId = null }) {
  if (sessionId && !dryRun) fail('extractor_session_selector_requires_dry_run');
  fs.mkdirSync(config.codexWorkDir, { recursive: true, mode: 0o700 });
  const token = privateToken(config.tokenFile); const state = dryRun ? createExtractorState() : normalizeState(readJson(config.stateFile, createExtractorState()));
  const query = new URL('/v2/internal/extractor/sessions', config.baseUrl);
  query.searchParams.set('limit', '1'); if (state.cursor) query.searchParams.set('cursor', state.cursor);
  const page = sessionId ? { nextCursor: null } : await requestJson({ url: query, token }); const session = sessionId ? { id: sessionId, lastOccurredAt: null } : page.items?.[0];
  if (!session) return { ok: true, dryRun, outcome: 'empty', scanned: 0 };
  const transcriptUrl = new URL(`/v2/internal/extractor/sessions/${encodeURIComponent(session.id)}/transcript`, config.baseUrl);
  transcriptUrl.searchParams.set('limit', String(config.transcriptItemLimit)); transcriptUrl.searchParams.set('window', 'newest');
  const transcript = await requestJson({ url: transcriptUrl, token }); const triage = triageConversation(transcript.items);
  const base = { ok: true, dryRun, sessionId: session.id, occurredAt: session.lastOccurredAt, triage: triage.reason, scanned: 1 };
  if (!triage.pass) {
    if (!dryRun) { state.cursor = page.nextCursor; state.inFlight = null; writeState(config.stateFile, state); }
    return { ...base, outcome: 'discarded', claims: [] };
  }
  let paid;
  if (!dryRun && state.inFlight?.sessionId === session.id && state.inFlight.stage === 'model_done') {
    paid = { claims: validateClaims(state.inFlight.claims, { maxClaims: config.maxClaimsPerConversation }), usage: state.inFlight.usage, inputTokenUpperBound: state.inFlight.inputTokenUpperBound };
  } else {
    let planUsage;
    try { planUsage = await planUsageGate(config); } catch (error) { planUsage = { checkedAt: new Date().toISOString(), constrained: true, minimumRemainingPercent: null, pauseUntil: null, error: error.message }; }
    if (!dryRun) { state.planUsage = planUsage; writeState(config.stateFile, state); }
    if (planUsage.constrained) return { ...base, outcome: 'plan_usage_constrained', claims: [], planUsage };
    const reservation = reserveModelBudget(state, config);
    if (!reservation.reserved) return { ...base, outcome: 'budget_exhausted', claims: [] };
    if (!dryRun) { state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'model_pending', reservation }; writeState(config.stateFile, state); }
    paid = await extractWithCodex(triage.text, config);
    settleModelBudget(state, reservation, paid.usage);
    if (!dryRun) { state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'model_done', claims: paid.claims, usage: paid.usage, inputTokenUpperBound: paid.inputTokenUpperBound }; writeState(config.stateFile, state); }
  }
  const records = [];
  for (const claim of paid.claims) {
    const canonical = await requestJson({ url: new URL('/v2/memory/search', config.baseUrl), token, method: 'POST', body: { scope: 'shared:global', query: claim.claim, purpose: 'memory_curation', limit: 20 } });
    const existing = canonical?.result?.items || canonical?.items || [];
    if (!duplicateCanonicalClaim(claim.claim, existing)) records.push(buildMemoryRecord({ sessionId: session.id, transcript: triage.text, claim, now: new Date().toISOString() }));
  }
  if (!dryRun) {
    state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'proposing', claims: paid.claims, usage: paid.usage, proposalKeys: records.map(record => proposalIdempotencyKey({ sessionId: session.id, claim: record.claim.text })) };
    writeState(config.stateFile, state);
    for (const record of records) await requestJson({ url: new URL('/v2/memory/proposals', config.baseUrl), token, method: 'POST', headers: { 'idempotency-key': proposalIdempotencyKey({ sessionId: session.id, claim: record.claim.text }) }, body: { record, rationale: `RAW extractor durable claim from ${session.id}; automatic curator and receipt applicator perform canonical plaintext deduplication.` } });
    state.cursor = page.nextCursor; state.inFlight = null; writeState(config.stateFile, state);
  }
  return { ...base, outcome: records.length ? (dryRun ? 'would_propose' : 'proposed') : 'no_durable_claim', claims: records.map(record => ({ claimType: record.claimType, claim: record.claim.text, confidence: record.confidence.score })), usage: paid.usage, inputTokenUpperBound: paid.inputTokenUpperBound };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) process.stdout.write('Usage: amf-raw-memory-extractor.mjs --config FILE [--dry-run] [--session-id ID]\n');
  else tick(configFromFile(options.config), options).then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(error => { process.stderr.write(`amf-raw-memory-extractor: ${error.message}\n`); process.exitCode = 1; });
}
