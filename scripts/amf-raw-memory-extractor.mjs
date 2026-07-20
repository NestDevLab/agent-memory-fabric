#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

import { buildMemoryRecord, createExtractorState, duplicateCanonicalClaim, normalizeState, proposalIdempotencyKey, reserveModelBudget, settleModelBudget, triageConversation, validateClaims } from '../src/raw-memory-extractor.mjs';

function fail(code) { throw new Error(code); }

function parseArgs(argv) {
  const options = { dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--dry-run') { options.dryRun = true; continue; }
    if (arg === '--config') { options.config = argv[++index]; continue; }
    if (arg === '--help') return { help: true };
    fail('extractor_argument_invalid');
  }
  if (!options.config) fail('extractor_config_required');
  return options;
}

function readJson(file, missing = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) { if (error?.code === 'ENOENT' && missing !== null) return missing; throw error; }
}

function writeState(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file); fs.chmodSync(file, 0o600);
}

function configFromFile(file) {
  const value = readJson(file);
  const required = ['baseUrl', 'tokenFile', 'stateFile', 'openaiApiKeyFile', 'model', 'dailyInputTokens', 'dailyOutputTokens', 'maxInputTokensPerConversation', 'maxOutputTokensPerConversation'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(key => value[key] === undefined)
      || typeof value.baseUrl !== 'string' || !/^https?:\/\//.test(value.baseUrl) || typeof value.model !== 'string'
      || value.model !== 'gpt-5.6-luna') fail('extractor_config_invalid');
  return { ...value, maxClaimsPerConversation: value.maxClaimsPerConversation ?? 2, transcriptItemLimit: value.transcriptItemLimit ?? 100 };
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

function modelInput(text, config) {
  return `Extract only durable shared memories from this redacted conversation. Return strict JSON: {"claims":[{"claimType":"decision|preference|instruction|summary","claim":"short factual durable statement","confidence":0..1}]}. Return [] for no durable memory. Never emit operational events, failures, metrics, logs, incidents, secrets, people, relationships, or a transcript summary. Maximum ${config.maxClaimsPerConversation} claims.\n\n${text.slice(0, config.maxInputTokensPerConversation * 4)}`;
}

function responseText(value) {
  if (typeof value?.output_text === 'string') return value.output_text;
  for (const output of value?.output || []) for (const content of output?.content || []) if (typeof content?.text === 'string') return content.text;
  return '';
}

async function extractPaid(text, config, token) {
  const response = await fetch('https://api.openai.com/v1/responses', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: config.model, input: modelInput(text, config), max_output_tokens: config.maxOutputTokensPerConversation, text: { format: { type: 'json_object' } } }) });
  const value = await response.json().catch(() => null);
  if (!response.ok) fail(`extractor_model_failed:${value?.error?.code || response.status}`);
  let parsed;
  try { parsed = JSON.parse(responseText(value)); } catch { fail('extractor_model_output_invalid'); }
  return { claims: validateClaims(parsed?.claims || [], { maxClaims: config.maxClaimsPerConversation }), usage: { inputTokens: Number(value?.usage?.input_tokens || 0), outputTokens: Number(value?.usage?.output_tokens || 0) } };
}

function cost(usage, prices) {
  if (!prices || !Number.isFinite(Number(prices.inputPerMillion)) || !Number.isFinite(Number(prices.outputPerMillion))) return null;
  return (usage.inputTokens * Number(prices.inputPerMillion) + usage.outputTokens * Number(prices.outputPerMillion)) / 1_000_000;
}

async function tick(config, { dryRun }) {
  const token = privateToken(config.tokenFile); const state = dryRun ? createExtractorState() : normalizeState(readJson(config.stateFile, createExtractorState()));
  const query = new URL('/v2/internal/extractor/sessions', config.baseUrl);
  query.searchParams.set('limit', '1'); if (state.cursor) query.searchParams.set('cursor', state.cursor);
  const page = await requestJson({ url: query, token }); const session = page.items?.[0];
  if (!session) return { ok: true, dryRun, outcome: 'empty', scanned: 0, cost: 0 };
  const transcriptUrl = new URL(`/v2/internal/extractor/sessions/${encodeURIComponent(session.id)}/transcript`, config.baseUrl);
  transcriptUrl.searchParams.set('limit', String(config.transcriptItemLimit));
  transcriptUrl.searchParams.set('window', 'newest');
  const transcript = await requestJson({ url: transcriptUrl, token }); const triage = triageConversation(transcript.items);
  const base = { ok: true, dryRun, sessionId: session.id, occurredAt: session.lastOccurredAt, triage: triage.reason, scanned: 1, cost: 0 };
  if (!triage.pass) {
    if (!dryRun) { state.cursor = page.nextCursor; state.inFlight = null; writeState(config.stateFile, state); }
    return { ...base, outcome: 'discarded', claims: [] };
  }
  let paid;
  if (!dryRun && state.inFlight?.sessionId === session.id && state.inFlight.stage === 'model_done') {
    paid = { claims: validateClaims(state.inFlight.claims, { maxClaims: config.maxClaimsPerConversation }), usage: state.inFlight.usage };
  } else {
    const reservation = reserveModelBudget(state, config);
    if (!reservation.reserved) return { ...base, outcome: 'budget_exhausted', claims: [] };
    if (!dryRun) {
      state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'model_pending', reservation };
      writeState(config.stateFile, state);
    }
    paid = await extractPaid(triage.text, config, privateToken(config.openaiApiKeyFile));
    settleModelBudget(state, reservation, paid.usage);
    if (!dryRun) {
      state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'model_done', claims: paid.claims, usage: paid.usage };
      writeState(config.stateFile, state);
    }
  }
  const records = [];
  for (const claim of paid.claims) {
    const canonical = await requestJson({ url: new URL('/v2/memory/search', config.baseUrl), token, method: 'POST', body: { scope: 'shared:global', query: claim.claim, purpose: 'memory_curation', limit: 20 } });
    const existing = canonical?.result?.items || canonical?.items || [];
    if (duplicateCanonicalClaim(claim.claim, existing)) continue;
    records.push(buildMemoryRecord({ sessionId: session.id, transcript: triage.text, claim, now: new Date().toISOString() }));
  }
  if (!dryRun) {
    state.inFlight = { sessionId: session.id, cursor: page.nextCursor, stage: 'proposing', claims: paid.claims, usage: paid.usage,
      proposalKeys: records.map(record => proposalIdempotencyKey({ sessionId: session.id, claim: record.claim.text })) };
    writeState(config.stateFile, state);
    for (const record of records) await requestJson({ url: new URL('/v2/memory/proposals', config.baseUrl), token, method: 'POST', headers: { 'idempotency-key': proposalIdempotencyKey({ sessionId: session.id, claim: record.claim.text }) }, body: { record, rationale: `RAW extractor durable claim from ${session.id}; automatic curator and receipt applicator perform canonical plaintext deduplication.` } });
    state.cursor = page.nextCursor; state.inFlight = null; writeState(config.stateFile, state);
  }
  return { ...base, outcome: records.length ? (dryRun ? 'would_propose' : 'proposed') : 'no_durable_claim', claims: records.map(record => ({ claimType: record.claimType, claim: record.claim.text, confidence: record.confidence.score })), usage: paid.usage, cost: cost(paid.usage, config.prices) };
}

const options = parseArgs(process.argv.slice(2));
if (options.help) process.stdout.write('Usage: amf-raw-memory-extractor.mjs --config /etc/agent-memory-fabric/raw-extractor.json [--dry-run]\n');
else tick(configFromFile(options.config), options).then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(error => { process.stderr.write(`amf-raw-memory-extractor: ${error.message}\n`); process.exitCode = 1; });
