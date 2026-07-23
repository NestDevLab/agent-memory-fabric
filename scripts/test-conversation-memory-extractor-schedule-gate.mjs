import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import * as canonical from './amf-conversation-memory-extractor.mjs';
import * as legacy from './amf-raw-memory-extractor.mjs';
import * as canonicalSource from '../src/conversation-memory-extractor.mjs';
import * as legacySource from '../src/raw-memory-extractor.mjs';
import { CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA, CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA, createConversationMemoryQualityReport } from '../src/conversation-memory-quality-gate.mjs';

const digest = letter => `sha256:${letter.repeat(64)}`;
const qualityKey = { schema: CONVERSATION_MEMORY_QUALITY_KEY_SCHEMA, keyId: 'schedule-test-key', key: Buffer.alloc(32, 3).toString('base64') };
const qualityPolicy = { schema: CONVERSATION_MEMORY_QUALITY_POLICY_SCHEMA, revision: 'schedule-test-policy', maxClaimsPerModel: 2, thresholds: { minRequested: 1, minScanned: 1, minModelSucceeded: 1, minPromotionBps: 0, minTriageRejectedBps: 0, maxTriageRejectedBps: 10000, maxDuplicateBps: 10000, maxNoOpBps: 10000, maxModelFailureBps: 10000, maxInvalidOrUnsafeBps: 10000 } };
function tempConfig(root) { return { baseUrl: 'https://memory.example.invalid', tokenFile: path.join(root, 'missing.token'), stateFile: path.join(root, 'state.json'), legacyStateFile: path.join(root, 'legacy.json'), codexWorkDir: path.join(root, 'codex'), model: 'gpt-5.6-luna', codexBinary: 'codex', readerGeneration: 'conversation-v3', dailyInputTokens: 20, dailyOutputTokens: 20, maxInputTokensPerConversation: 10, maxOutputTokensPerConversation: 2, maxClaimsPerConversation: 2, transcriptItemLimit: 10, planMinRemainingPercent: 25, codexTimeoutMs: 10, codexRateLimitTimeoutMs: 10, qualityPolicyFile: path.join(root, 'policy.json'), qualityKeyFile: path.join(root, 'key.json'), qualityReportFile: path.join(root, 'report.json'), qualityReleaseDigest: digest('a'), qualityGateMaxAgeMs: 60000, qualitySampleMaxConversations: 20 }; }
function writeQualityFiles(config, report = null) { fs.writeFileSync(config.qualityPolicyFile, JSON.stringify(qualityPolicy)); fs.writeFileSync(config.qualityKeyFile, JSON.stringify(qualityKey)); if (report) fs.writeFileSync(config.qualityReportFile, JSON.stringify(report)); }

test('canonical names own implementation and raw names remain import-compatible wrappers', () => {
  assert.equal(legacy.buildBoundedModelInput, canonical.buildBoundedModelInput);
  assert.equal(legacySource.proposalIdempotencyKey, canonicalSource.proposalIdempotencyKey);
  assert.match(fs.readFileSync(new URL('../src/raw-memory-extractor.mjs', import.meta.url), 'utf8'), /^\/\/ Deprecated[\s\S]*export \* from '\.\/conversation-memory-extractor\.mjs';\s*$/);
  const rawCli = fs.readFileSync(new URL('./amf-raw-memory-extractor.mjs', import.meta.url), 'utf8');
  assert.match(rawCli, /export \* from '\.\/amf-conversation-memory-extractor\.mjs';/);
  assert.doesNotMatch(rawCli, /function configFromFile|async function tick|evaluateConversationMemoryQuality/);
  const canonicalCli = fs.readFileSync(new URL('./amf-conversation-memory-extractor.mjs', import.meta.url), 'utf8');
  assert.match(canonicalCli, /quality_fabric_response_invalid/);
  assert.match(canonicalCli, /\(dependencies\.writeJson \?\? writeJson\)\(config\.qualityReportFile, report\)/);
  assert.doesNotMatch(canonicalCli, /sessionId: session\.id.*quality_evaluation/);
});

test('canonical CLI rejects a bare invocation and systemd units are always quality-gated', async () => {
  await assert.rejects(() => canonical.main([]), /extractor_config_required/);
  for (const file of ['../deploy/systemd/amf-conversation-memory-extractor.service', '../deploy/systemd/amf-raw-memory-extractor.service']) {
    const unit = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.match(unit, /^ExecCondition=.*--verify-quality-gate$/m);
    assert.match(unit, /^ExecStart=.*amf-conversation-memory-extractor\.mjs .*--scheduled$/m);
    assert.doesNotMatch(unit, /amf-raw-memory-extractor\.mjs.*--scheduled/);
  }
  const canonicalTimer = fs.readFileSync(new URL('../deploy/systemd/amf-conversation-memory-extractor.timer', import.meta.url), 'utf8');
  const legacyTimer = fs.readFileSync(new URL('../deploy/systemd/amf-raw-memory-extractor.timer', import.meta.url), 'utf8');
  assert.match(canonicalTimer, /^Conflicts=amf-raw-memory-extractor\.timer$/m);
  assert.match(legacyTimer, /^Conflicts=amf-conversation-memory-extractor\.timer$/m);
  assert.match(legacyTimer, /^Unit=amf-conversation-memory-extractor\.service$/m);
});

test('public example is v3, bounded, and does not choose a live quality policy', () => {
  const config = JSON.parse(fs.readFileSync(new URL('../config/conversation-memory-extractor.example.json', import.meta.url), 'utf8'));
  assert.equal(config.readerGeneration, 'conversation-v3'); assert.equal(config.qualitySampleMaxConversations, 12);
  assert.equal(/^sha256:[a-f0-9]{64}$/.test(config.qualityReleaseDigest), false, 'example cannot be activated without a real release digest');
  const policy = fs.readFileSync(new URL('../config/conversation-memory-quality-policy.example.json', import.meta.url), 'utf8');
  assert.match(policy, /example-only-m5-policy/);
  for (const unit of ['../deploy/systemd/amf-conversation-memory-extractor.service', '../deploy/systemd/amf-raw-memory-extractor.service']) {
    assert.doesNotMatch(fs.readFileSync(new URL(unit, import.meta.url), 'utf8'), /administrator|\/home\//);
  }
});

test('project-scoped model candidates are unsafe quality candidates, not model no-ops', () => {
  const result = canonical.splitQualityCandidates([{ claimType: 'decision', claim: 'This project should retain an internal convention.', confidence: 0.5 }]);
  assert.deepEqual(result.claims, []); assert.equal(result.invalidOrUnsafeClaims, 1);
  const candidateCount = result.claims.length + result.invalidOrUnsafeClaims;
  assert.equal(candidateCount, 1); assert.notEqual(candidateCount, 0, 'a filtered model claim is not a no-op');
});

test('quality evaluation uses bounded injected dependencies, aggregates only, and never proposes or writes state', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-quality-')); const config = tempConfig(root); writeQualityFiles(config);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const seen = []; let model = 0;
  const requestJson = async ({ url }) => { seen.push(url.pathname); if (url.pathname.endsWith('/sessions')) return { items: [{ id: 'synthetic-session-unique-a' }, { id: 'synthetic-session-unique-b' }, { id: 'synthetic-session-unique-c' }] }; if (url.pathname.endsWith('/synthetic-session-unique-a/transcript')) return { items: [{ role: 'user', text: 'We should retain this reusable policy forever because it is durable and should guide every future shared decision without exceptions.' }] }; if (url.pathname.endsWith('/synthetic-session-unique-b/transcript')) return { items: [{ role: 'user', text: 'short' }] }; if (url.pathname.endsWith('/synthetic-session-unique-c/transcript')) return { items: [{ role: 'user', text: 'We should retain this reusable policy forever because it is durable and should guide every future shared decision without exceptions.' }] }; if (url.pathname === '/v2/memory/search') return { items: model === 1 ? [{ record: { claim: { text: 'Synthetic durable claim unique marker' } } }] : [] }; throw new Error('unexpected'); };
  const result = await canonical.evaluateConversationMemoryQuality(config, { now: '2026-07-23T12:00:00Z', dependencies: { privateToken: () => 'token', requestJson, planUsageGate: async () => ({ constrained: false }), extractWithCodex: async () => { model += 1; if (model === 2) throw new Error('model marker'); return { claims: [{ claimType: 'decision', claim: 'Synthetic durable claim unique marker', confidence: 0.5 }], invalidOrUnsafeClaims: 1 }; } } });
  assert.equal(result.sample.requested, 3); assert.equal(result.sample.triageRejected, 1); assert.equal(result.sample.modelFailed, 1); assert.equal(result.sample.candidateClaims, 2); assert.equal(result.sample.invalidOrUnsafeClaims, 1); assert.equal(result.sample.duplicateClaims, 1); assert.equal(result.sample.wouldProposeClaims, 0);
  const serialized = `${JSON.stringify(result)}${fs.readFileSync(config.qualityReportFile, 'utf8')}`; for (const marker of ['synthetic-session-unique', 'Synthetic durable claim', 'model marker']) assert.equal(serialized.includes(marker), false);
  assert.equal(seen.some(value => value.includes('/proposals')), false); assert.equal(fs.existsSync(config.stateFile), false);
});

test('quality projection failures do not overwrite an existing report', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-quality-')); const config = tempConfig(root); writeQualityFiles(config); fs.writeFileSync(config.qualityReportFile, 'previous-report');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  await assert.rejects(() => canonical.evaluateConversationMemoryQuality(config, { dependencies: { privateToken: () => 'token', requestJson: async () => ({ items: null }) } }), /quality_fabric_response_invalid/);
  assert.equal(fs.readFileSync(config.qualityReportFile, 'utf8'), 'previous-report');
});

test('zero sessions creates a signed failing report and policy/config bindings fail closed', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-quality-')); const config = tempConfig(root); writeQualityFiles(config); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const zero = await canonical.evaluateConversationMemoryQuality(config, { dependencies: { privateToken: () => 'token', requestJson: async () => ({ items: [] }) } });
  assert.equal(zero.outcome, 'fail'); assert.equal(zero.sample.requested, 0); assert.ok(fs.readFileSync(config.qualityReportFile, 'utf8').includes('signature'));
  assert.notEqual(canonical.extractorConfigDigest(config), canonical.extractorConfigDigest({ ...config, codexBinary: 'other-codex' }));
  fs.writeFileSync(config.qualityPolicyFile, JSON.stringify({ ...qualityPolicy, maxClaimsPerModel: 1 }));
  assert.equal(canonical.verifyQualityGate(config).code, 'quality_policy_model_bound_mismatch');
});

test('quality evaluation enforces the configured aggregate token budget without writing a report', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-quality-budget-')); const config = tempConfig(root); writeQualityFiles(config);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  config.dailyInputTokens = config.maxInputTokensPerConversation; config.dailyOutputTokens = config.maxOutputTokensPerConversation;
  const durable = 'We should always retain this reusable policy because it is durable across repeated future conversations and contexts.';
  const requestJson = async ({ url }) => url.pathname.endsWith('/sessions') ? { items: [{ id: 'budget-a' }, { id: 'budget-b' }] }
    : url.pathname.endsWith('/transcript') ? { items: [{ role: 'user', text: durable }] } : { items: [] };
  await assert.rejects(() => canonical.evaluateConversationMemoryQuality(config, { now: '2026-07-23T12:00:00Z', dependencies: {
    privateToken: () => 'token', requestJson, planUsageGate: async () => ({ constrained: false }),
    extractWithCodex: async () => ({ claims: [], invalidOrUnsafeClaims: 0, usage: { inputTokens: config.maxInputTokensPerConversation, outputTokens: config.maxOutputTokensPerConversation } }),
  } }), /quality_budget_exhausted/);
  assert.equal(fs.existsSync(config.qualityReportFile), false);
});

test('scheduled gate rejects invalid reports before token, state, or Codex work', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-scheduled-')); const config = tempConfig(root); writeQualityFiles(config);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const configFile = path.join(root, 'config.json'); fs.writeFileSync(configFile, JSON.stringify(config));
  const sample = { requested: 1, scanned: 1, triageRejected: 0, modelAttempted: 1, modelSucceeded: 1, modelFailed: 0, modelNoOp: 1, candidateClaims: 0, duplicateClaims: 0, wouldProposeClaims: 0, invalidOrUnsafeClaims: 0 };
  const report = createConversationMemoryQualityReport({ policy: qualityPolicy, key: qualityKey, releaseDigest: config.qualityReleaseDigest, configDigest: canonical.extractorConfigDigest(config), completedAt: new Date().toISOString().replace('.000Z', 'Z'), sample });
  const at = new Date().toISOString().replace('.000Z', 'Z');
  const cases = [null, { ...report, signature: Buffer.alloc(32, 9).toString('base64') }, createConversationMemoryQualityReport({ policy: qualityPolicy, key: qualityKey, releaseDigest: config.qualityReleaseDigest, configDigest: canonical.extractorConfigDigest(config), completedAt: '2020-01-01T00:00:00Z', sample }), createConversationMemoryQualityReport({ policy: qualityPolicy, key: qualityKey, releaseDigest: config.qualityReleaseDigest, configDigest: canonical.extractorConfigDigest(config), completedAt: at, sample: { ...sample, modelSucceeded: 0, modelFailed: 1, modelNoOp: 0 } }), createConversationMemoryQualityReport({ policy: qualityPolicy, key: qualityKey, releaseDigest: config.qualityReleaseDigest, configDigest: digest('b'), completedAt: at, sample }), createConversationMemoryQualityReport({ policy: qualityPolicy, key: qualityKey, releaseDigest: digest('b'), configDigest: canonical.extractorConfigDigest(config), completedAt: at, sample })];
  for (const item of cases) {
    if (item) fs.writeFileSync(config.qualityReportFile, JSON.stringify(item)); else try { fs.unlinkSync(config.qualityReportFile); } catch { /* absent */ }
    await assert.rejects(() => canonical.main(['--config', configFile, '--scheduled']));
    assert.equal(fs.existsSync(config.tokenFile), false); assert.equal(fs.existsSync(config.stateFile), false); assert.equal(fs.existsSync(config.codexWorkDir), false);
  }
});
