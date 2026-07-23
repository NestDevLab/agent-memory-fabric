import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';

import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { collectM4SelectorScopeSnapshot } from '../src/migration/m4-authority-snapshots.mjs';
import { createM4CutoverAuthorization } from '../src/migration/m4-cutover-authorization.mjs';
import { createM4CutoverCanaryManifest } from '../src/migration/m4-cutover-canary.mjs';
import {
  m4RouteCheckpoint,
  planM4RouteExecutor,
  runM4RouteExecutor,
  verifyM4RouteExecutionResult
} from '../src/operator/m4-route-executor.mjs';
import { m4CutoverFixture } from './helpers/m4-cutover-fixtures.mjs';

const shaCanonical = value => `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
const shaBytes = value => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
const fixedClock = () => new Date('2026-01-02T01:04:00Z');
const testParent = fs.mkdtempSync(path.join(os.homedir(), '.amf-m4-route-test-'));
fs.chmodSync(testParent, 0o700);
after(() => fs.rmSync(testParent, { recursive: true, force: true }));

function privateDirectory(target, mode = 0o700) {
  fs.mkdirSync(target, { recursive: true, mode }); fs.chmodSync(target, mode);
}
function privateJson(target, value) { fs.writeFileSync(target, `${canonicalJson(value)}\n`, { mode: 0o600 }); }
function tree(root) {
  const visit = directory => fs.readdirSync(directory).sort().flatMap(name => {
    const target = path.join(directory, name); const stat = fs.lstatSync(target);
    return [path.relative(root, target), ...(stat.isDirectory() ? visit(target) : [])];
  });
  return visit(root);
}
const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });

async function routeFixture(t, { postCommit = async () => {}, readiness = async () => true, rollback = async () => {} } = {}) {
  privateDirectory(testParent);
  const root = fs.mkdtempSync(path.join(testParent, 'case-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const evidenceRoot = path.join(root, 'evidence'); const runtimeRoot = path.join(root, 'runtime');
  const artifactRoot = path.join(root, 'artifacts'); const backupRoot = path.join(root, 'backups');
  privateDirectory(evidenceRoot); privateDirectory(runtimeRoot, 0o711); privateDirectory(artifactRoot); privateDirectory(backupRoot);

  const before = Buffer.from([
    '# preserved comment',
    'UNRELATED_SECRET=do-not-leak',
    'AMF_CONVERSATION_READER_MODE=shadow',
    'UNCHANGED=value',
    'AMF_CONVERSATION_EXTRACTOR_MODE=legacy',
    ''
  ].join('\n'));
  const after = Buffer.from([
    '# preserved comment',
    'UNRELATED_SECRET=do-not-leak',
    'AMF_CONVERSATION_READER_MODE=active',
    'UNCHANGED=value',
    'AMF_CONVERSATION_EXTRACTOR_MODE=v3',
    ''
  ].join('\n'));
  const checkpoints = m4RouteCheckpoint(shaBytes(before), shaBytes(after), 'shadow', 'legacy');
  const base = await m4CutoverFixture();
  const canary = createM4CutoverCanaryManifest({
    manifestId: 'route-executor-canary', revision: 1, keyDocument: base.keys.canary,
    policy: base.canary.policy,
    observations: {
      ...base.canary.observations,
      rollbackDrill: { ...base.canary.observations.rollbackDrill, configurationRevision: checkpoints.rollback }
    }
  });
  const authorizationInput = structuredClone(base.authorizationInput);
  authorizationInput.canaryManifest = canary;
  authorizationInput.routeConfiguration.publicReader.revision = checkpoints.publicReader;
  authorizationInput.routeConfiguration.extractorReader.revision = checkpoints.extractorReader;
  authorizationInput.rollbackRevision = checkpoints.rollback;
  const authorization = createM4CutoverAuthorization(authorizationInput, { selectorScopeKeyDocument: base.keys.selectorScope });

  const paths = {
    authorization: path.join(evidenceRoot, 'authorization.json'),
    authorizationKey: path.join(evidenceRoot, 'authorization-key.json'),
    scope: path.join(evidenceRoot, 'scope.json'),
    scopeKey: path.join(evidenceRoot, 'scope-key.json'),
    runtime: path.join(runtimeRoot, '.env.runtime'),
    config: path.join(evidenceRoot, 'route-executor.json')
  };
  privateJson(paths.authorization, authorization); privateJson(paths.authorizationKey, base.keys.authorization);
  privateJson(paths.scope, base.selectorScope); privateJson(paths.scopeKey, base.keys.selectorScope);
  fs.writeFileSync(paths.runtime, before, { mode: 0o600 });
  const config = {
    schema: 'amf.m4-route-executor-input/v1', executionId: 'route-execution-one', revision: 1,
    artifactRoot, authorizationManifestPath: paths.authorization, authorizationKeyPath: paths.authorizationKey,
    selectorScopeManifestPath: paths.scope, selectorScopeTrustKeyPath: paths.scopeKey,
    runtimeConfigPath: paths.runtime, backupRoot, deploymentAdapter: 'release-adapter',
    postCommitHook: 'recreate-runtime', readinessHook: 'verify-readiness', rollbackHook: 'restore-runtime'
  };
  privateJson(paths.config, config);
  const events = [];
  const dependencies = {
    clock: fixedClock,
    adapters: {
      'release-adapter': {
        postCommit: { 'recreate-runtime': async plan => { events.push('postCommit'); return postCommit(plan); } },
        readiness: { 'verify-readiness': async plan => { events.push('readiness'); return readiness(plan); } },
        rollback: { 'restore-runtime': async plan => { events.push('rollback'); return rollback(plan); } }
      }
    }
  };
  return {
    root, artifactRoot, backupRoot, paths, config, before, after, authorization, base, dependencies, events,
    target: path.join(artifactRoot, 'm4', 'route-execution', 'route-execution-one-r1.json'),
    backupDir: path.join(backupRoot, 'm4', 'route-execution', 'route-execution-one-r1'),
    lock: `${paths.runtime}.m4-route-executor.lock`
  };
}

test('route checkpoints are deterministic, strict, and bind exact before and after bytes', () => {
  const before = `sha256:${'1'.repeat(64)}`; const after = `sha256:${'2'.repeat(64)}`;
  const checkpoints = m4RouteCheckpoint(before, after, 'shadow', 'legacy');
  assert.deepEqual(checkpoints.publicReader, { id: 'm4-public-reader-active', digest: shaCanonical(['amf.m4-route-revision/v1', 'public-reader', 'active', after]) });
  assert.deepEqual(checkpoints.extractorReader, { id: 'm4-extractor-reader-v3', digest: shaCanonical(['amf.m4-route-revision/v1', 'extractor-reader', 'v3', 'conversation-v3', after]) });
  assert.deepEqual(checkpoints.rollback, { id: 'm4-route-rollback', digest: shaCanonical(['amf.m4-route-revision/v1', 'rollback', 'shadow', 'legacy', before]) });
  assert.throws(() => m4RouteCheckpoint('invalid', after, 'shadow', 'legacy'), /m4_route_executor_revision_input_invalid/);
});

test('plan is zero-write, content-free, reproducible across clock ticks, and accepts a safe 0711 runtime parent', async t => {
  const value = await routeFixture(t); const beforeTree = tree(value.root);
  const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
  const later = { ...value.dependencies, clock: () => new Date('2026-01-02T01:05:00Z') };
  const second = planM4RouteExecutor({ configPath: value.paths.config }, later);
  assert.equal(plan.state, 'planned'); assert.equal(second.confirmationDigest, plan.confirmationDigest);
  assert.deepEqual(tree(value.root), beforeTree);
  const serialized = canonicalJson(plan);
  for (const privateValue of [value.root, value.paths.runtime, 'do-not-leak', 'UNCHANGED=value']) assert.equal(serialized.includes(privateValue), false);
});

test('run writes only the two route values, a config-only backup, and a verified immutable result', async t => {
  const value = await routeFixture(t); const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
  const result = await runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies);
  assert.equal(result.state, 'active'); assert.deepEqual(value.events, ['postCommit', 'readiness']);
  assert.deepEqual(fs.readFileSync(value.paths.runtime), value.after);
  assert.deepEqual(fs.readFileSync(path.join(value.backupDir, 'runtime-config.before')), value.before);
  assert.deepEqual(fs.readdirSync(value.backupDir).sort(), ['metadata.json', 'runtime-config.before']);
  assert.equal(fs.existsSync(value.lock), false); assert.deepEqual(verifyM4RouteExecutionResult(result), result);
  assert.deepEqual(JSON.parse(fs.readFileSync(value.target, 'utf8')), result);
  assert.equal(fs.statSync(value.target).mode & 0o777, 0o600);
  assert.equal(canonicalJson(result).includes(value.root), false);
  const tampered = structuredClone(result); tampered.afterDigest = `sha256:${'f'.repeat(64)}`;
  assert.throws(() => verifyM4RouteExecutionResult(tampered), /m4_route_executor_result_digest_mismatch/);
});

test('post-commit and readiness failures restore exact bytes and run rollback after the failed hook', async t => {
  for (const kind of ['postCommit', 'readiness']) {
    await t.test(kind, async child => {
      const value = await routeFixture(child, kind === 'postCommit'
        ? { postCommit: async () => { throw new Error('private'); } }
        : { readiness: async () => false });
      const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
      const result = await runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies);
      assert.equal(result.state, 'rolled_back'); assert.deepEqual(fs.readFileSync(value.paths.runtime), value.before);
      assert.equal(fs.existsSync(value.lock), false);
      assert.deepEqual(value.events, kind === 'postCommit' ? ['postCommit', 'rollback'] : ['postCommit', 'readiness', 'rollback']);
      assert.equal(result.rollback.state, 'passed');
    });
  }
});

test('rollback-hook failure records rollback_failed and preserves the exclusive lock', async t => {
  const value = await routeFixture(t, { readiness: async () => false, rollback: async () => { throw new Error('private'); } });
  const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
  const result = await runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies);
  assert.equal(result.state, 'rollback_failed'); assert.equal(result.rollback.state, 'failed');
  assert.deepEqual(fs.readFileSync(value.paths.runtime), value.before);
  assert.equal(fs.existsSync(value.lock), true);
  assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_(artifact|lock)_exists/);
});

test('confirmation and signed evidence drift fail before locks, backups, hooks, or config mutation', async t => {
  for (const kind of ['config', 'authorization', 'scope-key']) {
    await t.test(kind, async child => {
      const value = await routeFixture(child); const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
      if (kind === 'config') fs.appendFileSync(value.paths.runtime, 'NEW_UNRELATED=value\n');
      if (kind === 'authorization') {
        const manifest = JSON.parse(fs.readFileSync(value.paths.authorization, 'utf8'));
        manifest.integrity.signature = Buffer.alloc(32, 7).toString('base64url'); privateJson(value.paths.authorization, manifest);
      }
      if (kind === 'scope-key') {
        const key = JSON.parse(fs.readFileSync(value.paths.scopeKey, 'utf8'));
        key.key = Buffer.alloc(32, 99).toString('base64'); privateJson(value.paths.scopeKey, key);
      }
      await assert.rejects(() => runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies), /m4_route_executor_/);
      assert.equal(fs.existsSync(value.lock), false); assert.equal(fs.existsSync(value.backupDir), false);
      assert.deepEqual(value.events, []);
    });
  }
});

test('run normalizes pre-lock filesystem errors without exposing private paths', async t => {
  const value = await routeFixture(t); const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
  fs.renameSync(value.artifactRoot, `${value.artifactRoot}.moved`);
  await assert.rejects(
    () => runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies),
    error => error.code?.startsWith('m4_route_executor_') && !error.message.includes(value.root)
  );
  assert.equal(fs.existsSync(value.lock), false); assert.deepEqual(value.events, []);
});

test('executor independently rejects an authorization and selector scope signed by one authority', async t => {
  const value = await routeFixture(t); const sourceId = value.base.policy.rules[0].sourceInstanceId;
  const scope = await collectM4SelectorScopeSnapshot({
    snapshotId: value.base.selectorScope.snapshotId, revision: value.base.selectorScope.revision,
    policy: value.base.policy, observedAt: value.base.selectorScope.observedAt, validThrough: value.base.selectorScope.validThrough,
    selectorSource: iterable([{ sourceInstanceId: sourceId, contentClass: 'conversation' }]),
    keyDocument: value.base.keys.authorization
  });
  const forged = structuredClone(value.authorization);
  forged.selectorScopeEvidence = {
    manifestId: scope.snapshotId, digest: scope.integrity.payloadDigest, signature: scope.integrity.signature
  };
  const { integrity: ignored, ...body } = forged; void ignored;
  forged.integrity.payloadDigest = shaCanonical(body);
  forged.integrity.signature = crypto.createHmac('sha256', Buffer.from(value.base.keys.authorization.key, 'base64'))
    .update(canonicalJson(['amf.m4-cutover-authorization/v1/integrity', forged.integrity.payloadDigest, value.base.keys.authorization.keyId]), 'utf8')
    .digest('base64url');
  privateJson(value.paths.authorization, forged); privateJson(value.paths.scope, scope);
  privateJson(value.paths.scopeKey, value.base.keys.authorization);
  assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_evidence_invalid/);
  assert.equal(fs.existsSync(value.lock), false); assert.deepEqual(value.events, []);
});

test('expired scope, missing adapter, pre-existing lock, and pre-existing result fail closed', async t => {
  const expired = await routeFixture(t);
  assert.throws(() => planM4RouteExecutor({ configPath: expired.paths.config }, { ...expired.dependencies, clock: () => new Date('2026-01-04T00:00:00Z') }), /m4_route_executor_scope_stale/);
  assert.throws(() => planM4RouteExecutor({ configPath: expired.paths.config }, { adapters: {}, clock: fixedClock }), /m4_route_executor_adapter_invalid/);
  const getterRegistry = { clock: fixedClock };
  Object.defineProperty(getterRegistry, 'adapters', { enumerable: true, get() { throw new Error('private'); } });
  assert.throws(() => planM4RouteExecutor({ configPath: expired.paths.config }, getterRegistry), /m4_route_executor_adapter_invalid/);

  for (const kind of ['lock', 'artifact']) {
    await t.test(kind, async child => {
      const value = await routeFixture(child); const plan = planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies);
      const target = kind === 'lock' ? value.lock : value.target; privateDirectory(path.dirname(target));
      fs.writeFileSync(target, 'occupied\n', { mode: 0o600 });
      await assert.rejects(() => runM4RouteExecutor({ configPath: value.paths.config, confirmedPlanDigest: plan.confirmationDigest }, value.dependencies), new RegExp(`m4_route_executor_${kind === 'artifact' ? 'artifact' : 'lock'}_exists`));
      assert.deepEqual(value.events, []); assert.deepEqual(fs.readFileSync(value.paths.runtime), value.before);
    });
  }
});

test('unsafe and ambiguous runtime files fail closed', async t => {
  const malformed = [
    ' AMF_CONVERSATION_READER_MODE=shadow',
    'export AMF_CONVERSATION_READER_MODE=shadow',
    'AMF_CONVERSATION_READER_MODE=\"shadow\"',
    'AMF_CONVERSATION_READER_MODE=shadow\nAMF_CONVERSATION_READER_MODE=shadow',
    'AMF_CONVERSATION_READER_MODE=active'
  ];
  for (const line of malformed) {
    await t.test(line.slice(0, 24), async child => {
      const value = await routeFixture(child);
      fs.writeFileSync(value.paths.runtime, `${line}\nAMF_CONVERSATION_EXTRACTOR_MODE=legacy\n`, { mode: 0o600 });
      assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_runtime_config_invalid/);
    });
  }
  await t.test('hard link', async child => {
    const value = await routeFixture(child); fs.linkSync(value.paths.runtime, path.join(path.dirname(value.paths.runtime), 'second-link'));
    assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_input_invalid/);
  });
  await t.test('broad mode', async child => {
    const value = await routeFixture(child); fs.chmodSync(value.paths.authorization, 0o640);
    assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_input_invalid/);
  });
  await t.test('symlink', async child => {
    const value = await routeFixture(child); const linked = path.join(path.dirname(value.paths.scope), 'linked-scope.json');
    fs.symlinkSync(value.paths.scope, linked); const config = JSON.parse(fs.readFileSync(value.paths.config, 'utf8'));
    config.selectorScopeManifestPath = linked; privateJson(value.paths.config, config);
    assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_input_invalid/);
  });
  await t.test('derived backup identifier overflow', async child => {
    const value = await routeFixture(child); const config = JSON.parse(fs.readFileSync(value.paths.config, 'utf8'));
    config.executionId = 'a'.repeat(80); privateJson(value.paths.config, config);
    assert.throws(() => planM4RouteExecutor({ configPath: value.paths.config }, value.dependencies), /m4_route_executor_input_invalid/);
    assert.deepEqual(fs.readFileSync(value.paths.runtime), value.before);
    assert.equal(fs.existsSync(value.lock), false); assert.deepEqual(value.events, []);
  });
});
