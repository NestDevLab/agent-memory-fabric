#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { HttpRawEventSink } from '../src/ingest/http-raw-event-sink.mjs';
import { RAW_EVENT_HTTP_MAX_BODY_BYTES } from '../src/ingest/raw-event-contract.mjs';
import { CursorStore } from '../src/ingest/transcripts/cursor-store.mjs';
import { TranscriptIngestor } from '../src/ingest/transcripts/ingestor.mjs';
import { runTranscriptBackfill } from '../src/ingest/transcripts/backfill.mjs';

const FIXTURE_ROOT = fs.realpathSync(path.join(import.meta.dirname, 'fixtures', 'transcripts'));

function argumentsFrom(argv) {
  const options = {};
  const flags = new Set(['--replay', '--backfill', '--bootstrap-tail', '--full-audit', '--test-mode', '--allow-live-source']);
  const values = new Set(['--runtime', '--file', '--root', '--lease', '--spool', '--cursors', '--cursor-namespace', '--sink-module', '--source-instance', '--source-instance-id', '--session-id']);
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (!name.startsWith('--')) throw new Error(`unknown_argument:${name}`);
    if (flags.has(name)) { options[name.slice(2)] = true; continue; }
    if (!values.has(name)) throw new Error(`unknown_argument:${name}`);
    const value = argv[++index];
    if (!value || value.startsWith('--')) throw new Error(`argument_value_required:${name}`);
    options[name.slice(2)] = value;
  }
  return options;
}

function parseJsonAllowlist(value, name) {
  let parsed;
  try { parsed = JSON.parse(value || ''); } catch { throw new Error(`${name}_invalid`); }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some(item => typeof item !== 'string' || !item)) throw new Error(`${name}_invalid`);
  return parsed;
}

function readKeyRing(env, prefix) {
  const pathValue = String(env[`${prefix}_PATH`] || '').trim();
  const jsonValue = String(env[`${prefix}_JSON`] || '').trim();
  if (!pathValue && !jsonValue) return null;
  try {
    const parsed = JSON.parse(pathValue ? fs.readFileSync(path.resolve(pathValue), 'utf8') : jsonValue);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('invalid');
    return parsed;
  } catch { throw new Error(`${prefix.toLowerCase()}_invalid`); }
}

function boundedEnvInteger(env, name, fallback, min, max) {
  const raw = String(env[name] ?? '').trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name.toLowerCase()}_invalid`);
  return value;
}

function within(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function assertNoSymlinkPath(root, target) {
  let current = root;
  if (fs.lstatSync(current).isSymbolicLink()) throw new Error('transcript_source_symlink_forbidden');
  for (const segment of path.relative(root, target).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error('transcript_source_symlink_forbidden');
  }
}

function sourceInstanceFrom(options, env) {
  if (options['source-instance'] && options['source-instance-id']) throw new Error('source_instance_conflict');
  const optionValue = options['source-instance-id'] || options['source-instance'] || '';
  const environmentValue = env.AMF_INGEST_SOURCE_INSTANCE_ID || '';
  if (optionValue && environmentValue && optionValue !== environmentValue) throw new Error('source_instance_conflict');
  return String(optionValue || environmentValue);
}

function resolveAllowlistedDirectory(requestedPath, roots, errorPrefix) {
  const requested = path.resolve(requestedPath);
  const real = fs.realpathSync(requested);
  if (requested !== real || !fs.statSync(real).isDirectory()) throw new Error(`${errorPrefix}_symlink_forbidden`);
  const allowedRoots = roots.map(root => {
    const requestedRoot = path.resolve(root);
    const realRoot = fs.realpathSync(requestedRoot);
    if (requestedRoot !== realRoot || !fs.statSync(realRoot).isDirectory()) throw new Error(`${errorPrefix}_root_unsafe`);
    return realRoot;
  });
  const allowedRoot = allowedRoots.find(root => within(root, real));
  if (!allowedRoot) throw new Error(`${errorPrefix}_not_allowlisted`);
  assertNoSymlinkPath(allowedRoot, real);
  return { real, allowedRoot };
}

function validateReplayScope(options, env, injectedSink) {
  if (options['test-mode']) {
    if (options['allow-live-source']) throw new Error('replay_mode_conflict');
    const roots = parseJsonAllowlist(env.AMF_TRANSCRIPT_TEST_SPOOL_ROOTS, 'transcript_test_spool_roots');
    const resolved = resolveAllowlistedDirectory(options.spool, roots, 'replay_spool');
    const sourceInstance = sourceInstanceFrom(options, env);
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(sourceInstance)) throw new Error('source_instance_invalid');
    return { ...resolved, classification: 'fixture-test', sourceInstance };
  }
  if (!options['allow-live-source']) throw new Error('replay_live_opt_in_required');
  if (options['sink-module']) throw new Error('replay_sink_module_forbidden');
  const sourceInstance = sourceInstanceFrom(options, env);
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(sourceInstance)) throw new Error('source_instance_invalid');
  const instances = parseJsonAllowlist(env.AMF_TRANSCRIPT_SOURCE_INSTANCES, 'transcript_source_instances');
  if (!instances.includes(sourceInstance)) throw new Error('source_instance_not_allowlisted');
  let mapping;
  try { mapping = JSON.parse(env.AMF_TRANSCRIPT_LIVE_REPLAY_ROOTS || ''); }
  catch { throw new Error('transcript_live_replay_roots_invalid'); }
  if (!mapping || Array.isArray(mapping) || typeof mapping !== 'object' || !Array.isArray(mapping[sourceInstance]) || mapping[sourceInstance].length === 0) {
    throw new Error('transcript_live_replay_roots_invalid');
  }
  return {
    ...resolveAllowlistedDirectory(options.spool, mapping[sourceInstance], 'replay_spool'),
    classification: 'live', sourceInstance
  };
}

function resolveSource(options, env) {
  if (!options.file) throw new Error('argument_required:file');
  const requested = path.resolve(options.file);
  const real = fs.realpathSync(requested);
  if (requested !== real) throw new Error('transcript_source_symlink_forbidden');
  if (path.extname(real) !== '.jsonl' || !fs.statSync(real).isFile()) throw new Error('transcript_source_invalid');
  if (within(FIXTURE_ROOT, real)) {
    assertNoSymlinkPath(FIXTURE_ROOT, real);
    if (options['allow-live-source']) throw new Error('fixture_live_mode_forbidden');
    return { filePath: real, logicalSource: `${options.runtime}:fixture:${path.basename(real)}`, sourceInstance: 'fixture', fixture: true };
  }
  if (!options['allow-live-source']) throw new Error('live_source_opt_in_required');
  const roots = parseJsonAllowlist(env.AMF_TRANSCRIPT_ALLOWED_ROOTS, 'transcript_allowed_roots').map(root => {
    const requestedRoot = path.resolve(root);
    const realRoot = fs.realpathSync(requestedRoot);
    if (requestedRoot !== realRoot) throw new Error('transcript_source_symlink_forbidden');
    return realRoot;
  });
  const allowedRoot = roots.find(root => within(root, real));
  if (!allowedRoot) throw new Error('transcript_source_not_allowlisted');
  assertNoSymlinkPath(allowedRoot, real);
  const sourceInstance = sourceInstanceFrom(options, env);
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(sourceInstance)) throw new Error('source_instance_invalid');
  const instances = parseJsonAllowlist(env.AMF_TRANSCRIPT_SOURCE_INSTANCES, 'transcript_source_instances');
  if (!instances.includes(sourceInstance)) throw new Error('source_instance_not_allowlisted');
  return {
    filePath: real,
    logicalSource: `${options.runtime}:${sourceInstance}:${path.relative(allowedRoot, real)}`,
    sourceInstance,
    fixture: false
  };
}

function resolveBackfillScope(options, env) {
  if (!options.root || !options.lease) throw new Error('backfill_arguments_required');
  if (!options['allow-live-source']) throw new Error('live_source_opt_in_required');
  const sourceInstance = sourceInstanceFrom(options, env);
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(sourceInstance)) throw new Error('source_instance_invalid');
  const instances = parseJsonAllowlist(env.AMF_TRANSCRIPT_SOURCE_INSTANCES, 'transcript_source_instances');
  if (!instances.includes(sourceInstance)) throw new Error('source_instance_not_allowlisted');
  const sourceRoots = parseJsonAllowlist(env.AMF_TRANSCRIPT_ALLOWED_ROOTS, 'transcript_allowed_roots');
  const source = resolveAllowlistedDirectory(options.root, sourceRoots, 'backfill_root');
  const leaseRoots = parseJsonAllowlist(env.AMF_TRANSCRIPT_LEASE_ROOTS, 'transcript_lease_roots');
  const leaseParent = resolveAllowlistedDirectory(path.dirname(path.resolve(options.lease)), leaseRoots, 'backfill_lease');
  return { rootPath: source.real, leasePath: path.join(leaseParent.real, path.basename(options.lease)), sourceInstanceId: sourceInstance };
}

async function loadTestSink(modulePath) {
  const module = await import(pathToFileURL(path.resolve(modulePath)).href);
  const factory = module.createSink || module.default;
  if (typeof factory !== 'function') throw new Error('sink_factory_required');
  const sink = await factory();
  if (!sink || typeof sink.deliver !== 'function') throw new Error('raw_event_sink_required');
  return sink;
}

async function resolveSink(options, injectedSink, env, { sourceInstanceId, actorId }) {
  if (injectedSink) {
    if (options['sink-module']) throw new Error('sink_injection_conflict');
    if (typeof injectedSink.deliver !== 'function' && typeof injectedSink.deliverCiphertext !== 'function') throw new Error('raw_event_sink_required');
    return injectedSink;
  }
  if (options['sink-module']) {
    if (!options['test-mode'] || options['allow-live-source']) throw new Error('sink_module_test_mode_only');
    return loadTestSink(options['sink-module']);
  }
  if (options['test-mode']) throw new Error('raw_event_sink_required');
  const sink = new HttpRawEventSink({
    endpoint: env.AMF_INGEST_ENDPOINT || '', token: env.AMF_INGEST_TOKEN || '', sourceInstanceId, actorId,
    timeoutMs: boundedEnvInteger(env, 'AMF_INGEST_HTTP_TIMEOUT_MS', 10000, 100, 120000),
    maxRequestBytes: boundedEnvInteger(env, 'AMF_INGEST_HTTP_MAX_REQUEST_BYTES', RAW_EVENT_HTTP_MAX_BODY_BYTES, RAW_EVENT_HTTP_MAX_BODY_BYTES, 16 * 1024 * 1024),
    maxResponseBytes: boundedEnvInteger(env, 'AMF_INGEST_HTTP_MAX_RESPONSE_BYTES', 64 * 1024, 256, 1024 * 1024)
  });
  if (!sink.configured) throw new Error('raw_event_http_sink_unconfigured');
  return sink;
}

export async function main(argv = process.argv.slice(2), env = process.env, { sink: injectedSink = null } = {}) {
  const options = argumentsFrom(argv);
  for (const required of ['spool', 'cursors']) if (!options[required]) throw new Error(`argument_required:${required}`);
  if (!options.replay && !options.runtime) throw new Error('argument_required:runtime');
  if ([options.replay, options.backfill, options['bootstrap-tail']].filter(Boolean).length > 1) throw new Error('ingest_mode_conflict');
  if (options['bootstrap-tail'] && (options['full-audit'] || options['test-mode'] || !options['allow-live-source'])) throw new Error('tail_bootstrap_mode_invalid');
  const backfill = options.backfill ? resolveBackfillScope(options, env) : null;
  const source = options.replay || options.backfill ? null : resolveSource(options, env);
  const cursorNamespace = options['cursor-namespace'] || (source?.fixture || options.replay ? 'default' : '');
  if (backfill && cursorNamespace !== 'backfill') throw new Error('backfill_cursor_namespace_required');
  if (source && !source.fixture && cursorNamespace !== 'realtime') throw new Error('realtime_cursor_namespace_required');
  const replayScope = options.replay ? validateReplayScope(options, env, injectedSink) : null;
  const encryptionKey = env.AMF_OUTBOX_ENCRYPTION_KEY;
  const outboxKeyRing = readKeyRing(env, 'AMF_OUTBOX_KEY_RING');
  const cursorKeyRing = readKeyRing(env, 'AMF_CURSOR_KEY_RING');
  const digestKey = env.AMF_INGEST_DIGEST_KEY || (options['test-mode'] ? encryptionKey : '');
  const sourceInstanceId = replayScope?.sourceInstance || backfill?.sourceInstanceId || source?.sourceInstance || 'fixture';
  const actorId = env.AMF_INGEST_ACTOR_ID || (options['test-mode'] ? 'synthetic-actor' : '');
  const keyId = env.AMF_OUTBOX_KEY_ID || 'default';
  const sink = await resolveSink(options, injectedSink, env, { sourceInstanceId, actorId });
  const outbox = new EncryptedOutbox({
    rootPath: options.spool, encryptionKey, keyRing: outboxKeyRing, digestKey,
    checkpointKey: env.AMF_INGEST_CHECKPOINT_KEY || (options['test-mode'] ? encryptionKey : ''),
    sourceInstanceId, actorId, keyId
  });
  if (options.replay) return { replayed: await outbox.replay(sink) };
  const ingestor = new TranscriptIngestor({
    outbox,
    cursorStore: new CursorStore({
      rootPath: options.cursors,
      encryptionKey: env.AMF_CURSOR_ENCRYPTION_KEY || encryptionKey,
      keyId: env.AMF_CURSOR_KEY_ID || keyId,
      keyRing: cursorKeyRing
    }),
    sink
  });
  if (backfill) return runTranscriptBackfill({ ...backfill, runtime: options.runtime, ingestor, cursorNamespace, fullAudit: Boolean(options['full-audit']) });
  return ingestor.ingestFile({
    runtime: options.runtime,
    filePath: source.filePath,
    logicalSource: source.logicalSource,
    sessionHint: options['session-id'] || null,
    fullAudit: Boolean(options['full-audit']),
    cursorNamespace,
    bootstrapTail: Boolean(options['bootstrap-tail']),
    requireExistingCursor: !source.fixture
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
