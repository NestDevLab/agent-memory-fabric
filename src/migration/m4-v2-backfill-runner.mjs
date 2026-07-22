import { createM4BackfillGateVerifier } from './m4-backfill-gate.mjs';
import { planM4BackfillBatch, runM4BackfillBatch } from './m4-backfill-coordinator.mjs';
import { M4ConversationArchiveSink } from './m4-conversation-archive-sink.mjs';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9-]{2,79}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function validated(code, check) { try { return check(); } catch { fail(code); } }

function planInput(value) {
  return validated('m4_runner_plan_input_invalid', () => {
    if (!exact(value, ['gateInput', 'maxEvents'])) fail('m4_runner_plan_input_invalid');
    return { gateInput: structuredClone(value.gateInput), maxEvents: value.maxEvents };
  });
}

function runInput(value) {
  return validated('m4_runner_run_input_invalid', () => {
    if (!exact(value, ['gateInput', 'maxEvents', 'confirmedPlanDigest', 'factories'])
      || typeof value.confirmedPlanDigest !== 'string' || !DIGEST.test(value.confirmedPlanDigest)) {
      fail('m4_runner_run_input_invalid');
    }
    return { gateInput: structuredClone(value.gateInput), maxEvents: value.maxEvents,
      confirmedPlanDigest: value.confirmedPlanDigest, factories: value.factories };
  });
}

async function planFor(gateInput, maxEvents) {
  let verifier;
  try { verifier = createM4BackfillGateVerifier(gateInput); }
  catch { fail('m4_runner_gate_invalid'); }
  try { return await planM4BackfillBatch({ gateVerifier: verifier, maxEvents }); }
  catch { fail('m4_runner_plan_invalid'); }
}

function factorySet(value, phase) {
  const keys = phase === 'paused-native'
    ? ['lease', 'postCutoffStore', 'source', 'outbox', 'archive', 'checkpointStore']
    : ['lease', 'source', 'outbox', 'archive', 'checkpointStore'];
  return validated('m4_runner_factories_invalid', () => {
    if (!exact(value, keys)) fail('m4_runner_factories_invalid');
    const entries = keys.map(key => [key, value[key]]);
    if (entries.some(([, factory]) => typeof factory !== 'function')) fail('m4_runner_factories_invalid');
    return Object.fromEntries(entries);
  });
}

function invocation(plan) {
  return { runId: plan.runId, phase: plan.phase, planDigest: plan.planDigest,
    sourceCheckpoint: structuredClone(plan.sourceCheckpoint), targetCheckpoint: structuredClone(plan.targetCheckpoint) };
}

async function callFactory(factories, key, input) {
  try { return await factories[key](structuredClone(input)); }
  catch { fail(`m4_runner_${key}_factory_failed`); }
}

function leaseResult(value) {
  return validated('m4_runner_factory_result_invalid', () => {
    if (!object(value) || typeof value.acquire !== 'function' || typeof value.heartbeat !== 'function' || typeof value.release !== 'function') fail('m4_runner_factory_result_invalid');
    return value;
  });
}
function sourceResult(value) { return validated('m4_runner_factory_result_invalid', () => { if (!object(value) || typeof value.open !== 'function') fail('m4_runner_factory_result_invalid'); return value; }); }
function outboxResult(value) { return validated('m4_runner_factory_result_invalid', () => { if (!object(value) || typeof value.enqueue !== 'function' || typeof value.deliver !== 'function') fail('m4_runner_factory_result_invalid'); return value; }); }
function archiveResult(value) {
  return validated('m4_runner_factory_result_invalid', () => {
    if (!exact(value, ['archive', 'resolveIntegrityKey']) || !object(value.archive) || typeof value.archive.append !== 'function'
      || typeof value.archive.tombstone !== 'function' || typeof value.resolveIntegrityKey !== 'function') fail('m4_runner_factory_result_invalid');
    return value;
  });
}
function checkpointStoreResult(value) { return validated('m4_runner_factory_result_invalid', () => { if (!object(value) || typeof value.load !== 'function' || typeof value.commit !== 'function') fail('m4_runner_factory_result_invalid'); return value; }); }
function postCutoffStoreResult(value) { return validated('m4_runner_factory_result_invalid', () => { if (!object(value) || typeof value.load !== 'function' || typeof value.commit !== 'function') fail('m4_runner_factory_result_invalid'); return value; }); }

function copyResult(value, plan) {
  return validated('m4_runner_result_invalid', () => {
    if (!exact(value, ['schema', 'runId', 'phase', 'processed', 'duplicates', 'lastCheckpoint', 'complete'])
      || value.schema !== 'amf.m4-backfill-result/v1' || value.runId !== plan.runId || value.phase !== plan.phase
      || !Number.isSafeInteger(value.processed) || value.processed < 0 || !Number.isSafeInteger(value.duplicates) || value.duplicates < 0
      || value.duplicates > value.processed || typeof value.complete !== 'boolean'
      || !exact(value.lastCheckpoint, ['id', 'digest']) || typeof value.lastCheckpoint.id !== 'string' || !ID.test(value.lastCheckpoint.id)
      || typeof value.lastCheckpoint.digest !== 'string' || !DIGEST.test(value.lastCheckpoint.digest)) {
      fail('m4_runner_result_invalid');
    }
    return structuredClone(value);
  });
}

async function closeResources(items) {
  let failed = false;
  for (const item of [...items].reverse()) {
    try {
      const close = item?.close;
      if (typeof close === 'function') await close.call(item);
    } catch { failed = true; }
  }
  return failed;
}

export async function planM4V2Backfill(input = {}) {
  const request = planInput(input);
  return structuredClone(await planFor(request.gateInput, request.maxEvents));
}

export async function runM4V2Backfill(input = {}) {
  const request = runInput(input);
  const plan = await planFor(request.gateInput, request.maxEvents);
  if (request.confirmedPlanDigest !== plan.planDigest) fail('m4_runner_plan_confirmation_invalid');
  const factories = factorySet(request.factories, plan.phase);
  const created = [];
  let primary = null;
  try {
    const parameters = invocation(plan);
    const lease = leaseResult(await callFactory(factories, 'lease', parameters)); created.push(lease);
    const postCutoffStore = plan.phase === 'paused-native'
      ? postCutoffStoreResult(await callFactory(factories, 'postCutoffStore', parameters)) : null;
    if (postCutoffStore !== null) created.push(postCutoffStore);
    const source = sourceResult(await callFactory(factories, 'source', parameters)); created.push(source);
    const outbox = outboxResult(await callFactory(factories, 'outbox', parameters)); created.push(outbox);
    const archive = archiveResult(await callFactory(factories, 'archive', parameters)); created.push(archive.archive);
    const checkpointStore = checkpointStoreResult(await callFactory(factories, 'checkpointStore', parameters)); created.push(checkpointStore);
    const sink = new M4ConversationArchiveSink(archive);
    let result;
    try {
      result = await runM4BackfillBatch({ gateVerifier: createM4BackfillGateVerifier(request.gateInput), maxEvents: request.maxEvents,
        confirmedPlanDigest: plan.planDigest, lease, source, outbox, sink, checkpointStore, postCutoffStore });
    } catch (error) {
      if (error?.code?.startsWith?.('m4_')) throw error;
      fail('m4_runner_execution_failed');
    }
    return copyResult(result, plan);
  } catch (error) {
    primary = error;
    throw error;
  } finally {
    const cleanupFailed = await closeResources(created);
    if (primary === null && cleanupFailed) fail('m4_runner_cleanup_failed');
  }
}
