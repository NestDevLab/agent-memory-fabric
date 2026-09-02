import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { buildContextRequest, normalizeOpaqueTagMap } from '../access-contract.mjs';
import { issueContextToken, normalizeContextKeyRing, requestDigest } from '../context-token.mjs';
import {
  INTERACTIVE_RECALL_HANDOFF_SCHEMA,
  INTERACTIVE_RECALL_WRITE_HANDOFF_SCHEMA,
  INTERACTIVE_RECALL_PERMISSIONS,
  INTERACTIVE_RECALL_WRITE_PERMISSIONS,
  INTERACTIVE_RECALL_SCOPES,
  interactiveRecallProfile,
  normalizeInteractiveRecallEndpoint
} from './interactive-recall-provisioning.mjs';

export const INTERACTIVE_RECALL_HANDOFF_ENV = 'AMF_INTERACTIVE_RECALL_HANDOFF_DIR';
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const HANDOFF_FILES = Object.freeze(['bearer.token', 'context-key-ring.json', 'manifest.json']);
const GOVERNED_WRITE_RECORD_CONTRACT = 'record must be an exact amf-memory/v1 object with schema, id, revision, claimType, scope, visibility, subjects, claim, confidence, lifecycle, provenance, createdAt, and updatedAt. New records use revision 1, expectedRevision null, and lifecycle.supersedes []. scope.id is fixed to shared:global. claimType is fact, preference, event, decision, instruction, summary, or relationship. visibility is private, restricted, shared, or confidential. Use a sealed claim when the record or subjects are sensitive.';
const GOVERNED_WRITE_EXAMPLE = JSON.stringify({ schema: 'amf-memory/v1', id: 'mem_example_handoff_0001', revision: 1, claimType: 'summary', scope: { type: 'shared', id: 'shared:global' }, visibility: 'shared', subjects: [{ identityId: 'agent:chatgpt-web', role: 'owner' }], claim: { encoding: 'plain', text: 'Short handoff summary.' }, confidence: { score: 0.8, basis: 'asserted', assessedAt: '2026-01-01T00:00:00.000Z' }, lifecycle: { status: 'active', validFrom: '2026-01-01T00:00:00.000Z', validTo: null, supersedes: [], revokedAt: null, revocationReason: null }, provenance: [{ sourceType: 'chatgpt-web', sourceId: 'durable-source-ref', eventId: 'event_example_0001', contentSha256: '21a4b3360f5d340c7c3f1672669f5fcda06314959dfb4a78631ec751cc9f4709', capturedAt: '2026-01-01T00:00:00.000Z' }], createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' });

function fail(code) { throw new Error(code); }

function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }

function exactKeys(value, keys) {
  return object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function exactArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]);
}

function statOwnedByCurrentUser(stat) {
  const uid = process.geteuid?.();
  return uid === undefined || uid === 0 || stat.uid === uid;
}

function readPrivateDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail('interactive_recall_handoff_path_invalid');
  let stat;
  try { stat = fs.lstatSync(directory); } catch { fail('interactive_recall_handoff_unavailable'); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || !statOwnedByCurrentUser(stat)) {
    fail('interactive_recall_handoff_unsafe');
  }
  return { path: path.resolve(directory), stat };
}

function readPrivateFile(directory, name) {
  const filePath = path.join(directory.path, name);
  let before; let descriptor;
  try {
    before = fs.lstatSync(filePath);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600
      || !statOwnedByCurrentUser(before)) fail('interactive_recall_handoff_unsafe');
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino
      || (opened.mode & 0o777) !== 0o600 || !statOwnedByCurrentUser(opened)) {
      fail('interactive_recall_handoff_unsafe');
    }
    return fs.readFileSync(descriptor);
  } catch (error) {
    if (error?.message?.startsWith('interactive_recall_')) throw error;
    fail('interactive_recall_handoff_unavailable');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseJson(bytes) {
  try { return JSON.parse(bytes.toString('utf8')); } catch { fail('interactive_recall_handoff_invalid'); }
}

function validateManifest(value) {
  const writeEnabled = value?.schema === INTERACTIVE_RECALL_WRITE_HANDOFF_SCHEMA;
  const keys = ['schema', 'actor', 'runtime', 'profile', 'contextKeyVersion', 'permissions', 'scopes',
    'scopeSetSha256', 'purpose', 'sessionDescriptor', 'policyRevision', 'endpoint', 'createdAt'];
  if (writeEnabled) keys.push('tools');
  if (!exactKeys(value, keys) || (!writeEnabled && value.schema !== INTERACTIVE_RECALL_HANDOFF_SCHEMA)
    || typeof value.runtime !== 'string' || typeof value.profile !== 'string') {
    fail('interactive_recall_handoff_invalid');
  }
  let expected;
  try { expected = interactiveRecallProfile(value.runtime, { writeEnabled }); } catch { fail('interactive_recall_handoff_invalid'); }
  if (value.actor !== expected.actor || value.profile !== expected.profile
    || value.contextKeyVersion !== expected.contextKeyVersion || value.purpose !== expected.purpose
    || !exactArray(value.permissions, expected.permissions) || !exactArray(value.scopes, expected.scopes)
    || (writeEnabled && !exactArray(value.tools, expected.tools))
    || typeof value.scopeSetSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeSetSha256)
    || value.scopeSetSha256 !== crypto.createHash('sha256').update(canonicalJson(expected.scopes), 'utf8').digest('hex')
    || typeof value.policyRevision !== 'string' || !SAFE_ID.test(value.policyRevision)
    || !Number.isFinite(Date.parse(value.createdAt))) {
    fail('interactive_recall_handoff_invalid');
  }
  try {
    if (normalizeInteractiveRecallEndpoint(value.endpoint) !== value.endpoint
      || !exactKeys(value.sessionDescriptor, ['conversationKind', 'contextTags'])
      || canonicalJson(normalizeOpaqueTagMap(value.sessionDescriptor?.contextTags))
        !== canonicalJson(expected.sessionDescriptor.contextTags)
      || value.sessionDescriptor?.conversationKind !== expected.sessionDescriptor.conversationKind) {
      fail('interactive_recall_handoff_invalid');
    }
  } catch { fail('interactive_recall_handoff_invalid'); }
  return {
    actor: expected.actor,
    runtime: expected.runtime,
    profile: expected.profile,
    contextKeyVersion: expected.contextKeyVersion,
    permissions: [...(writeEnabled ? INTERACTIVE_RECALL_WRITE_PERMISSIONS : INTERACTIVE_RECALL_PERMISSIONS)],
    scopes: [...INTERACTIVE_RECALL_SCOPES],
    purpose: expected.purpose,
    sessionDescriptor: expected.sessionDescriptor,
    policyRevision: value.policyRevision,
    endpoint: value.endpoint,
    tools: writeEnabled ? [...expected.tools] : ['memory_search', 'memory_read']
  };
}

export function loadInteractiveRecallHandoff(directory) {
  const handoff = readPrivateDirectory(directory);
  const files = Object.fromEntries(HANDOFF_FILES.map(name => [name, readPrivateFile(handoff, name)]));
  const bearer = files['bearer.token'].toString('utf8');
  if (!/^[A-Za-z0-9_-]{43}\n$/.test(bearer)) fail('interactive_recall_handoff_invalid');
  const manifest = validateManifest(parseJson(files['manifest.json']));
  let keyRing;
  try { keyRing = normalizeContextKeyRing(parseJson(files['context-key-ring.json'])); }
  catch { fail('interactive_recall_handoff_invalid'); }
  if (keyRing.currentKeyVersion !== manifest.contextKeyVersion || keyRing.keys.size !== 1
    || !keyRing.keys.has(manifest.contextKeyVersion)) fail('interactive_recall_handoff_invalid');
  return { ...manifest, bearer: bearer.slice(0, -1), keyRing };
}

function rpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function toolDefinitions(handoff) {
  const definitions = [
    { name: 'memory_search', description: 'Search shared canonical memories for the current interactive session.',
      inputSchema: { type: 'object', additionalProperties: false,
        properties: { query: { type: 'string', minLength: 1, maxLength: 4096 },
          limit: { type: 'integer', minimum: 1, maximum: 100 }, cursor: { type: ['string', 'null'] },
          from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] } }, required: ['query'] } },
    { name: 'memory_read', description: 'Read one shared canonical memory by identifier.',
      inputSchema: { type: 'object', additionalProperties: false,
        properties: { id: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['id'] } }
  ];
  if (handoff.tools.includes('memory_upsert')) {
    definitions.push(
      { name: 'memory_upsert', description: `Queue a governed canonical memory proposal. Updates require expectedRevision and a new revisioned record with lifecycle.supersedes; this tool never writes canonical state directly. ${GOVERNED_WRITE_RECORD_CONTRACT} Large Markdown is not stored as a claim: when the proposal exceeds the server limit (default 32768 characters), store the full document durably and submit a bounded summary or instruction claim with its durable reference. The server returns proposal_too_large with its actual limit and this remediation. Worked example: ${GOVERNED_WRITE_EXAMPLE}`,
        inputSchema: { type: 'object', additionalProperties: false,
          properties: { record: { type: 'object', description: `${GOVERNED_WRITE_RECORD_CONTRACT} Example: ${GOVERNED_WRITE_EXAMPLE}` }, rationale: { type: 'string', minLength: 1, maxLength: 4096 },
            expectedRevision: { type: ['integer', 'null'], minimum: 0 },
            idempotencyKey: { type: 'string', minLength: 1, maxLength: 192 } },
          required: ['record', 'rationale', 'expectedRevision', 'idempotencyKey'] } },
      { name: 'memory_proposal_status', description: 'Read the bounded lifecycle status of a governed memory proposal.',
        inputSchema: { type: 'object', additionalProperties: false,
          properties: { id: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['id'] } }
    );
  }
  return definitions;
}

function requireOnly(value, allowed) {
  if (!object(value) || Object.keys(value).some(key => !allowed.has(key))) fail('interactive_recall_tool_input_invalid');
}

function searchInput(value) {
  requireOnly(value, new Set(['query', 'limit', 'cursor', 'from', 'to']));
  if (typeof value.query !== 'string' || !value.query.trim() || value.query.length > 4096) fail('interactive_recall_tool_input_invalid');
  const output = { query: value.query };
  if (Object.hasOwn(value, 'limit')) {
    if (!Number.isInteger(value.limit) || value.limit < 1 || value.limit > 100) fail('interactive_recall_tool_input_invalid');
    output.limit = value.limit;
  }
  for (const key of ['cursor', 'from', 'to']) {
    if (Object.hasOwn(value, key)) {
      if (value[key] !== null && typeof value[key] !== 'string') fail('interactive_recall_tool_input_invalid');
      output[key] = value[key];
    }
  }
  return output;
}

function readInput(value) {
  requireOnly(value, new Set(['id']));
  if (typeof value.id !== 'string' || !SAFE_ID.test(value.id)) fail('interactive_recall_tool_input_invalid');
  return { id: value.id };
}

function upsertInput(value) {
  requireOnly(value, new Set(['record', 'rationale', 'expectedRevision', 'idempotencyKey']));
  if (!object(value.record) || value.record?.scope?.id !== INTERACTIVE_RECALL_SCOPES[0]
    || typeof value.rationale !== 'string' || !value.rationale.trim() || value.rationale.length > 4096
    || (value.expectedRevision !== null && (!Number.isInteger(value.expectedRevision) || value.expectedRevision < 0))
    || typeof value.idempotencyKey !== 'string' || !SAFE_ID.test(value.idempotencyKey)) {
    fail('interactive_recall_tool_input_invalid');
  }
  const revision = Number(value.record.revision);
  const supersedes = value.record?.lifecycle?.supersedes;
  if (!Number.isInteger(revision) || revision < 1 || (value.expectedRevision === null
    ? revision !== 1 || !Array.isArray(supersedes) || supersedes.length !== 0
    : revision !== value.expectedRevision + 1 || !Array.isArray(supersedes) || supersedes.length < 1)) {
    fail('interactive_recall_tool_input_invalid');
  }
  return { record: value.record, rationale: value.rationale.trim(), expectedRevision: value.expectedRevision,
    idempotencyKey: value.idempotencyKey };
}

function nonce(randomBytes) {
  const bytes = Buffer.from(randomBytes(24));
  if (bytes.length !== 24) fail('interactive_recall_random_source_invalid');
  return bytes.toString('base64url');
}

function nowIso(clock) {
  const now = Number(clock());
  if (!Number.isFinite(now)) fail('interactive_recall_clock_invalid');
  return new Date(now);
}

function safeUpstreamResult(value) {
  if (!object(value)) fail('interactive_recall_upstream_invalid');
  return Object.hasOwn(value, 'data') ? value.data : value;
}

function upstreamFailure(code, details = null) {
  const error = new Error(`interactive_recall_upstream_${code}`);
  error.details = details;
  throw error;
}

function boundedFields(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter(field => typeof field === 'string' && /^(schema|id|revision|claimType|scope|visibility|subjects|claim|confidence|lifecycle|provenance|createdAt|updatedAt|record)$/.test(field)))].slice(0, 12);
}

function safeUpstreamFailure(body) {
  const error = object(body?.error) ? body.error : null;
  if (!error || typeof error.code !== 'string') return null;
  if (error.code === 'canonical_record_invalid') {
    return { code: error.code, details: { fields: boundedFields(error.details?.fields),
      action: 'Use the published amf-memory/v1 record template and supply every required field.' } };
  }
  if (error.code === 'proposal_too_large') {
    const maxChars = Number(error.details?.maxChars); const observedChars = Number(error.details?.observedChars);
    return { code: error.code, details: { ...(Number.isSafeInteger(maxChars) && maxChars > 0 ? { maxChars } : {}),
      ...(Number.isSafeInteger(observedChars) && observedChars > 0 ? { observedChars } : {}),
      strategy: 'summary_plus_pointer',
      action: 'Store the full document durably, then submit a bounded summary or instruction claim with a durable reference.' } };
  }
  return null;
}

function upstreamErrorData(message) {
  if (message === 'interactive_recall_upstream_unavailable') {
    return { code: 'memory_upstream_unavailable', retryable: true, action: 'Retry the request after the memory service is available.' };
  }
  if (message === 'interactive_recall_upstream_invalid') {
    return { code: 'memory_upstream_invalid_response', retryable: true, action: 'Retry the request; if it persists, report the request id to the AMF operator.' };
  }
  return { code: 'memory_upstream_failed', retryable: false, action: 'Check the governed record contract or request status, then retry with a corrected request.' };
}

export function createInteractiveRecallBridge({ handoff, fetchImpl = globalThis.fetch,
  clock = () => Date.now(), randomBytes = crypto.randomBytes } = {}) {
  if (!handoff || typeof handoff !== 'object' || typeof handoff.bearer !== 'string'
    || !(handoff.keyRing?.keys instanceof Map) || typeof fetchImpl !== 'function') {
    fail('interactive_recall_bridge_invalid');
  }

  function contextToken(operation, input) {
    const issuedAt = nowIso(clock); const expiresAt = new Date(issuedAt.getTime() + 60_000);
    return issueContextToken({ actor: handoff.actor, runtime: handoff.runtime, profile: handoff.profile,
      conversationKind: handoff.sessionDescriptor.conversationKind,
      contextTags: handoff.sessionDescriptor.contextTags, purpose: handoff.purpose,
      policyRevision: handoff.policyRevision, issuedAt: issuedAt.toISOString(), expiresAt: expiresAt.toISOString(),
      nonce: nonce(randomBytes), canonicalScopes: [...INTERACTIVE_RECALL_SCOPES],
      requestDigest: requestDigest(buildContextRequest(operation, input)) }, handoff.keyRing);
  }

  async function request(url, init) {
    let response;
    try { response = await fetchImpl(url, init); } catch { fail('interactive_recall_upstream_unavailable'); }
    let body;
    try { body = JSON.parse(await response.text()); } catch { fail('interactive_recall_upstream_invalid'); }
    if (!response.ok) {
      const failure = safeUpstreamFailure(body);
      if (failure) upstreamFailure(failure.code, failure.details);
      fail('interactive_recall_upstream_failed');
    }
    return safeUpstreamResult(body);
  }

  async function callTool(name, args) {
    if (name === 'memory_search') {
      const input = searchInput(args);
      const body = { ...input, scopes: [...INTERACTIVE_RECALL_SCOPES], purpose: 'conversation_recall' };
      body.contextToken = contextToken('memory_search', body);
      return request(new URL('v2/memory/search', handoff.endpoint), {
        method: 'POST', headers: { authorization: `Bearer ${handoff.bearer}`, 'content-type': 'application/json' },
        body: JSON.stringify(body)
      });
    }
    if (name === 'memory_read') {
      const input = readInput(args); const token = contextToken('memory_read', input);
      // SAFE_ID excludes path delimiters, so preserve canonical identifier characters for the signed request.
      const url = new URL(`v2/memory/${input.id}`, handoff.endpoint);
      url.searchParams.set('purpose', 'conversation_recall');
      return request(url, { method: 'GET', headers: { authorization: `Bearer ${handoff.bearer}`,
        'x-amf-context-token': token } });
    }
    if (name === 'memory_upsert' && handoff.tools.includes(name)) {
      const input = upsertInput(args); const { idempotencyKey, ...body } = input;
      return request(new URL('v2/memory/proposals', handoff.endpoint), {
        method: 'POST', headers: { authorization: `Bearer ${handoff.bearer}`, 'content-type': 'application/json',
          'idempotency-key': idempotencyKey }, body: JSON.stringify(body)
      });
    }
    if (name === 'memory_proposal_status' && handoff.tools.includes(name)) {
      const input = readInput(args);
      return request(new URL(`v2/memory/proposals/${input.id}`, handoff.endpoint), {
        method: 'GET', headers: { authorization: `Bearer ${handoff.bearer}` }
      });
    }
    fail('interactive_recall_tool_unknown');
  }

  async function handleRpc(message) {
    const id = object(message) && Object.hasOwn(message, 'id') ? message.id : null;
    if (!object(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      return rpcError(id, -32600, 'Invalid request');
    }
    if (message.method === 'initialize') {
      return rpcResult(id, { protocolVersion: String(message.params?.protocolVersion || '2025-03-26'),
        capabilities: { tools: {} }, serverInfo: { name: 'amf-interactive-recall', version: '1' } });
    }
    if (message.method === 'notifications/initialized') return null;
    if (message.method === 'tools/list') return rpcResult(id, { tools: toolDefinitions(handoff) });
    if (message.method !== 'tools/call') return rpcError(id, -32601, 'Unsupported method');
    const name = message.params?.name;
    if (!handoff.tools.includes(name)) return rpcError(id, -32601, 'Unknown tool');
    try {
      const result = await callTool(name, message.params?.arguments || {});
      return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result) }] });
    } catch (error) {
      if (error?.message === 'interactive_recall_upstream_canonical_record_invalid') {
        return rpcError(id, -32602, 'Invalid governed memory record', { code: 'canonical_record_invalid', ...error.details });
      }
      if (error?.message === 'interactive_recall_upstream_proposal_too_large') {
        return rpcError(id, -32602, 'Governed memory proposal is too large', { code: 'proposal_too_large', ...error.details });
      }
      const code = error?.message === 'interactive_recall_tool_input_invalid' ? -32602 : -32000;
      return rpcError(id, code, code === -32602 ? 'Invalid tool arguments' : 'Memory request failed',
        code === -32602 ? { code: 'invalid_tool_arguments', action: 'Check the tool input schema and retry.' } : upstreamErrorData(error?.message));
    }
  }

  return Object.freeze({ handleRpc, tools: toolDefinitions(handoff) });
}

export function createInteractiveRecallBridgeFromDirectory(directory, options = {}) {
  return createInteractiveRecallBridge({ ...options, handoff: loadInteractiveRecallHandoff(directory) });
}
