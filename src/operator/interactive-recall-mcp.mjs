import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { buildContextRequest, normalizeOpaqueTagMap } from '../access-contract.mjs';
import { issueContextToken, normalizeContextKeyRing, requestDigest } from '../context-token.mjs';
import {
  INTERACTIVE_RECALL_HANDOFF_SCHEMA,
  INTERACTIVE_RECALL_PERMISSIONS,
  INTERACTIVE_RECALL_SCOPES,
  interactiveRecallProfile,
  normalizeInteractiveRecallEndpoint
} from './interactive-recall-provisioning.mjs';

export const INTERACTIVE_RECALL_HANDOFF_ENV = 'AMF_INTERACTIVE_RECALL_HANDOFF_DIR';
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const HANDOFF_FILES = Object.freeze(['bearer.token', 'context-key-ring.json', 'manifest.json']);

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
  const keys = ['schema', 'actor', 'runtime', 'profile', 'contextKeyVersion', 'permissions', 'scopes',
    'scopeSetSha256', 'purpose', 'sessionDescriptor', 'policyRevision', 'endpoint', 'createdAt'];
  if (!exactKeys(value, keys) || value.schema !== INTERACTIVE_RECALL_HANDOFF_SCHEMA
    || typeof value.runtime !== 'string' || typeof value.profile !== 'string') {
    fail('interactive_recall_handoff_invalid');
  }
  let expected;
  try { expected = interactiveRecallProfile(value.runtime); } catch { fail('interactive_recall_handoff_invalid'); }
  if (value.actor !== expected.actor || value.profile !== expected.profile
    || value.contextKeyVersion !== expected.contextKeyVersion || value.purpose !== expected.purpose
    || !exactArray(value.permissions, expected.permissions) || !exactArray(value.scopes, expected.scopes)
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
    permissions: [...INTERACTIVE_RECALL_PERMISSIONS],
    scopes: [...INTERACTIVE_RECALL_SCOPES],
    purpose: expected.purpose,
    sessionDescriptor: expected.sessionDescriptor,
    policyRevision: value.policyRevision,
    endpoint: value.endpoint
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
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

function toolDefinitions() {
  return [
    { name: 'memory_search', description: 'Search shared canonical memories for the current interactive session.',
      inputSchema: { type: 'object', additionalProperties: false,
        properties: { query: { type: 'string', minLength: 1, maxLength: 4096 },
          limit: { type: 'integer', minimum: 1, maximum: 100 }, cursor: { type: ['string', 'null'] },
          from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] } }, required: ['query'] } },
    { name: 'memory_read', description: 'Read one shared canonical memory by identifier.',
      inputSchema: { type: 'object', additionalProperties: false,
        properties: { id: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['id'] } }
  ];
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
    if (!response.ok) fail('interactive_recall_upstream_failed');
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
    if (message.method === 'tools/list') return rpcResult(id, { tools: toolDefinitions() });
    if (message.method !== 'tools/call') return rpcError(id, -32601, 'Unsupported method');
    const name = message.params?.name;
    if (name !== 'memory_search' && name !== 'memory_read') return rpcError(id, -32601, 'Unknown tool');
    try {
      const result = await callTool(name, message.params?.arguments || {});
      return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result) }] });
    } catch (error) {
      const code = error?.message === 'interactive_recall_tool_input_invalid' ? -32602 : -32000;
      return rpcError(id, code, code === -32602 ? 'Invalid tool arguments' : 'Memory request failed');
    }
  }

  return Object.freeze({ handleRpc, tools: toolDefinitions() });
}

export function createInteractiveRecallBridgeFromDirectory(directory, options = {}) {
  return createInteractiveRecallBridge({ ...options, handoff: loadInteractiveRecallHandoff(directory) });
}
