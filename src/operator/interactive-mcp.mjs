import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { buildContextRequest, normalizeOpaqueTagMap } from '../access-contract.mjs';
import { issueContextToken, normalizeContextKeyRing, requestDigest } from '../context-token.mjs';
import { INTERACTIVE_MCP_HANDOFF_SCHEMA, INTERACTIVE_MCP_TOOLS, interactiveMcpPermissions, interactiveMcpPurposes } from './interactive-mcp-provisioning.mjs';

export const INTERACTIVE_MCP_HANDOFF_ENV = 'AMF_INTERACTIVE_MCP_HANDOFF_DIR';
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const HANDOFF_FILES = Object.freeze(['bearer.token', 'context-key-ring.json', 'manifest.json']);

function fail(code) { throw new Error(code); }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function exactKeys(value, keys) { return object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function canonicalJson(value) { if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`; if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function exactArray(value, expected) { return Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]); }
function owned(stat) { const uid = process.geteuid?.(); return uid === undefined || uid === 0 || stat.uid === uid; }

function readDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail('interactive_mcp_handoff_path_invalid');
  let stat; try { stat = fs.lstatSync(directory); } catch { fail('interactive_mcp_handoff_unavailable'); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || !owned(stat)) fail('interactive_mcp_handoff_unsafe');
  return { path: path.resolve(directory), stat };
}
function readFile(directory, name) {
  let before; let fd;
  try {
    before = fs.lstatSync(path.join(directory.path, name));
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600 || !owned(before)) fail('interactive_mcp_handoff_unsafe');
    fd = fs.openSync(path.join(directory.path, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || (opened.mode & 0o777) !== 0o600 || !owned(opened)) fail('interactive_mcp_handoff_unsafe');
    return fs.readFileSync(fd);
  } catch (error) { if (error?.message?.startsWith('interactive_mcp_')) throw error; fail('interactive_mcp_handoff_unavailable'); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function parseJson(bytes) { try { return JSON.parse(bytes.toString('utf8')); } catch { fail('interactive_mcp_handoff_invalid'); } }
function endpoint(value) {
  try { const parsed = new URL(value); if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password || parsed.hash || parsed.search || parsed.pathname !== '/') throw new Error(); return parsed.toString(); }
  catch { fail('interactive_mcp_handoff_invalid'); }
}
function grantList(value, { scope = false, wildcard = false } = {}) {
  const pattern = scope ? /^(?:agent|person|relationship|room|domain|shared):[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/ : SAFE_ID;
  if (!Array.isArray(value) || !value.length || value.some(item => typeof item !== 'string' || (item !== '*' && !pattern.test(item)) || (item === '*' && !wildcard))
    || new Set(value).size !== value.length || (value.includes('*') && value.length !== 1)
    || canonicalJson([...value].sort()) !== canonicalJson(value)) fail('interactive_mcp_handoff_invalid');
  return [...value];
}
function validateManifest(value) {
  const keys = ['schema', 'actor', 'runtime', 'profile', 'contextKeyVersion', 'permissions', 'readScopes', 'proposeScopes', 'readVaults', 'writeVaults', 'purpose', 'purposes', 'tools', 'sessionDescriptor', 'policyRevision', 'endpoint', 'createdAt'];
  if (!exactKeys(value, keys) || value.schema !== INTERACTIVE_MCP_HANDOFF_SCHEMA || !['codex', 'claude'].includes(value.runtime) || value.actor !== `client:mcp:${value.runtime}` || value.profile !== 'interactive-mcp' || value.contextKeyVersion !== `ctx-mcp-${value.runtime}-v1` || value.purpose !== 'operator_review' || !Array.isArray(value.tools) || !value.tools.length || value.tools.some(tool => !INTERACTIVE_MCP_TOOLS.includes(tool)) || new Set(value.tools).size !== value.tools.length || !exactArray(value.tools, INTERACTIVE_MCP_TOOLS.filter(tool => value.tools.includes(tool))) || !exactArray(value.permissions, interactiveMcpPermissions(value.tools)) || !exactArray(value.purposes, interactiveMcpPurposes(value.tools))) fail('interactive_mcp_handoff_invalid');
  const readScopes = grantList(value.readScopes, { scope: true, wildcard: true });
  const proposeScopes = grantList(value.proposeScopes, { scope: true });
  const readVaults = grantList(value.readVaults, { wildcard: true });
  const writeVaults = grantList(value.writeVaults);
  if (typeof value.policyRevision !== 'string' || !SAFE_ID.test(value.policyRevision) || !Number.isFinite(Date.parse(value.createdAt)) || endpoint(value.endpoint) !== value.endpoint) fail('interactive_mcp_handoff_invalid');
  try { if (!exactKeys(value.sessionDescriptor, ['conversationKind', 'contextTags']) || value.sessionDescriptor.conversationKind !== 'session' || canonicalJson(normalizeOpaqueTagMap(value.sessionDescriptor.contextTags)) !== canonicalJson(value.sessionDescriptor.contextTags)) fail('interactive_mcp_handoff_invalid'); } catch { fail('interactive_mcp_handoff_invalid'); }
  return { actor: value.actor, runtime: value.runtime, profile: value.profile, contextKeyVersion: value.contextKeyVersion, permissions: [...value.permissions], readScopes, proposeScopes, readVaults, writeVaults, sessionDescriptor: value.sessionDescriptor, policyRevision: value.policyRevision, endpoint: value.endpoint, tools: [...value.tools] };
}

export function loadInteractiveMcpHandoff(directory) {
  const handoff = readDirectory(directory); const files = Object.fromEntries(HANDOFF_FILES.map(name => [name, readFile(handoff, name)]));
  const bearer = files['bearer.token'].toString('utf8'); if (!/^[A-Za-z0-9_-]{43}\n$/.test(bearer)) fail('interactive_mcp_handoff_invalid');
  const manifest = validateManifest(parseJson(files['manifest.json'])); let keyRing;
  try { keyRing = normalizeContextKeyRing(parseJson(files['context-key-ring.json'])); } catch { fail('interactive_mcp_handoff_invalid'); }
  if (keyRing.currentKeyVersion !== manifest.contextKeyVersion || keyRing.keys.size !== 1 || !keyRing.keys.has(manifest.contextKeyVersion)) fail('interactive_mcp_handoff_invalid');
  return { ...manifest, bearer: bearer.slice(0, -1), keyRing };
}

function rpcResult(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }
function definitions() {
  return {
    memory_search: { name: 'memory_search', description: 'Search canonical memories only in granted scopes.', inputSchema: { type: 'object', additionalProperties: false, properties: { query: { type: 'string', minLength: 1, maxLength: 4096 }, limit: { type: 'integer', minimum: 1, maximum: 100 }, cursor: { type: ['string', 'null'] }, from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] } }, required: ['query'] } },
    memory_read: { name: 'memory_read', description: 'Read one authorized canonical memory.', inputSchema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['id'] } },
    memory_propose: { name: 'memory_propose', description: 'Queue an authorized proposal candidate for curation; it never applies a memory directly.', inputSchema: { type: 'object', additionalProperties: false, properties: { scope: { type: 'string', minLength: 1, maxLength: 192 }, text: { type: 'string', minLength: 1, maxLength: 4096 }, metadata: { type: 'object' }, infer: { type: 'boolean' }, idempotencyKey: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['scope', 'text', 'idempotencyKey'] } },
    memory_proposal_status: { name: 'memory_proposal_status', description: 'Read the lifecycle of an authorized proposal.', inputSchema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['id'] } },
    documents_search: { name: 'documents_search', description: 'Search documents in granted vaults only.', inputSchema: { type: 'object', additionalProperties: false, properties: { query: { type: 'string', minLength: 1, maxLength: 4096 }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, required: ['query'] } },
    document_read: { name: 'document_read', description: 'Read an authorized document revision.', inputSchema: { type: 'object', additionalProperties: false, properties: { documentId: { type: 'string', minLength: 1, maxLength: 192 }, revision: { type: ['integer', 'null'], minimum: 1 } }, required: ['documentId'] } },
    document_upsert: { name: 'document_upsert', description: 'Write an authorized revisioned document to a granted vault.', inputSchema: { type: 'object', additionalProperties: false, properties: { document: { type: 'object' }, text: { type: ['string', 'null'] }, expectedRevision: { type: ['integer', 'null'], minimum: 0 }, idempotencyKey: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['document', 'text', 'expectedRevision', 'idempotencyKey'] } },
    document_delete: { name: 'document_delete', description: 'Append an authorized document tombstone in a granted vault.', inputSchema: { type: 'object', additionalProperties: false, properties: { document: { type: 'object' }, expectedRevision: { type: 'integer', minimum: 1 }, idempotencyKey: { type: 'string', minLength: 1, maxLength: 192 } }, required: ['document', 'expectedRevision', 'idempotencyKey'] } },
    memory_status: { name: 'memory_status', description: 'Return bounded Fabric readiness.', inputSchema: { type: 'object', additionalProperties: false, properties: {} } }
  };
}
function requireOnly(value, keys) { if (!object(value) || Object.keys(value).some(key => !keys.has(key))) fail('interactive_mcp_tool_input_invalid'); }
function safeId(value) { if (typeof value !== 'string' || !SAFE_ID.test(value)) fail('interactive_mcp_tool_input_invalid'); return value; }
function nonce(randomBytes) { const bytes = Buffer.from(randomBytes(24)); if (bytes.length !== 24) fail('interactive_mcp_random_source_invalid'); return bytes.toString('base64url'); }
function safeResult(value) { if (!object(value)) fail('interactive_mcp_upstream_invalid'); return Object.hasOwn(value, 'data') ? value.data : value; }

export function createInteractiveMcpBridge({ handoff, fetchImpl = globalThis.fetch, clock = () => Date.now(), randomBytes = crypto.randomBytes } = {}) {
  if (!handoff || typeof handoff.bearer !== 'string' || !(handoff.keyRing?.keys instanceof Map) || typeof fetchImpl !== 'function') fail('interactive_mcp_bridge_invalid');
  const tools = definitions(); const allowed = new Set(handoff.tools);
  const contextToken = (purpose, operation, input) => {
    const now = Number(clock()); if (!Number.isFinite(now)) fail('interactive_mcp_clock_invalid'); const issuedAt = new Date(now); const expiresAt = new Date(now + 60_000);
    const canonicalScopes = handoff.readScopes.includes('*') ? undefined : handoff.readScopes;
    return issueContextToken({ actor: handoff.actor, runtime: handoff.runtime, profile: handoff.profile, conversationKind: handoff.sessionDescriptor.conversationKind, contextTags: handoff.sessionDescriptor.contextTags, purpose, policyRevision: handoff.policyRevision, issuedAt: issuedAt.toISOString(), expiresAt: expiresAt.toISOString(), nonce: nonce(randomBytes), ...(canonicalScopes ? { canonicalScopes } : {}), requestDigest: requestDigest(buildContextRequest(operation, input)) }, handoff.keyRing);
  };
  const request = async (url, init) => { let response; try { response = await fetchImpl(url, init); } catch { fail('interactive_mcp_upstream_unavailable'); } let body; try { body = JSON.parse(await response.text()); } catch { fail('interactive_mcp_upstream_invalid'); } if (!response.ok) fail('interactive_mcp_upstream_failed'); return safeResult(body); };
  const headers = extra => ({ authorization: `Bearer ${handoff.bearer}`, 'content-type': 'application/json', ...extra });
  const writeInput = (args, deleting = false) => { requireOnly(args, deleting ? new Set(['document', 'expectedRevision', 'idempotencyKey']) : new Set(['document', 'text', 'expectedRevision', 'idempotencyKey'])); if (!object(args.document) || !handoff.writeVaults.includes(String(args.document.vaultId || '')) || typeof args.idempotencyKey !== 'string' || !args.idempotencyKey || args.idempotencyKey.length > 192 || !Number.isInteger(args.expectedRevision) || args.expectedRevision < (deleting ? 1 : 0) || (!deleting && args.text !== null && typeof args.text !== 'string')) fail('interactive_mcp_tool_input_invalid'); return { ...args }; };
  async function callTool(name, args) {
    if (!allowed.has(name)) fail('interactive_mcp_tool_unknown');
    if (name === 'memory_search') { requireOnly(args, new Set(['query', 'limit', 'cursor', 'from', 'to'])); if (typeof args.query !== 'string' || !args.query.trim() || args.query.length > 4096) fail('interactive_mcp_tool_input_invalid'); const body = { ...args, scopes: handoff.readScopes, purpose: 'conversation_recall' }; body.contextToken = contextToken('conversation_recall', 'memory_search', body); return request(new URL('v2/memory/search', handoff.endpoint), { method: 'POST', headers: headers(), body: JSON.stringify(body) }); }
    if (name === 'memory_read') { requireOnly(args, new Set(['id'])); const id = safeId(args.id); const token = contextToken('conversation_recall', 'memory_read', { id }); const url = new URL(`v2/memory/${id}`, handoff.endpoint); url.searchParams.set('purpose', 'conversation_recall'); return request(url, { method: 'GET', headers: { authorization: `Bearer ${handoff.bearer}`, 'x-amf-context-token': token } }); }
    if (name === 'memory_propose') { requireOnly(args, new Set(['scope', 'text', 'metadata', 'infer', 'idempotencyKey'])); if (!handoff.proposeScopes.includes(String(args.scope || '')) || typeof args.text !== 'string' || !args.text.trim() || args.text.length > 4096 || (args.metadata !== undefined && !object(args.metadata)) || (args.infer !== undefined && typeof args.infer !== 'boolean') || typeof args.idempotencyKey !== 'string' || !args.idempotencyKey || args.idempotencyKey.length > 192) fail('interactive_mcp_tool_input_invalid'); return request(new URL('v2/memory/proposals', handoff.endpoint), { method: 'POST', headers: headers({ 'idempotency-key': args.idempotencyKey }), body: JSON.stringify({ scope: args.scope, text: args.text, metadata: args.metadata || {}, infer: args.infer === true }) }); }
    if (name === 'memory_proposal_status') { requireOnly(args, new Set(['id'])); return request(new URL(`v2/memory/proposals/${safeId(args.id)}`, handoff.endpoint), { method: 'GET', headers: { authorization: `Bearer ${handoff.bearer}` } }); }
    if (name === 'documents_search') { requireOnly(args, new Set(['query', 'limit'])); if (typeof args.query !== 'string' || !args.query.trim() || args.query.length > 4096) fail('interactive_mcp_tool_input_invalid'); const body = { ...args, vaultIds: handoff.readVaults, purpose: 'operator_review' }; const token = contextToken('operator_review', 'documents_search', body); return request(new URL('v2/documents/search', handoff.endpoint), { method: 'POST', headers: headers({ 'x-amf-context-token': token }), body: JSON.stringify(body) }); }
    if (name === 'document_read') { requireOnly(args, new Set(['documentId', 'revision'])); const body = { documentId: safeId(args.documentId), revision: args.revision ?? null, purpose: 'operator_review' }; if (body.revision !== null && (!Number.isInteger(body.revision) || body.revision < 1)) fail('interactive_mcp_tool_input_invalid'); const token = contextToken('operator_review', 'document_read', body); return request(new URL('v2/documents/read', handoff.endpoint), { method: 'POST', headers: headers({ 'x-amf-context-token': token }), body: JSON.stringify(body) }); }
    if (name === 'document_upsert' || name === 'document_delete') { const deleting = name === 'document_delete'; const body = writeInput(args, deleting); const id = safeId(body.document.documentId); return request(new URL(`v2/documents/${id}`, handoff.endpoint), { method: deleting ? 'DELETE' : 'PUT', headers: headers({ 'idempotency-key': body.idempotencyKey }), body: JSON.stringify(body) }); }
    if (name === 'memory_status') { requireOnly(args, new Set()); return request(new URL('v2/status', handoff.endpoint), { method: 'GET', headers: { authorization: `Bearer ${handoff.bearer}` } }); }
    fail('interactive_mcp_tool_unknown');
  }
  async function handleRpc(message) {
    const id = object(message) && Object.hasOwn(message, 'id') ? message.id : null;
    if (!object(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return rpcError(id, -32600, 'Invalid request');
    if (message.method === 'initialize') return rpcResult(id, { protocolVersion: String(message.params?.protocolVersion || '2025-03-26'), capabilities: { tools: {} }, serverInfo: { name: 'amf-interactive-mcp', version: '1' } });
    if (message.method === 'notifications/initialized') return null;
    if (message.method === 'tools/list') return rpcResult(id, { tools: handoff.tools.map(name => tools[name]) });
    if (message.method !== 'tools/call') return rpcError(id, -32601, 'Unsupported method');
    try { return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(await callTool(message.params?.name, message.params?.arguments || {})) }] }); }
    catch (error) { const code = error?.message === 'interactive_mcp_tool_input_invalid' ? -32602 : error?.message === 'interactive_mcp_tool_unknown' ? -32601 : -32000; return rpcError(id, code, code === -32602 ? 'Invalid tool arguments' : code === -32601 ? 'Unknown tool' : 'Memory request failed'); }
  }
  return Object.freeze({ handleRpc, tools: handoff.tools.map(name => tools[name]) });
}
export function createInteractiveMcpBridgeFromDirectory(directory, options = {}) { return createInteractiveMcpBridge({ ...options, handoff: loadInteractiveMcpHandoff(directory) }); }
