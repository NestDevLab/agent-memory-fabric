import { CAPABILITY_MCP_TOOL_DEFINITIONS } from './capability-mcp-runtime.mjs';

export const CAPABILITY_MCP_PROTOCOL_VERSION = '2024-11-05';
const TOOL_NAMES = new Set(['search', 'read', 'propose', 'proposal_status', 'status']);
const MAX_BYTES = 131072;

function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const item of Object.values(value)) freeze(item); Object.freeze(value); } return value; }
function plain(value) { try { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; } catch { return false; } }
function record(value, allowed, required = []) {
  try { if (!plain(value)) return null; const keys = Reflect.ownKeys(value); if (keys.some(key => typeof key !== 'string' || !allowed.includes(key)) || required.some(key => !keys.includes(key))) return null; const out = {}; for (const key of keys) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null; Object.defineProperty(out, key, { value: descriptor.value, enumerable: true }); } return out; } catch { return null; }
}
function boundedJson(value) { try { const text = JSON.stringify(value); return typeof text === 'string' && Buffer.byteLength(text, 'utf8') <= MAX_BYTES ? text : null; } catch { return null; } }
function boundedValue(value, state = { keys: 0 }, seen = new WeakSet(), depth = 0) {
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return true;
  if (typeof value === 'string') return value.length <= 4096;
  try {
    if (!value || typeof value !== 'object' || depth >= 6 || seen.has(value)) return false; seen.add(value);
    const keys = Reflect.ownKeys(value); if (keys.some(key => typeof key !== 'string') || (state.keys += keys.length) > 64) return false;
    if (Array.isArray(value)) { const length = Object.getOwnPropertyDescriptor(value, 'length')?.value; if (!Number.isSafeInteger(length) || length > 32 || keys.length !== length + 1) return false; for (let index = 0; index < length; index += 1) { const descriptor = Object.getOwnPropertyDescriptor(value, String(index)); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') || !boundedValue(descriptor.value, state, seen, depth + 1)) return false; } return true; }
    if (!plain(value)) return false; for (const key of keys) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value') || !boundedValue(descriptor.value, state, seen, depth + 1)) return false; } return true;
  } catch { return false; } finally { try { seen.delete(value); } catch {} }
}
function response(id, result) { return freeze({ jsonrpc: '2.0', id, result }); }
function failure(id, code, message) { return freeze({ jsonrpc: '2.0', id, error: freeze({ code, message }) }); }
function validId(value) { return value === null || (typeof value === 'string' && value.length <= 64) || (Number.isSafeInteger(value) && Math.abs(value) <= 2147483647); }
function rpc(value) {
  const row = record(value, ['jsonrpc', 'id', 'method', 'params'], ['jsonrpc', 'method']);
  if (!row || row.jsonrpc !== '2.0' || typeof row.method !== 'string' || row.method.length < 1 || row.method.length > 64 || (Object.hasOwn(row, 'id') && !validId(row.id)) || !boundedJson(row)) return null;
  return row;
}
function rpcResponse(value) {
  const row = record(value, ['jsonrpc', 'id', 'result', 'error'], ['jsonrpc', 'id']);
  if (!row || row.jsonrpc !== '2.0' || !validId(row.id) || (Object.hasOwn(row, 'result') === Object.hasOwn(row, 'error')) || !boundedJson(row)) return null;
  if (Object.hasOwn(row, 'error')) { const issue = record(row.error, ['code', 'message'], ['code', 'message']); if (!issue || !Number.isSafeInteger(issue.code) || typeof issue.message !== 'string' || issue.message.length > 64 || /[\r\n\0]/.test(issue.message)) return null; }
  return row;
}
function toolParams(value) { const row = record(value, ['name', 'arguments'], ['name', 'arguments']); return row && typeof row.name === 'string' && row.name.length > 0 && row.name.length <= 64 && plain(row.arguments) ? row : null; }
function emptyParams(value) { return value === undefined || (record(value, []) !== null); }
function toolResult(value) { const text = boundedJson(value); return text === null ? null : freeze({ content: freeze([freeze({ type: 'text', text })]), isError: value?.ok === false }); }

/** A small transport-neutral JSON-RPC/MCP kernel over a capability MCP runtime. */
export function createCapabilityMcpJsonRpc(config) {
  const input = record(config, ['runtime'], ['runtime']); const runtime = input?.runtime;
  if (!runtime || typeof runtime.listTools !== 'function' || typeof runtime.callTool !== 'function') throw Object.assign(new Error('capability_mcp_jsonrpc_config_invalid'), { code: 'capability_mcp_jsonrpc_config_invalid' });
  let tools;
  try { tools = runtime.listTools(); } catch { tools = null; }
  if (!Array.isArray(tools) || tools.length !== 5 || new Set(tools.map(item => item?.name)).size !== 5 || tools.some(item => !TOOL_NAMES.has(item?.name))) throw Object.assign(new Error('capability_mcp_jsonrpc_config_invalid'), { code: 'capability_mcp_jsonrpc_config_invalid' });
  const advertised = CAPABILITY_MCP_TOOL_DEFINITIONS;

  const handle = async raw => {
    const request = rpc(raw); const id = request && Object.hasOwn(request, 'id') ? request.id : null;
    if (!request) return failure(null, -32600, 'Invalid request');
    const notification = !Object.hasOwn(request, 'id');
    if (request.method === 'notifications/initialized') return emptyParams(request.params) ? null : (notification ? null : failure(id, -32602, 'Invalid params'));
    if (request.method === 'initialize') {
      const params = record(request.params, ['protocolVersion', 'capabilities', 'clientInfo'], ['protocolVersion']);
      const clientInfo = params && Object.hasOwn(params, 'clientInfo')
        ? record(params.clientInfo, ['name', 'version'], ['name', 'version']) : null;
      if (!params || params.protocolVersion !== CAPABILITY_MCP_PROTOCOL_VERSION
        || (Object.hasOwn(params, 'capabilities') && (!plain(params.capabilities) || !boundedValue(params.capabilities)))
        || (Object.hasOwn(params, 'clientInfo') && (!clientInfo
          || typeof clientInfo.name !== 'string' || clientInfo.name.length < 1 || clientInfo.name.length > 128
          || typeof clientInfo.version !== 'string' || clientInfo.version.length < 1 || clientInfo.version.length > 128))) return notification ? null : failure(id, -32602, 'Invalid params');
      return notification ? null : response(id, freeze({ protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION, capabilities: freeze({ tools: freeze({}) }), serverInfo: freeze({ name: 'amf-capability-mcp', version: '1' }) }));
    }
    if (request.method === 'tools/list') return emptyParams(request.params) ? (notification ? null : response(id, freeze({ tools: advertised }))) : (notification ? null : failure(id, -32602, 'Invalid params'));
    if (request.method !== 'tools/call') return notification ? null : failure(id, -32601, 'Method not found');
    const params = toolParams(request.params); if (!params) return notification ? null : failure(id, -32602, 'Invalid params');
    try { const result = toolResult(await runtime.callTool(params.name, params.arguments)); return result ? (notification ? null : response(id, result)) : (notification ? null : failure(id, -32000, 'Internal error')); } catch { return notification ? null : failure(id, -32000, 'Internal error'); }
  };
  return freeze({ handle, tools: () => advertised });
}

export function encodeCapabilityMcpStreamableHttp(value) {
  if (value !== null && !rpcResponse(value)) throw Object.assign(new Error('capability_mcp_jsonrpc_encode_invalid'), { code: 'capability_mcp_jsonrpc_encode_invalid' });
  const body = value === null ? '' : boundedJson(value); if (body === null) throw Object.assign(new Error('capability_mcp_jsonrpc_encode_invalid'), { code: 'capability_mcp_jsonrpc_encode_invalid' });
  return freeze({ status: value === null ? 202 : 200,
    headers: freeze(value === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), body });
}

export function encodeCapabilityMcpSse(value) {
  if (value === null || !rpcResponse(value)) throw Object.assign(new Error('capability_mcp_jsonrpc_encode_invalid'), { code: 'capability_mcp_jsonrpc_encode_invalid' });
  const data = boundedJson(value); if (data === null) throw Object.assign(new Error('capability_mcp_jsonrpc_encode_invalid'), { code: 'capability_mcp_jsonrpc_encode_invalid' });
  return freeze({ event: 'message', data, body: `event: message\ndata: ${data}\n\n` });
}
