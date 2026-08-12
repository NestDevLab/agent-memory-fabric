import crypto from 'node:crypto';

import { provisionScopedConsumer } from './recall-consumer-provisioning.mjs';
import { INTERACTIVE_MCP_TOOLS } from './interactive-mcp-contract.mjs';

export { INTERACTIVE_MCP_TOOLS } from './interactive-mcp-contract.mjs';

export const INTERACTIVE_MCP_HANDOFF_SCHEMA = 'amf.interactive-mcp-handoff/v2';
export const INTERACTIVE_MCP_PERMISSIONS = Object.freeze([
  'memory:search', 'memory:read', 'memory:propose', 'memory:status',
  'documents:search', 'documents:read', 'documents:write',
  'purpose:conversation_recall', 'purpose:memory_curation', 'purpose:operator_review'
]);
export const INTERACTIVE_MCP_PURPOSES = Object.freeze(['conversation_recall', 'memory_curation', 'operator_review']);
const TOOL_PERMISSIONS = Object.freeze({
  memory_search: ['memory:search', 'purpose:conversation_recall'],
  memory_read: ['memory:read', 'purpose:conversation_recall'],
  memory_propose: ['memory:propose', 'purpose:memory_curation'],
  memory_proposal_status: ['memory:read', 'purpose:memory_curation'],
  documents_search: ['documents:search', 'purpose:operator_review'],
  document_read: ['documents:read', 'purpose:operator_review'],
  document_upsert: ['documents:write'], document_delete: ['documents:write'], memory_status: ['memory:status']
});

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const SAFE_SCOPE = /^(?:agent|person|relationship|room|domain|shared):[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const SAFE_VAULT = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const OPTION_KEYS = new Set([
  'runtime', 'authRegistryPath', 'policyPath', 'contextKeyRingPath', 'handoffPath', 'backupRoot',
  'backendUserId', 'serviceOwnerUid', 'policyRevision', 'endpoint',
  'readScopes', 'proposeScopes', 'readVaults', 'writeVaults', 'tools',
  'dryRun', 'clock', 'randomBytes', 'faultAt', 'migrate'
]);

function fail(code) { throw new Error(code); }

function normalizedGrant(value, pattern, code, { wildcard = false } = {}) {
  if (!Array.isArray(value) || !value.length || value.some(item => typeof item !== 'string' || item !== item.trim()
    || (item !== '*' && !pattern.test(item)) || (item === '*' && !wildcard)) || new Set(value).size !== value.length) fail(code);
  if (value.includes('*') && value.length !== 1) fail(code);
  return [...value].sort();
}

function endpoint(value) {
  if (typeof value !== 'string') fail('interactive_mcp_endpoint_invalid');
  let parsed;
  try { parsed = new URL(value); } catch { fail('interactive_mcp_endpoint_invalid'); }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password
    || parsed.hash || parsed.search || parsed.pathname !== '/') fail('interactive_mcp_endpoint_invalid');
  return parsed.toString();
}

export function interactiveMcpPermissions(tools) {
  return [...new Set(tools.flatMap(tool => TOOL_PERMISSIONS[tool] || []))].sort();
}

export function interactiveMcpPurposes(tools) {
  return INTERACTIVE_MCP_PURPOSES.filter(purpose => interactiveMcpPermissions(tools).includes(`purpose:${purpose}`));
}

function normalizedTools(value) {
  if (!Array.isArray(value) || value.length !== INTERACTIVE_MCP_TOOLS.length || value.some(tool => !INTERACTIVE_MCP_TOOLS.includes(tool)) || new Set(value).size !== value.length) {
    fail('interactive_mcp_tool_invalid');
  }
  return INTERACTIVE_MCP_TOOLS;
}

function profileFor(runtime, operationGrants, tools, policyRevision, targetEndpoint) {
  if (!['codex', 'claude'].includes(runtime)) fail('interactive_mcp_runtime_invalid');
  const digest = crypto.createHash('sha256').update(`amf-interactive-mcp:${runtime}`, 'utf8').digest('hex');
  const registeredScopes = [...new Set([...operationGrants.readScopes.filter(scope => scope !== '*'), ...operationGrants.proposeScopes])].sort();
  const registeredVaults = [...new Set([...operationGrants.readVaults.filter(vaultId => vaultId !== '*'), ...operationGrants.writeVaults])].sort();
  return {
    actor: `client:mcp:${runtime}`,
    contextKeyVersion: `ctx-mcp-${runtime}-v1`, runtime, profile: 'interactive-mcp',
    sessionDescriptor: { conversationKind: 'session', contextTags: { conversation: [`hmac-sha256:amf-interactive-mcp-v1:${digest}`] } },
    permissions: interactiveMcpPermissions(tools),
    // Legacy fields are deliberately the narrow write grants: an old server can
    // never inherit a read wildcard as a write permission during a rollback.
    scopes: operationGrants.proposeScopes, allowedVaults: operationGrants.writeVaults,
    registeredScopes, registeredVaults, operationGrants, handoffOperationGrants: true,
    sessionOwnerActors: [], mode: 'scoped', purpose: 'operator_review', purposes: interactiveMcpPurposes(tools),
    tools, handoffSchema: INTERACTIVE_MCP_HANDOFF_SCHEMA,
    backupSlug: `interactive-mcp-${runtime}`, policyRevision, endpoint: targetEndpoint,
    requireRegisteredScopes: true, requireRegisteredVaults: true, migrate: false
  };
}

export function interactiveMcpProfile(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key => !OPTION_KEYS.has(key))) {
    fail('interactive_mcp_option_invalid');
  }
  if (typeof options.policyRevision !== 'string' || !SAFE_ID.test(options.policyRevision)) fail('interactive_mcp_policy_revision_invalid');
  const operationGrants = Object.freeze({
    readScopes: normalizedGrant(options.readScopes, SAFE_SCOPE, 'interactive_mcp_read_scope_invalid', { wildcard: true }),
    proposeScopes: normalizedGrant(options.proposeScopes, SAFE_SCOPE, 'interactive_mcp_propose_scope_invalid'),
    readVaults: normalizedGrant(options.readVaults, SAFE_VAULT, 'interactive_mcp_read_vault_invalid', { wildcard: true }),
    writeVaults: normalizedGrant(options.writeVaults, SAFE_VAULT, 'interactive_mcp_write_vault_invalid')
  });
  const tools = normalizedTools(options.tools);
  const profile = profileFor(options.runtime, operationGrants, tools, options.policyRevision, endpoint(options.endpoint));
  if (options.migrate !== undefined && typeof options.migrate !== 'boolean') fail('interactive_mcp_option_invalid');
  return { ...profile, migrate: options.migrate === true };
}

export function provisionInteractiveMcp(options = {}) {
  const profile = interactiveMcpProfile(options);
  return provisionScopedConsumer(options, profile);
}
