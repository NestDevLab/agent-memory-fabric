export const INTERACTIVE_MCP_TOOLS = Object.freeze([
  'memory_search', 'memory_read', 'memory_propose', 'memory_proposal_status',
  'documents_search', 'document_read', 'document_upsert', 'document_delete', 'memory_status'
]);

export const INTERACTIVE_MCP_ACTORS = Object.freeze(['client:mcp:codex', 'client:mcp:claude']);

export function isInteractiveMcpActor(actor) {
  return INTERACTIVE_MCP_ACTORS.includes(actor);
}

export function isMcpClientActor(actor) {
  return typeof actor === 'string' && actor.startsWith('client:mcp:');
}

export function hasExactInteractiveMcpTools(tools) {
  return Array.isArray(tools) && tools.length === INTERACTIVE_MCP_TOOLS.length
    && tools.every(tool => INTERACTIVE_MCP_TOOLS.includes(tool))
    && new Set(tools).size === INTERACTIVE_MCP_TOOLS.length;
}
