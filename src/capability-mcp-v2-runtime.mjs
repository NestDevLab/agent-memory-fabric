function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }

export function createCapabilityMcpV2Runtime({ composition } = {}) {
  if (!composition || !Array.isArray(composition.tools) || typeof composition.callTool !== 'function' ||
    composition.tools.map(tool => tool?.name).join('\0') !== 'search\0read\0propose\0proposal_status\0status') throw new TypeError('capability_mcp_v2_runtime_invalid');
  let closed = false;
  const unavailable = freeze({ ok: false, outcome: 'unavailable', capabilities: composition.tools.map(tool => ({ name: tool.name, state: 'unavailable' })) });
  return freeze({
    listTools() { return closed ? [] : composition.tools; },
    async callTool(name, arguments_) { return closed ? unavailable : composition.callTool(name, arguments_); },
    close() { closed = true; }
  });
}
