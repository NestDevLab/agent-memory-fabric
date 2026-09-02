const TOOL_NAMES = Object.freeze(['search', 'read', 'propose', 'proposal_status', 'status']);
function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function capsuleSearchRequest(value) { return value?.purpose === 'context_recall' && Array.isArray(value.kinds) && value.kinds.length === 1 && value.kinds[0] === 'conversation'; }

export function createCapabilityMcpV2Composition({ adapter, retainedCapabilities } = {}) {
  if (!adapter || typeof adapter.call !== 'function' || !retainedCapabilities ||
    TOOL_NAMES.some(name => typeof retainedCapabilities[name] !== 'function') ||
    Object.keys(retainedCapabilities).some(name => !TOOL_NAMES.includes(name))) throw new TypeError('capability_mcp_v2_composition_invalid');
  return freeze({
    tools: TOOL_NAMES.map(name => freeze({ name })),
    async callTool(name, arguments_) {
      if (!TOOL_NAMES.includes(name)) return freeze({ ok: false, outcome: 'invalid_request' });
      // Capsule search has an unambiguous public owner only when conversation
      // is the sole requested kind.  Defaults and mixed kinds retain the
      // canonical composite path, including context_recall requests.
      if (name === 'search' && capsuleSearchRequest(arguments_)) return adapter.call(name, arguments_);
      if (name === 'read' && arguments_?.purpose === 'context_recall') {
        let retained;
        try { retained = freeze(await retainedCapabilities[name](arguments_)); } catch { return freeze({ ok: false, outcome: 'forbidden' }); }
        // rid_* intentionally carries no public kind.  Retained canonical /
        // document ownership takes precedence; only its exact not_found may
        // probe the capsule store.  Invalid, forbidden, and unavailable
        // outcomes never fall through and cannot bypass their own boundary.
        if (retained?.outcome !== 'not_found') return retained;
        return adapter.call(name, arguments_);
      }
      try { return freeze(await retainedCapabilities[name](arguments_)); } catch { return freeze({ ok: false, outcome: name === 'proposal_status' ? 'not_found' : 'forbidden' }); }
    }
  });
}
