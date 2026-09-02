function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
const INVALID = freeze({ ok: false, outcome: 'invalid_request' });
const FORBIDDEN = freeze({ ok: false, outcome: 'forbidden' });
const NOT_FOUND = freeze({ ok: false, outcome: 'not_found' });

export function createCapabilityProviderV2Adapter({ authorizationBridge, operations } = {}) {
  if (!authorizationBridge || typeof authorizationBridge.authorize !== 'function' || !operations || typeof operations.search !== 'function' || typeof operations.read !== 'function') throw new TypeError('capability_provider_v2_adapter_invalid');
  return freeze({
    async call(capability, arguments_) {
      if (!['search', 'read'].includes(capability)) return INVALID;
      let authorization;
      try { authorization = await authorizationBridge.authorize({ capability, arguments: arguments_ }); } catch { return INVALID; }
      if (!authorization?.grant) return capability === 'read' || authorization?.normalized?.delivery === 'notice' ? NOT_FOUND : FORBIDDEN;
      try {
        const result = await operations[capability](authorization.normalized, { grant: authorization.grant });
        return freeze(result);
      } catch (caught) {
        if (capability === 'read' || authorization.normalized.delivery === 'notice' || caught?.code === 'fabric_capability_provider_v2_not_found') return NOT_FOUND;
        if (caught?.code === 'fabric_capability_provider_v2_invalid' || caught?.code === 'session_context_cursor_invalid') return INVALID;
        return FORBIDDEN;
      }
    }
  });
}
