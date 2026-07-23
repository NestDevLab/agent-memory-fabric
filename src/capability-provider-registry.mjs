export const CAPABILITY_PROVIDER_REGISTRY_CAPABILITIES = Object.freeze([
  'search',
  'read',
  'propose',
  'proposal_status',
  'status'
]);

const CAPABILITIES = new Set(CAPABILITY_PROVIDER_REGISTRY_CAPABILITIES);
const PROVIDER_ID = /^[a-z][a-z0-9_-]{2,63}$/;

function registryError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function configInvalid() {
  throw registryError('capability_provider_registry_config_invalid');
}

function providerCallFailed() {
  throw registryError('capability_provider_registry_call_failed');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function hasOnlyKeys(value, keys) {
  return Reflect.ownKeys(value).every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string' && keys.includes(key) && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function cleanArray(value) {
  return Array.isArray(value) && Reflect.ownKeys(value).every(key => {
    if (key === 'length') return true;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string' && /^(?:0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length
      && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function normalizeEnabledCapabilities(value) {
  if (!cleanArray(value) || value.length < 1 || value.length > CAPABILITY_PROVIDER_REGISTRY_CAPABILITIES.length) configInvalid();
  const seen = new Set();
  for (const capability of value) {
    if (typeof capability !== 'string' || !CAPABILITIES.has(capability) || seen.has(capability)) configInvalid();
    seen.add(capability);
  }
  return [...value];
}

function normalizeAssignments(value, enabled) {
  if (!cleanArray(value) || value.length > 16) configInvalid();
  const assignments = new Map();
  for (const assignment of value) {
    if (!isPlainObject(assignment) || !hasOnlyKeys(assignment, ['capability', 'providerId'])
      || typeof assignment.capability !== 'string' || !CAPABILITIES.has(assignment.capability)
      || typeof assignment.providerId !== 'string' || !PROVIDER_ID.test(assignment.providerId)
      || !enabled.has(assignment.capability) || assignments.has(assignment.capability)) configInvalid();
    assignments.set(assignment.capability, assignment.providerId);
  }
  if (assignments.size !== enabled.size) configInvalid();
  return assignments;
}

function normalizeProviders(value) {
  if (!cleanArray(value) || value.length > 16) configInvalid();
  const providers = new Map();
  for (const provider of value) {
    if (!isPlainObject(provider) || !hasOnlyKeys(provider, ['providerId', 'handle'])
      || typeof provider.providerId !== 'string' || !PROVIDER_ID.test(provider.providerId)
      || typeof provider.handle !== 'function' || providers.has(provider.providerId)) configInvalid();
    providers.set(provider.providerId, provider.handle);
  }
  return providers;
}

function registryUnavailable() {
  throw registryError('capability_provider_registry_unavailable');
}

/**
 * Create a deterministic, provider-neutral internal operator router.
 *
 * The input is deliberately a small operator-only configuration object. Provider
 * identities never appear in the returned snapshots, routing objects, or errors.
 * Provider return values are opaque to this module and MUST be validated by the
 * capability MCP public dispatcher before they are released to a caller.
 */
export function createCapabilityProviderRegistry(config) {
  if (!isPlainObject(config) || !hasOnlyKeys(config, ['enabledCapabilities', 'providerAssignments', 'providers'])) configInvalid();

  const enabledCapabilities = normalizeEnabledCapabilities(config.enabledCapabilities);
  const enabled = new Set(enabledCapabilities);
  const assignments = normalizeAssignments(config.providerAssignments, enabled);
  const providers = normalizeProviders(config.providers);
  const routes = new Map();

  for (const capability of enabledCapabilities) {
    const handle = providers.get(assignments.get(capability));
    if (typeof handle !== 'function') configInvalid();
    routes.set(capability, handle);
  }

  const snapshot = deepFreeze({
    enabledCapabilities: [...enabledCapabilities],
    capabilities: enabledCapabilities.map(name => ({ name, state: 'ready' }))
  });

  const invoke = async (capability, request) => {
    const handle = routes.get(capability);
    if (!handle) registryUnavailable();
    try {
      return await handle(request, Object.freeze({ capability }));
    } catch {
      providerCallFailed();
    }
  };

  const lookup = capability => {
    if (typeof capability !== 'string' || !CAPABILITIES.has(capability) || !routes.has(capability)) registryUnavailable();
    return Object.freeze({ capability, call: request => invoke(capability, request) });
  };

  return Object.freeze({
    lookup,
    call: invoke,
    snapshot: () => snapshot
  });
}
