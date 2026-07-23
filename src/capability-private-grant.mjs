const SNAPSHOTS = new WeakSet();
const INVALID = Symbol('invalid_private_grant');
const LIMITS = Object.freeze({ depth: 8, keys: 128, arrayItems: 128, stringLength: 4096, bytes: 16384 });

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function scalar(value) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.length <= LIMITS.stringLength ? value : INVALID;
  if (typeof value === 'number') return Number.isFinite(value) ? value : INVALID;
  return INVALID;
}

function capture(value, state, visiting, depth) {
  const primitive = scalar(value);
  if (primitive !== INVALID) return primitive;
  if (!value || typeof value !== 'object' || depth >= LIMITS.depth || visiting.has(value)) return INVALID;
  visiting.add(value);
  try {
    if (Array.isArray(value)) return captureArray(value, state, visiting, depth);
    if (Object.getPrototypeOf(value) !== Object.prototype) return INVALID;
    return captureObject(value, state, visiting, depth);
  } finally {
    visiting.delete(value);
  }
}

function descriptorsFor(value) {
  const keys = Reflect.ownKeys(value);
  const descriptors = new Map();
  for (const key of keys) descriptors.set(key, Object.getOwnPropertyDescriptor(value, key));
  return { keys, descriptors };
}

function captureArray(value, state, visiting, depth) {
  const { keys, descriptors } = descriptorsFor(value);
  const length = descriptors.get('length');
  if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value) || length.value < 0 || length.value > LIMITS.arrayItems
    || keys.length !== length.value + 1 || (state.keys += length.value) > LIMITS.keys) return INVALID;
  const result = [];
  for (let index = 0; index < length.value; index += 1) {
    const key = String(index);
    const descriptor = descriptors.get(key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return INVALID;
    const copied = capture(descriptor.value, state, visiting, depth + 1);
    if (copied === INVALID) return INVALID;
    result.push(copied);
  }
  for (const key of keys) if (key !== 'length' && (!/^0$|^[1-9][0-9]*$/.test(key) || Number(key) >= length.value)) return INVALID;
  return result;
}

function captureObject(value, state, visiting, depth) {
  const { keys, descriptors } = descriptorsFor(value);
  if (keys.some(key => typeof key !== 'string') || (state.keys += keys.length) > LIMITS.keys) return INVALID;
  const result = {};
  for (const key of [...keys].sort()) {
    const descriptor = descriptors.get(key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return INVALID;
    const copied = capture(descriptor.value, state, visiting, depth + 1);
    if (copied === INVALID) return INVALID;
    Object.defineProperty(result, key, { value: copied, enumerable: true, writable: true, configurable: true });
  }
  return result;
}

/** Returns a private, inert snapshot or undefined; the trusted brand is module-private. */
export function snapshotPrivateGrant(value) {
  if (value && typeof value === 'object' && SNAPSHOTS.has(value)) return value;
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return undefined;
    const copied = capture(value, { keys: 0 }, new WeakSet(), 0);
    if (copied === INVALID) return undefined;
    const canonical = JSON.stringify(copied);
    if (Buffer.byteLength(canonical, 'utf8') > LIMITS.bytes) return undefined;
    const frozen = deepFreeze(copied);
    SNAPSHOTS.add(frozen);
    return frozen;
  } catch {
    return undefined;
  }
}
