import path from 'node:path';
import fs from 'node:fs';
import { PostgresOpaqueReferenceStore, SqliteOpaqueReferenceStore } from './capability-opaque-reference-store.mjs';

const PREFIX = 'AMF_CAPABILITY_OPAQUE_';
const KEYS = new Set(['AMF_CAPABILITY_OPAQUE_STORE', 'AMF_CAPABILITY_OPAQUE_SQLITE_PATH', 'AMF_CAPABILITY_OPAQUE_POSTGRES_URL', 'AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE', 'AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH']);
const SSL_MODES = new Set(['disable', 'require', 'verify-full']);

function fail() { const error = new Error('capability_opaque_reference_env_invalid'); error.code = error.message; throw error; }
function record(value, keys) {
  try { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null; const own = Reflect.ownKeys(value); if (own.some(key => typeof key !== 'string' || !keys.includes(key))) return null; const out = {}; for (const key of own) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null; Object.defineProperty(out, key, { value: descriptor.value, enumerable: true }); } return out; } catch { return null; }
}
function environment(value) {
  try { if (!value || typeof value !== 'object') return null; const out = {}; for (const key of Reflect.ownKeys(value)) { if (typeof key !== 'string' || !key.startsWith(PREFIX)) continue; if (!KEYS.has(key)) return null; const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') return null; out[key] = descriptor.value; } return out; } catch { return null; }
}
function postgresUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 8192 || /[\0\r\n]/.test(value)) return null;
  try { const parsed = new URL(value); if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || !parsed.hostname || !parsed.pathname || parsed.pathname === '/' || [...parsed.searchParams.keys()].some(key => key.toLowerCase().startsWith('ssl'))) return null; return parsed.toString(); } catch { return null; }
}

/** Select a durable opaque-reference store from explicit environment configuration. */
export function createCapabilityOpaqueReferenceStoreFromEnv(config = {}) {
  const input = record(config, ['env', 'constructors', 'readFile']); if (!input) fail();
  const env = environment(input.env === undefined ? process.env : input.env); const constructors = input.constructors === undefined ? { sqlite: SqliteOpaqueReferenceStore, postgres: PostgresOpaqueReferenceStore } : record(input.constructors, ['sqlite', 'postgres']);
  const readFile = input.readFile === undefined ? fs.readFileSync : input.readFile;
  if (!env || !constructors || typeof constructors.sqlite !== 'function' || typeof constructors.postgres !== 'function' || typeof readFile !== 'function') fail();
  const backend = env.AMF_CAPABILITY_OPAQUE_STORE;
  if (backend === 'sqlite') {
    const filename = env.AMF_CAPABILITY_OPAQUE_SQLITE_PATH;
    if (typeof filename !== 'string' || filename.length < 1 || filename.length > 4096 || filename.includes('\0') || filename === ':memory:' || !path.isAbsolute(filename)
      || ['AMF_CAPABILITY_OPAQUE_POSTGRES_URL', 'AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE', 'AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH'].some(key => Object.hasOwn(env, key))) fail();
    try { return new constructors.sqlite({ filename }); } catch { fail(); }
  }
  if (backend === 'postgres') {
    const connectionString = postgresUrl(env.AMF_CAPABILITY_OPAQUE_POSTGRES_URL);
    if (!connectionString || Object.hasOwn(env, 'AMF_CAPABILITY_OPAQUE_SQLITE_PATH')) fail();
    const mode = env.AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE === undefined ? 'verify-full' : env.AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE;
    const caPath = env.AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH;
    if (!SSL_MODES.has(mode) || (caPath !== undefined && mode !== 'verify-full')) fail();
    let ca;
    if (caPath !== undefined) {
      if (typeof caPath !== 'string' || caPath.length < 1 || caPath.length > 4096 || caPath.includes('\0') || !path.isAbsolute(caPath)) fail();
      try { ca = readFile(caPath, 'utf8'); } catch { fail(); }
      if (typeof ca !== 'string' || ca.length < 1 || ca.length > 1048576 || ca.includes('\0')) fail();
    }
    const ssl = mode === 'disable' ? false : Object.freeze({ rejectUnauthorized: mode === 'verify-full', ...(ca === undefined ? {} : { ca }) });
    try { return new constructors.postgres({ connectionString, ssl }); } catch { fail(); }
  }
  fail();
}
