import assert from 'node:assert/strict';
import test from 'node:test';
import { createCapabilityOpaqueReferenceStoreFromEnv } from '../src/capability-opaque-reference-store-env.mjs';

class FakeSqlite { constructor(options) { this.options = options; } }
class FakePostgres { constructor(options) { this.options = options; this.readyCalls = 0; } async ready() { this.readyCalls += 1; } }
const constructors = { sqlite: FakeSqlite, postgres: FakePostgres };
const create = env => createCapabilityOpaqueReferenceStoreFromEnv({ env, constructors });

test('selects only explicit durable SQLite and Postgres configurations', async () => {
  const sqlite = create({ AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/var/lib/amf/opaque.sqlite' });
  assert.ok(sqlite instanceof FakeSqlite); assert.deepEqual(sqlite.options, { filename: '/var/lib/amf/opaque.sqlite' });
  const postgres = create({ AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: 'postgresql://user:password@example.test/amf' });
  assert.ok(postgres instanceof FakePostgres); assert.deepEqual(postgres.options.ssl, { rejectUnauthorized: true }); assert.equal(postgres.options.connectionString.startsWith('postgresql:'), true); await postgres.ready(); assert.equal(postgres.readyCalls, 1);
});

test('selects explicit TLS modes and reads an optional verify-full CA without exposing it', () => {
  const url = 'postgresql://user:password@example.test/amf';
  assert.deepEqual(create({ AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: url, AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE: 'disable' }).options.ssl, false);
  assert.deepEqual(create({ AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: url, AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE: 'require' }).options.ssl, { rejectUnauthorized: false });
  const calls = []; const postgres = createCapabilityOpaqueReferenceStoreFromEnv({ env: { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: url, AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH: '/etc/amf/ca.pem' }, constructors, readFile(file, encoding) { calls.push([file, encoding]); return 'synthetic certificate'; } });
  assert.deepEqual(calls, [['/etc/amf/ca.pem', 'utf8']]); assert.deepEqual(postgres.options.ssl, { rejectUnauthorized: true, ca: 'synthetic certificate' });
});

test('rejects missing, ambiguous, fallback, path, URL, SSL, and unknown relevant configuration without leaks', () => {
  const privateValue = 'postgresql://user:private-secret@example.test/amf';
  const invalid = [
    {}, { AMF_CAPABILITY_OPAQUE_STORE: 'memory' }, { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite' },
    { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: ':memory:' }, { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: 'relative.sqlite' },
    { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a\0b' }, { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a.sqlite', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: privateValue }, { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a.sqlite', AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE: 'verify-full' },
    { AMF_CAPABILITY_OPAQUE_STORE: 'postgres' }, { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: 'https://example.test/amf' }, { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: `${privateValue}?sslmode=require` }, { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: `${privateValue}?sslcert=/tmp/cert.pem` }, { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: privateValue, AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE: 'verify-ca' }, { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: privateValue, AMF_CAPABILITY_OPAQUE_POSTGRES_SSL_MODE: 'require', AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH: '/etc/amf/ca.pem' },
    { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: privateValue, AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a.sqlite' }, { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a.sqlite', AMF_CAPABILITY_OPAQUE_UNKNOWN: 'x' }
  ];
  for (const env of invalid) assert.throws(() => create(env), error => error.code === 'capability_opaque_reference_env_invalid' && !error.message.includes('private-secret'));
});

test('injected constructors and hostile configuration fail closed without a production default', () => {
  let called = false; class ThrowingSqlite { constructor() { called = true; throw Error('private'); } }
  assert.throws(() => createCapabilityOpaqueReferenceStoreFromEnv({ env: { AMF_CAPABILITY_OPAQUE_STORE: 'sqlite', AMF_CAPABILITY_OPAQUE_SQLITE_PATH: '/tmp/a.sqlite' }, constructors: { sqlite: ThrowingSqlite, postgres: FakePostgres } }), { code: 'capability_opaque_reference_env_invalid' }); assert.equal(called, true);
  const hostile = {}; Object.defineProperty(hostile, 'AMF_CAPABILITY_OPAQUE_STORE', { enumerable: true, get() { throw Error('private'); } });
  assert.throws(() => create(hostile), { code: 'capability_opaque_reference_env_invalid' });
  assert.throws(() => createCapabilityOpaqueReferenceStoreFromEnv({ env: { AMF_CAPABILITY_OPAQUE_STORE: 'postgres', AMF_CAPABILITY_OPAQUE_POSTGRES_URL: 'postgresql://user:password@example.test/amf', AMF_CAPABILITY_OPAQUE_POSTGRES_CA_PATH: '/etc/amf/ca.pem' }, constructors, readFile() { throw Error('private-ca-content'); } }), error => error.code === 'capability_opaque_reference_env_invalid' && !error.message.includes('private-ca-content'));
});
