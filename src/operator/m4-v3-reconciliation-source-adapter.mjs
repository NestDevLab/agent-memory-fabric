import Database from 'better-sqlite3';
import fs from 'node:fs';
import pg from 'pg';

import { createM4PostgresReconciliationCollector,
  createM4SqliteReconciliationCollector } from './m4-reconciliation-collector-sources.mjs';
import { assertPrivateFileIdentity, privateFileIdentity, readPrivateBuffer } from './private-artifacts.mjs';

const SCHEMA = 'amf.m4-v3-reconciliation-source-adapter/v1';
const TIMEOUT_MINIMUM = 100;
const TIMEOUT_MAXIMUM = 60_000;
const SQLITE_MAX_BYTES = 16 * 1024 * 1024 * 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function text(value, maximum = 512) { return typeof value === 'string' && value.length > 0 && value.length <= maximum; }
function timeout(value) { return Number.isSafeInteger(value) && value >= TIMEOUT_MINIMUM && value <= TIMEOUT_MAXIMUM; }
function code(errorCode = 'm4_v3_reconciliation_source_adapter_invalid') { return errorCode; }

function validateSqlite(value, errorCode) {
  const keys = ['schema', 'archive', 'driver', 'databasePath', 'pageSize'];
  if (!exact(value, keys) || value.schema !== SCHEMA || value.archive !== 'v3' || value.driver !== 'sqlite'
    || !text(value.databasePath, 4096) || !Number.isSafeInteger(value.pageSize)
    || value.pageSize < 1 || value.pageSize > 10_000) fail(errorCode);
  return value;
}

function validatePostgres(value, errorCode) {
  const base = ['schema', 'archive', 'driver', 'host', 'port', 'database', 'user', 'password', 'sslMode',
    'pageSize', 'connectionTimeoutMillis', 'idleTimeoutMillis', 'queryTimeoutMillis', 'statementTimeoutMillis'];
  const keys = value?.sslMode === 'verify-full' ? [...base, 'caPath'] : base;
  if (!exact(value, keys) || value.schema !== SCHEMA || value.archive !== 'v3' || value.driver !== 'postgres'
    || !['disable', 'require', 'verify-full'].includes(value.sslMode)
    || ![value.host, value.database, value.user, value.password].every(item => text(item))
    || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65_535
    || !Number.isSafeInteger(value.pageSize) || value.pageSize < 1 || value.pageSize > 10_000
    || ![value.connectionTimeoutMillis, value.idleTimeoutMillis, value.queryTimeoutMillis,
      value.statementTimeoutMillis].every(timeout)
    || (value.sslMode === 'verify-full' && (!text(value.caPath, 4096)))) fail(errorCode);
  return value;
}

function validate(value, errorCode) {
  if (!plain(value) || value.archive === 'legacy-v2') fail(value?.archive === 'legacy-v2'
    ? 'm4_v3_reconciliation_source_adapter_legacy_unsupported' : errorCode);
  if (value.driver === 'sqlite') return validateSqlite(value, errorCode);
  if (value.driver === 'postgres') return validatePostgres(value, errorCode);
  fail(errorCode);
}

function once(close, errorCode) {
  let promise;
  return async () => {
    if (!promise) promise = Promise.resolve().then(close).catch(() => fail(errorCode));
    return promise;
  };
}

function sqlite(config, dependencies, errorCode) {
  const identity = privateFileIdentity(config.databasePath, {
    code: errorCode,
    minBytes: 1,
    maxBytes: SQLITE_MAX_BYTES,
  });
  let db;
  try {
    db = new dependencies.Database(`/proc/self/fd/${identity.descriptor}`, {
      readonly: true,
      fileMustExist: true,
    });
    assertPrivateFileIdentity(identity, errorCode);
  } catch (error) {
    try { db?.close?.(); } catch {}
    try { fs.closeSync(identity.descriptor); } catch {}
    if (error?.code === errorCode) throw error;
    fail(errorCode);
  }
  const collector = createM4SqliteReconciliationCollector({ db, pageSize: config.pageSize });
  return { revisionSource: collector.revisionSource, events: collector.events,
    close: once(async () => {
      try { await collector.close(); }
      finally {
        try { db.close(); }
        finally { try { fs.closeSync(identity.descriptor); } catch {} }
      }
    }, errorCode) };
}

function postgres(config, dependencies, errorCode) {
  let ca;
  if (config.sslMode === 'verify-full') ca = readPrivateBuffer(config.caPath, { code: errorCode, minBytes: 1 }).toString('utf8');
  const ssl = config.sslMode === 'disable' ? false
    : config.sslMode === 'require' ? { rejectUnauthorized: false } : { rejectUnauthorized: true, ca };
  let pool;
  try {
    pool = new dependencies.Pool({ host: config.host, port: config.port, database: config.database,
      user: config.user, password: config.password, ssl, max: 1,
      connectionTimeoutMillis: config.connectionTimeoutMillis, idleTimeoutMillis: config.idleTimeoutMillis,
      query_timeout: config.queryTimeoutMillis, statement_timeout: config.statementTimeoutMillis });
  } catch { fail(errorCode); }
  const collector = createM4PostgresReconciliationCollector({ acquireClient: () => pool.connect(), pageSize: config.pageSize });
  return { revisionSource: collector.revisionSource, events: collector.events,
    close: once(async () => { try { await collector.close(); } finally { await pool.end(); } }, errorCode) };
}

export function createM4V3ReconciliationSource(input = {}, rawDependencies = {}) {
  const errorCode = code(rawDependencies.errorCode);
  if (!exact(input, ['archive', 'config', 'sourceConfig']) || input.archive === 'legacy-v2') {
    fail(input?.archive === 'legacy-v2' ? 'm4_v3_reconciliation_source_adapter_legacy_unsupported' : errorCode);
  }
  if (input.archive !== 'v3' || !plain(input.config)) fail(errorCode);
  const dependencies = { Database: rawDependencies.Database ?? Database, Pool: rawDependencies.Pool ?? pg.Pool };
  if (typeof dependencies.Database !== 'function' || typeof dependencies.Pool !== 'function') fail(errorCode);
  const config = validate(input.sourceConfig, errorCode);
  return config.driver === 'sqlite' ? sqlite(config, dependencies, errorCode) : postgres(config, dependencies, errorCode);
}

export function createM4V3ReconciliationSourceFactory(rawDependencies = {}) {
  return input => createM4V3ReconciliationSource(input, rawDependencies);
}
