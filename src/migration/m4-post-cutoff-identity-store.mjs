import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId, deriveM4V3SourceInstanceIdFromLegacySession } from './m4-v2-conversation-projector.mjs';

const STATE_SCHEMA = 'amf.m4-post-cutoff-identity-store/v1';
const ID = /^[a-z][a-z0-9-]{2,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const LEGACY_EVENT = /^evt_[a-f0-9]{64}$/;
const LEGACY_SESSION = /^ses_[a-f0-9]{64}$/;
const EVENT = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const CONVERSATION = /^ccon_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE = /^src_[a-z0-9][a-z0-9_-]{7,127}$/;
const SOURCE_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}:[a-f0-9]{64}$/;
const MAX_RECORDS = 10_000;
const MAX_BYTES = 32 * 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function uid() { return typeof process.geteuid === 'function' ? process.geteuid() : typeof process.getuid === 'function' ? process.getuid() : null; }
function owner(stat, code) { if (uid() !== null && stat.uid !== uid()) fail(code); }
function directory(stat) { if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) fail('m4_post_cutoff_identity_store_unsafe'); owner(stat, 'm4_post_cutoff_identity_store_unsafe'); }
function file(stat) { if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) fail('m4_post_cutoff_identity_store_unsafe'); owner(stat, 'm4_post_cutoff_identity_store_unsafe'); }
function checkpointDigest(value, code) { if (typeof value !== 'string' || !DIGEST.test(value)) fail(code); return value; }
function timestamp(value, code) { if (typeof value !== 'string' || !isConversationEventUtcTimestamp(value)) fail(code); return value; }
function sourceTags(value, code) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64 || value.some(tag => typeof tag !== 'string' || !SOURCE_TAG.test(tag))) fail(code);
  const copy = [...value]; if (new Set(copy).size !== copy.length || copy.some((tag, index) => index > 0 && copy[index - 1] >= tag)) fail(code); return copy;
}
function namespace(value, code) {
  if (!exact(value, ['runId', 'phase', 'planDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'])
    || typeof value.runId !== 'string' || !ID.test(value.runId) || value.phase !== 'paused-native') fail(code);
  return { runId: value.runId, phase: 'paused-native', planDigest: checkpointDigest(value.planDigest, code),
    registryAuthorityDigest: checkpointDigest(value.registryAuthorityDigest, code), sourceTagAuthorityDigest: checkpointDigest(value.sourceTagAuthorityDigest, code) };
}
function binding(value, code) {
  if (!exact(value, ['legacyEventId', 'legacySessionId', 'eventId', 'conversationId', 'sourceInstanceId', 'sourceTags', 'observedAt'])
    || typeof value.legacyEventId !== 'string' || !LEGACY_EVENT.test(value.legacyEventId)
    || typeof value.legacySessionId !== 'string' || !LEGACY_SESSION.test(value.legacySessionId) || typeof value.eventId !== 'string' || !EVENT.test(value.eventId)
    || typeof value.conversationId !== 'string' || !CONVERSATION.test(value.conversationId) || typeof value.sourceInstanceId !== 'string' || !SOURCE.test(value.sourceInstanceId)) fail(code);
  const tags = sourceTags(value.sourceTags, code);
  if (value.eventId !== deriveM4V3EventIdFromLegacyEventId(value.legacyEventId)
    || value.conversationId !== deriveM4V3ConversationIdFromLegacySessionId(value.legacySessionId)
    || value.sourceInstanceId !== deriveM4V3SourceInstanceIdFromLegacySession(value.legacySessionId, tags)) fail(code);
  return { legacyEventId: value.legacyEventId, legacySessionId: value.legacySessionId,
    eventId: value.eventId, conversationId: value.conversationId, sourceInstanceId: value.sourceInstanceId,
    sourceTags: tags, observedAt: timestamp(value.observedAt, code) };
}
function state(value, expected, code) {
  if (!exact(value, ['schema', 'binding', 'records']) || value.schema !== STATE_SCHEMA || !same(namespace(value.binding, code), expected)
    || !Array.isArray(value.records) || value.records.length > MAX_RECORDS) fail(code);
  const records = value.records.map(item => binding(item, code));
  for (let index = 1; index < records.length; index += 1) if (records[index - 1].legacyEventId >= records[index].legacyEventId) fail(code);
  return { schema: STATE_SCHEMA, binding: expected, records };
}
function namespaceDigest(value) { return crypto.createHash('sha256').update(canonicalJson(['amf.m4-post-cutoff-identity-store/namespace/v1', value]), 'utf8').digest('hex'); }
function roots(root) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root) fail('m4_post_cutoff_identity_store_dependency_invalid');
  let current = path.parse(root).root;
  for (const piece of root.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, piece); try { const stat = fs.lstatSync(current); if (stat.isSymbolicLink() || !stat.isDirectory()) fail('m4_post_cutoff_identity_store_unsafe'); }
    catch (error) { if (error?.code === 'ENOENT') break; if (error?.code?.startsWith?.('m4_post_cutoff_identity_store_')) throw error; fail('m4_post_cutoff_identity_store_unsafe'); }
  }
}
function open(root) { roots(root); try { fs.mkdirSync(root, { recursive: true, mode: 0o700 }); const fd = fs.openSync(root, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | (fs.constants.O_NOFOLLOW ?? 0)); directory(fs.fstatSync(fd)); return fd; } catch (error) { if (error?.code?.startsWith?.('m4_post_cutoff_identity_store_')) throw error; fail('m4_post_cutoff_identity_store_unsafe'); } }
function child(fd, name) { return `/proc/self/fd/${fd}/${name}`; }
function statChild(fd, name) { try { return fs.lstatSync(child(fd, name)); } catch (error) { if (error?.code === 'ENOENT') return null; fail('m4_post_cutoff_identity_store_unsafe'); } }
function read(fd, name, expected) {
  const before = statChild(fd, name); if (before === null) return { schema: STATE_SCHEMA, binding: expected, records: [] }; file(before);
  let handle; try { handle = fs.openSync(child(fd, name), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)); const opened = fs.fstatSync(handle); file(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size > MAX_BYTES) fail('m4_post_cutoff_identity_store_unsafe');
    const bytes = fs.readFileSync(handle); const after = fs.fstatSync(handle);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || bytes.length > MAX_BYTES) fail('m4_post_cutoff_identity_store_unsafe');
    let parsed; try { parsed = JSON.parse(bytes.toString('utf8')); } catch { fail('m4_post_cutoff_identity_store_corrupt'); } return state(parsed, expected, 'm4_post_cutoff_identity_store_corrupt');
  } catch (error) { if (error?.code?.startsWith?.('m4_post_cutoff_identity_store_')) throw error; fail('m4_post_cutoff_identity_store_unsafe'); } finally { if (handle !== undefined) fs.closeSync(handle); }
}
function write(fd, name, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8'); if (bytes.length > MAX_BYTES) fail('m4_post_cutoff_identity_store_limit');
  const temp = `.${name}.${crypto.randomUUID()}.tmp`; let handle;
  try { handle = fs.openSync(child(fd, temp), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600); fs.fchmodSync(handle, 0o600); fs.writeFileSync(handle, bytes); fs.fsyncSync(handle); fs.closeSync(handle); handle = undefined; fs.renameSync(child(fd, temp), child(fd, name)); fs.fsyncSync(fd); }
  catch (error) { if (error?.code?.startsWith?.('m4_post_cutoff_identity_store_')) throw error; fail('m4_post_cutoff_identity_store_durability_failed'); }
  finally { if (handle !== undefined) fs.closeSync(handle); try { fs.unlinkSync(child(fd, temp)); } catch (error) { if (error?.code !== 'ENOENT') fail('m4_post_cutoff_identity_store_durability_failed'); } }
}
function recoverTemps(fd, prefix) {
  let names; try { names = fs.readdirSync(child(fd, '.')); } catch { fail('m4_post_cutoff_identity_store_unsafe'); }
  const expression = new RegExp(`^\\.${prefix}-[a-f0-9]{2}\\.json\\.[a-f0-9-]{36}\\.tmp$`);
  for (const name of names) {
    if (!expression.test(name)) continue;
    const stat = statChild(fd, name); if (stat === null) continue; file(stat);
    try { fs.unlinkSync(child(fd, name)); } catch { fail('m4_post_cutoff_identity_store_unsafe'); }
  }
  try { fs.fsyncSync(fd); } catch { fail('m4_post_cutoff_identity_store_durability_failed'); }
}

export class M4PostCutoffIdentityStore {
  constructor(input = {}) {
    if (!exact(input, ['rootPath', 'runId', 'phase', 'planDigest', 'registryAuthorityDigest', 'sourceTagAuthorityDigest'])) fail('m4_post_cutoff_identity_store_dependency_invalid');
    const { rootPath, runId, phase, planDigest, registryAuthorityDigest, sourceTagAuthorityDigest } = input;
    this.binding = namespace({ runId, phase, planDigest, registryAuthorityDigest, sourceTagAuthorityDigest }, 'm4_post_cutoff_identity_store_dependency_invalid');
    this.directory = open(rootPath); this.statePrefix = `m4-post-cutoff-${namespaceDigest(this.binding)}`;
    try { recoverTemps(this.directory, this.statePrefix); } catch (error) { fs.closeSync(this.directory); this.directory = null; throw error; }
  }
  #name(legacyEventId) { return `${this.statePrefix}-${legacyEventId.slice(4, 6)}.json`; }
  load(legacyEventId) { if (this.directory === null) fail('m4_post_cutoff_identity_store_closed'); if (typeof legacyEventId !== 'string' || !LEGACY_EVENT.test(legacyEventId)) fail('m4_post_cutoff_identity_store_request_invalid'); const found = read(this.directory, this.#name(legacyEventId), this.binding).records.find(item => item.legacyEventId === legacyEventId); return found ? structuredClone(found) : null; }
  commit(value) { if (this.directory === null) fail('m4_post_cutoff_identity_store_closed'); const next = binding(value, 'm4_post_cutoff_identity_store_binding_invalid'); const name = this.#name(next.legacyEventId); const current = read(this.directory, name, this.binding); const index = current.records.findIndex(item => item.legacyEventId === next.legacyEventId); if (index >= 0) { if (!same(current.records[index], next)) fail('m4_post_cutoff_identity_store_drift'); return structuredClone(next); }
    if (current.records.length >= MAX_RECORDS) fail('m4_post_cutoff_identity_store_limit'); const records = [...current.records, next].sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId)); write(this.directory, name, { schema: STATE_SCHEMA, binding: this.binding, records }); return structuredClone(next); }
  close() { if (this.directory !== null) { fs.closeSync(this.directory); this.directory = null; } }
}
