import http from 'node:http';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { dirname, isAbsolute, parse, resolve, sep } from 'node:path';
import { createHash, timingSafeEqual } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const hash = value => createHash('sha256').update(value).digest();
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
const integer = (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const absolute = value => typeof value === 'string' && isAbsolute(value) && !value.includes('\0');
const STATES = new Set(['healthy','degraded','critical','unknown','skipped']);

/** Private configuration and report reads never follow symlinks or print file contents on failure. */
export async function readPrivateFile(path, maxBytes = 1024 * 1024) {
  if (!absolute(path)) throw new Error('private_file_invalid');
  const normalized = resolve(path);
  let cursor = parse(normalized).root;
  for (const part of normalized.slice(cursor.length).split(sep).filter(Boolean).slice(0,-1)) {
    cursor = resolve(cursor,part);
    const stat = await lstat(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('private_file_invalid');
  }
  const parent = await lstat(dirname(normalized));
  if (parent.uid !== process.getuid() || (parent.mode & 0o077) !== 0) throw new Error('private_file_invalid');
  const before = await lstat(normalized);
  if (!before.isFile() || before.nlink !== 1 || before.uid !== process.getuid() || (before.mode & 0o077) !== 0 || before.size > maxBytes) throw new Error('private_file_invalid');
  const handle = await open(normalized,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.nlink !== 1 || stat.size > maxBytes) throw new Error('private_file_invalid');
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(buffer,0,buffer.length,0);
    const after = await handle.stat();
    if (bytesRead !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) throw new Error('private_file_changed');
    return buffer.subarray(0,bytesRead).toString('utf8');
  } finally { await handle.close(); }
}

export function validateHostAdminConfig(input) {
  const allowed = ['schema','bind','port','policyPath','databasePath','tokenFile','scanIntervalMs','scanBudgetMs','scanMaxEntries','rescanIntervalMs','healthProbe','qualityReportPath'];
  if (!plain(input) || Object.keys(input).some(key => !allowed.includes(key)) || input.schema !== 'amf.host-admin-config/v1' || input.bind !== '127.0.0.1' || !integer(input.port,1024,65535)) throw new Error('admin_config_invalid');
  for (const name of ['policyPath','databasePath','tokenFile']) if (!absolute(input[name])) throw new Error('admin_config_invalid');
  const config = {scanIntervalMs:1000,scanBudgetMs:1000,scanMaxEntries:5000,rescanIntervalMs:3600000,...structuredClone(input)};
  if (!integer(config.scanIntervalMs,100,60000) || !integer(config.scanBudgetMs,10,5000) || !integer(config.scanMaxEntries,1,100000) || !integer(config.rescanIntervalMs,60000,7*86400000)) throw new Error('admin_config_invalid');
  if (config.qualityReportPath !== undefined && !absolute(config.qualityReportPath)) throw new Error('admin_config_invalid');
  if (config.healthProbe !== undefined) {
    const probe = config.healthProbe;
    if (!plain(probe) || Object.keys(probe).some(key => !['command','args','intervalMs','timeoutMs'].includes(key)) || !absolute(probe.command) || !Array.isArray(probe.args) || probe.args.length > 32 || probe.args.some(arg => typeof arg !== 'string' || arg.length > 4096 || arg.includes('\0')) || !integer(probe.intervalMs,60000,86400000) || !integer(probe.timeoutMs,1000,120000)) throw new Error('admin_config_invalid');
  }
  return config;
}

export function normalizeHealth(value, now = Date.now()) {
  if (!plain(value) || value.schema !== 'amf.health-report/v1' || !STATES.has(value.overall) || !Array.isArray(value.checks) || value.checks.length > 256 || !Number.isFinite(Date.parse(value.generatedAt))) return {overall:'unknown',reason:'health_report_invalid'};
  const ageMs = now - Date.parse(value.generatedAt);
  const checks = value.checks.map(check => {
    const evidence = {};
    const keys = ['enabled','schedulerKind','schedulerState','timerState','serviceState','runtimeMarkerState','result','execMainStatus','pending','dead','lastTriggerAt'];
    for (const key of keys) if (typeof check.evidence?.[key] === 'number' || typeof check.evidence?.[key] === 'boolean' || (typeof check.evidence?.[key] === 'string' && check.evidence[key].length < 256) || check.evidence?.[key] === null) evidence[key] = check.evidence[key];
    return {id:String(check.id ?? 'unknown').slice(0,128),status:STATES.has(check.status) ? check.status : 'unknown',summary:String(check.summary ?? '').slice(0,512),evidence};
  });
  return {schema:value.schema,generatedAt:value.generatedAt,ageMs,overall:ageMs < -60000 || ageMs > 300000 ? 'unknown' : value.overall,stale:ageMs < -60000 || ageMs > 300000,checks};
}

export async function runHealthProbe(probe) {
  try {
    const {stdout} = await execute(probe.command,probe.args,{timeout:probe.timeoutMs,maxBuffer:1024*1024,encoding:'utf8',windowsHide:true});
    return JSON.parse(stdout);
  } catch (error) {
    // Probe exit 1/2 is meaningful degraded/critical evidence, not a transport failure.
    if ([1,2].includes(error.code) && error.stdout) {
      try { return JSON.parse(error.stdout); } catch { /* Return a bounded unknown state. */ }
    }
    return null;
  }
}

/** No raw memories, document bodies, configuration paths or credentials enter the status DTO. */
export function normalizeQuality(value, now = Date.now()) {
  if (!plain(value) || value.schema !== 'amf.memory-quality-report/v1' || !Number.isFinite(Date.parse(value.generatedAt)) || !Array.isArray(value.checks)) return {overall:'unknown',reason:'quality_not_measured'};
  const ageMs = now - Date.parse(value.generatedAt);
  return {schema:value.schema,generatedAt:value.generatedAt,ageMs,overall:ageMs >= -60000 && ageMs <= 86400000 && STATES.has(value.overall) ? value.overall : 'unknown',checks:value.checks.slice(0,100).map(check => ({id:String(check.id ?? '').slice(0,128),status:STATES.has(check.status) ? check.status : 'unknown',metric:typeof check.metric === 'number' && Number.isFinite(check.metric) ? check.metric : null,unit:String(check.unit ?? '').slice(0,32),summary:String(check.summary ?? '').slice(0,512)}))};
}

export function createHostAdminServer({catalog,token,healthProvider = async () => null,qualityProvider = async () => null,clock = Date.now}) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('admin_token_invalid');
  const expected = hash(token);
  let health = null,quality = null,refreshing = null,lastError = null;
  const refresh = async () => {
    if (refreshing) return refreshing;
    refreshing = Promise.allSettled([healthProvider(),qualityProvider()]).then(results => {
      health = results[0].status === 'fulfilled' ? results[0].value : null;
      quality = results[1].status === 'fulfilled' ? results[1].value : null;
    }).finally(() => { refreshing = null; });
    return refreshing;
  };
  const server = http.createServer(async (request,response) => {
    const reply = (status,body) => {
      response.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'"});
      response.end(JSON.stringify(body));
    };
    const credentials = request.headers.authorization;
    if (typeof credentials !== 'string' || credentials.length > 280 || !credentials.startsWith('Bearer ') || !timingSafeEqual(hash(credentials.slice(7)),expected)) { reply(401,{error:'unauthorized'});return; }
    if (request.method !== 'GET') { reply(405,{error:'method_not_allowed'});return; }
    try {
      const url = new URL(request.url,'http://localhost');
      const allowed = url.pathname === '/v1/files' ? ['query','domain','limit','offset'] : url.pathname === '/v1/suggestions' ? ['limit'] : [];
      if ([...url.searchParams.keys()].some(key => !allowed.includes(key) || url.searchParams.getAll(key).length !== 1)) { reply(400,{error:'invalid_query'});return; }
      const number = (name,fallback,min,max) => {
        const raw = url.searchParams.get(name);
        if (raw === null) return fallback;
        if (!/^\d+$/.test(raw) || !integer(Number(raw),min,max)) throw new Error('invalid_query');
        return Number(raw);
      };
      if (url.pathname === '/v1/status') {
        const now = clock(),h = normalizeHealth(health,now),q = normalizeQuality(quality,now),c = catalog.status();
        const incomplete = (c.coverage?.summary ?? []).some(row => ['error','incomplete'].includes(row.kind) && row.count > 0);
        const overall = h.overall === 'critical' ? 'critical' : lastError || h.overall !== 'healthy' || q.overall !== 'healthy' || c.scan?.state !== 'complete' || incomplete || c.freshness?.unverified > 0 ? 'degraded' : 'healthy';
        reply(200,{schema:'amf.host-admin-status/v1',asOf:new Date(now).toISOString(),overall,catalog:c,health:h,quality:q,scannerError:lastError});
      } else if (url.pathname === '/v1/files') {
        const query = url.searchParams.get('query') ?? '',domain = url.searchParams.get('domain');
        if (query.length > 1000 || (domain !== null && !/^[A-Za-z0-9:._-]{1,128}$/.test(domain))) throw new Error('invalid_query');
        reply(200,catalog.search({query,domain,limit:number('limit',50,1,100),offset:number('offset',0,0,1000000)}));
      } else if (url.pathname === '/v1/suggestions') {
        const result = catalog.suggestions({limit:number('limit',50,1,100)});
        reply(200,Array.isArray(result) ? {items:result} : result);
      } else reply(404,{error:'not_found'});
    } catch (error) { reply(error.message === 'invalid_query' ? 400 : 503,{error:error.message === 'invalid_query' ? 'invalid_query' : 'admin_unavailable'}); }
  });
  server.requestTimeout = 10000;server.headersTimeout = 10000;server.keepAliveTimeout = 1000;
  return {server,refresh,setScannerError:value => {lastError = value ? 'scan_failed' : null;}};
}

export async function startHostAdmin(rawConfig) {
  const config = validateHostAdminConfig(rawConfig);
  const {HostFileCatalog} = await import('./host-file-catalog.mjs');
  const policy = JSON.parse(await readPrivateFile(config.policyPath));
  const token = (await readPrivateFile(config.tokenFile,512)).trim();
  const catalog = new HostFileCatalog({databasePath:config.databasePath,policy});
  const api = createHostAdminServer({catalog,token,
    healthProvider:() => config.healthProbe ? runHealthProbe(config.healthProbe) : null,
    qualityProvider:async () => config.qualityReportPath ? JSON.parse(await readPrivateFile(config.qualityReportPath)) : null});
  let stopped = false,scanning = null,lastComplete = 0;
  const tick = async () => {
    if (stopped || scanning) return;
    const state = catalog.scanState().state;
    if (state === 'complete' && Date.now() - lastComplete < config.rescanIntervalMs) return;
    scanning = catalog.scan({maxEntries:config.scanMaxEntries,budgetMs:config.scanBudgetMs,restart:state === 'complete',includeStatus:false});
    try { const result = await scanning; api.setScannerError(null); if (result.state === 'complete') lastComplete = Date.now(); }
    catch {api.setScannerError('scan_failed');}
    finally {scanning = null;}
  };
  try {
    await new Promise((accept,reject) => {api.server.once('error',reject);api.server.listen(config.port,config.bind,accept);});
  } catch (error) { catalog.close();throw error; }
  // Initial report/scan run asynchronously: large scans never hold startup hostage.
  void api.refresh();void tick();
  const scanTimer = setInterval(() => {void tick();},config.scanIntervalMs);
  const healthTimer = setInterval(() => {void api.refresh();},config.healthProbe?.intervalMs ?? 60000);
  return {address:api.server.address(),close:async () => {
    stopped = true;clearInterval(scanTimer);clearInterval(healthTimer);
    await new Promise(resolveClose => {api.server.close(resolveClose);api.server.closeIdleConnections();});
    await scanning;catalog.close();
  }};
}
