import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = 'amf.host-file-catalog-policy/v1';
const within = (p, prefix) => p === prefix || p.startsWith(prefix === '/' ? '/' : `${prefix}/`);
const absolute = p => typeof p === 'string' && path.isAbsolute(p) && path.normalize(p) === p;
const secretPath = p => /(^|\/)(\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.docker|\.npmrc|\.netrc|\.git-credentials|cookies?|login data|gogcli|keyrings?|credentials?|secrets?|\.env(?:\..*)?|id_(?:rsa|ed25519)|[^/]*\.(?:pem|key|p12|pfx|kdbx))($|\/)|(?:password|token|credential|secret|session[-_.]?store)/i.test(p);
const secretText = s => /-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH)|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,})|(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|authorization|refresh[_-]?token)\s*["']?\s*[:=]\s*["']?\S{4,}/i.test(s);
const now = () => new Date().toISOString();
const int = (n, min, max, name) => { if (!Number.isInteger(n) || n < min || n > max) throw new Error(`Invalid ${name}`); return n; };

// Anchor every component to an open directory descriptor. Linux /proc/self/fd is
// used only for descriptor-relative operations, never as an inventory source.
function anchored(p, fn) {
  let fd = fs.openSync('/', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    const parts = p.split('/').filter(Boolean), leaf = parts.pop();
    for (const part of parts) {
      const next = fs.openSync(`/proc/self/fd/${fd}/${part}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      fs.closeSync(fd); fd = next;
    }
    return fn(leaf ? `/proc/self/fd/${fd}/${leaf}` : `/proc/self/fd/${fd}/.`);
  } finally { fs.closeSync(fd); }
}

export class HostFileCatalog {
  constructor({ databasePath, policy }) {
    if (!absolute(databasePath) || !policy || policy.schema !== SCHEMA || typeof policy.hostId !== 'string' || !policy.hostId) throw new Error('Invalid catalog configuration');
    for (const key of ['roots', 'excludePrefixes', 'metadataOnlyPrefixes']) if (!Array.isArray(policy[key]) || policy[key].some(p => !absolute(p))) throw new Error(`Invalid ${key}`);
    for (const virtual of ['/proc','/sys','/dev']) {
      if (policy.roots.some(root => within(virtual,root) || within(root,virtual)) && !policy.excludePrefixes.some(prefix => within(virtual,prefix))) throw new Error('Virtual filesystem trees require explicit exclusion');
    }
    if (!policy.roots.length || !Array.isArray(policy.domains)) throw new Error('Invalid roots/domains');
    const ids = new Set();
    for (const d of policy.domains) {
      if (!d.id || typeof d.id !== 'string' || ids.has(d.id) || !Array.isArray(d.prefixes) || d.prefixes.some(p => !absolute(p)) || (d.destination && !absolute(d.destination))) throw new Error('Invalid domain');
      ids.add(d.id);
    }
    if (policy.metadataOnlyDirectoryNames !== undefined && (!Array.isArray(policy.metadataOnlyDirectoryNames) || policy.metadataOnlyDirectoryNames.some(name => typeof name !== 'string' || !/^[A-Za-z0-9._-]{1,255}$/.test(name) || name === '.' || name === '..'))) throw new Error('Invalid metadataOnlyDirectoryNames');
    const c = policy.content;
    if (!c || typeof c.enabled !== 'boolean' || !Array.isArray(c.extensions) || c.extensions.some(e => !/^\.[a-z0-9]+$/i.test(e))) throw new Error('Invalid content policy');
    int(c.maxBytes, 1, 10 * 1024 * 1024, 'content.maxBytes');
    this.policy = structuredClone(policy); this.databasePath = databasePath; this.handles = new Map(); this.closed = false;
    this.maxDirectoryEntries = int(policy.limits?.maxDirectoryEntries ?? 100000, 1, 1000000, 'maxDirectoryEntries');
    // Require a dedicated private directory; do not silently chmod a shared tree.
    const parent = path.dirname(databasePath);
    anchored(path.dirname(parent), p => { if (!fs.statSync(p).isDirectory()) throw new Error('Invalid database ancestor'); });
    if (!fs.existsSync(parent)) fs.mkdirSync(parent, { mode: 0o700 });
    anchored(parent, p => { const s = fs.lstatSync(p); if (!s.isDirectory() || (s.mode & 0o077) || s.uid !== process.getuid()) throw new Error('Database parent must be private and owned by current user'); });
    try {
      anchored(databasePath, p => { const fd = fs.openSync(p, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600); const s = fs.fstatSync(fd); fs.closeSync(fd); if (!s.isFile() || s.nlink !== 1 || s.uid !== process.getuid() || (s.mode & 0o077)) throw new Error('Database must be private regular file'); });
      this.db = new DatabaseSync(databasePath);
      this.db.exec(`PRAGMA busy_timeout=1000; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT; PRAGMA journal_mode=DELETE;
        CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, phase TEXT NOT NULL, started TEXT, completed TEXT, policy_hash TEXT);
        CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY, path TEXT NOT NULL, kind TEXT NOT NULL, cursor INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, kind TEXT, size INTEGER, mtime TEXT, signature TEXT, domain TEXT, classification_prefix TEXT, confidence REAL, content_state TEXT, generation INTEGER, observed_at TEXT);
        CREATE TABLE IF NOT EXISTS coverage (id INTEGER PRIMARY KEY, generation INTEGER, path TEXT, kind TEXT, reason TEXT, observed_at TEXT);
        CREATE VIRTUAL TABLE IF NOT EXISTS texts USING fts5(path UNINDEXED, body);
        INSERT OR IGNORE INTO state(id,generation,phase) VALUES(1,0,'idle');`);
      this.policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');
      const state = this.db.prepare('SELECT * FROM state').get();
      if (state.policy_hash && state.policy_hash !== this.policyHash) throw new Error('Policy changed: use a separate catalog database');
    } catch (error) { this.close(); throw error; }
  }
  record(p, kind, reason) { this.db.prepare('INSERT INTO coverage(generation,path,kind,reason,observed_at) VALUES(?,?,?,?,?)').run(this.generation, p, kind, reason, now()); }
  classification(p) {
    const candidates = this.policy.domains.flatMap(d => d.prefixes.filter(prefix => within(p, prefix)).map(prefix => ({ domain: d.id, prefix })));
    candidates.sort((a,b) => b.prefix.length - a.prefix.length);
    if (!candidates.length || (candidates[1] && candidates[0].prefix === candidates[1].prefix && candidates[0].domain !== candidates[1].domain)) return { domain: 'unknown', prefix: null, confidence: 0 };
    return { ...candidates[0], confidence: 1 };
  }
  excluded(p) { return within(p, path.dirname(this.databasePath)) || this.policy.excludePrefixes.some(prefix => within(p, prefix)); }
  inspect(p) {
    if (this.excluded(p)) { this.record(p, 'excluded', 'policy-or-catalog-state'); return; }
    anchored(p, target => {
      const s = fs.lstatSync(target, { bigint: true });
      const kind = s.isFile() ? 'file' : s.isDirectory() ? 'directory' : s.isSymbolicLink() ? 'symlink' : 'special';
      const signature = [s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.mode].join(':');
      const previous = this.db.prepare('SELECT signature,content_state FROM files WHERE path=?').get(p);
      const classification = this.classification(p);
      let contentState = kind === 'file' ? 'not-allowlisted' : 'metadata-only';
      let body = null;
      const allowed = this.policy.content.enabled && this.policy.content.extensions.includes(path.extname(p).toLowerCase());
      if (kind === 'file' && secretPath(p)) contentState = 'sensitive-path';
      else if (kind === 'file' && (this.policy.metadataOnlyPrefixes.some(prefix => within(p, prefix)) || path.dirname(p).split(path.sep).some(component => (this.policy.metadataOnlyDirectoryNames ?? []).includes(component)))) contentState = 'metadata-only-policy';
      else if (kind === 'file' && allowed) {
        if (s.size > BigInt(this.policy.content.maxBytes)) contentState = 'too-large';
        else if (previous?.signature === signature && previous.content_state !== 'unavailable') contentState = previous.content_state;
        else {
          const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
          try {
            const before = fs.fstatSync(fd, { bigint: true });
            if (!before.isFile() || [before.dev,before.ino,before.size,before.mtimeNs,before.ctimeNs,before.mode].join(':') !== signature) throw new Error('File changed before read');
            const bytes = Buffer.alloc(this.policy.content.maxBytes + 1);
            const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
            const after = fs.fstatSync(fd, { bigint: true });
            if ([after.dev,after.ino,after.size,after.mtimeNs,after.ctimeNs,after.mode].join(':') !== signature) throw new Error('File changed during read');
            if (BigInt(length) !== s.size && length <= this.policy.content.maxBytes) throw new Error('Incomplete file read');
            if (length > this.policy.content.maxBytes) contentState = 'too-large';
            else {
              try { body = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0,length)); } catch { contentState = 'invalid-utf8'; }
              if (body !== null) {
                if (body.includes('\0')) { body = null; contentState = 'binary'; }
                else if (secretText(body)) { body = null; contentState = 'sensitive-content'; }
                else contentState = 'indexed';
              }
            }
          } finally { fs.closeSync(fd); }
        }
      }
      if (!(previous?.signature === signature && contentState === 'indexed')) {
        this.db.prepare('DELETE FROM texts WHERE path=?').run(p);
        if (body !== null) this.db.prepare('INSERT INTO texts(path,body) VALUES(?,?)').run(p,body);
      }
      this.db.prepare(`INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET kind=excluded.kind,size=excluded.size,mtime=excluded.mtime,signature=excluded.signature,domain=excluded.domain,classification_prefix=excluded.classification_prefix,confidence=excluded.confidence,content_state=excluded.content_state,generation=excluded.generation,observed_at=excluded.observed_at`).run(p,kind,Number(s.size),String(s.mtimeNs),signature,classification.domain,classification.prefix,classification.confidence,contentState,this.generation,now());
      if (kind === 'directory') this.db.prepare("INSERT INTO queue(path,kind) VALUES(?,'directory')").run(p);
      if (kind === 'symlink' || kind === 'special') this.record(p,'excluded',`${kind}-no-follow-no-read`);
    });
  }
  directory(task) {
    let handle = this.handles.get(task.id);
    if (!handle) {
      handle = anchored(task.path, p => {
        const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
        try { return fs.opendirSync(`/proc/self/fd/${fd}/.`); } finally { fs.closeSync(fd); }
      });
      // Offsets are traversal hints, not deletion evidence; changed directories may
      // need the next full generation to include concurrently inserted entries.
      handle = { directory:handle, skip:task.cursor };
      this.handles.set(task.id,handle);
    }
    if (handle.skip > 0) { handle.directory.readSync(); handle.skip--; return false; }
    if (task.cursor >= this.maxDirectoryEntries) { this.record(task.path,'incomplete','directory-entry-limit'); handle.directory.closeSync(); this.handles.delete(task.id); return true; }
    const entry = handle.directory.readSync();
    if (!entry) { handle.directory.closeSync(); this.handles.delete(task.id); return true; }
    this.db.prepare("INSERT INTO queue(path,kind) VALUES(?,'entry')").run(path.join(task.path,entry.name));
    this.db.prepare('UPDATE queue SET cursor=cursor+1 WHERE id=?').run(task.id);
    return false;
  }
  async scan({ maxEntries=10000, budgetMs=2000, restart=false }={}) {
    int(maxEntries,1,100000,'maxEntries'); int(budgetMs,1,60000,'budgetMs');
    if (typeof restart !== 'boolean') throw new Error('Invalid restart');
    if (this.scanning) throw new Error('Scan already running');
    this.scanning = true;
    try {
      let state = this.db.prepare('SELECT * FROM state').get();
      if (state.phase === 'complete' && !restart) return { processed:0, state:'complete', ...this.status() };
      if (state.phase !== 'scanning') {
        this.db.exec('BEGIN IMMEDIATE');
        try {
          this.db.prepare("UPDATE state SET generation=generation+1,phase='scanning',completed=NULL,started=?,policy_hash=? WHERE id=1").run(now(),this.policyHash);
          for (const root of [...new Set(this.policy.roots)].filter(r => !this.policy.roots.some(other => other !== r && within(r,other)))) this.db.prepare("INSERT INTO queue(path,kind) VALUES(?,'entry')").run(root);
          this.db.exec('COMMIT');
        } catch(error) { this.db.exec('ROLLBACK'); throw error; }
      }
      this.generation = this.db.prepare('SELECT generation FROM state').get().generation;
      const start = Date.now(); let processed = 0;
      while (processed < maxEntries && Date.now()-start < budgetMs) {
        const task = this.db.prepare('SELECT * FROM queue ORDER BY id LIMIT 1').get();
        if (!task) break;
        this.db.exec('BEGIN IMMEDIATE');
        try {
          let done = true;
          try { if (task.kind === 'directory') done = this.directory(task); else this.inspect(task.path); }
          catch(error) {
            this.record(task.path,'error',error.code ?? 'inspection-failed');
            this.db.prepare('DELETE FROM texts WHERE path=?').run(task.path);
            this.db.prepare("UPDATE files SET content_state='unavailable' WHERE path=?").run(task.path);
            const active = this.handles.get(task.id);
            if (active) { try { active.directory.closeSync(); } catch {} this.handles.delete(task.id); }
          }
          if (done) this.db.prepare('DELETE FROM queue WHERE id=?').run(task.id);
          this.db.exec('COMMIT');
        } catch(error) {
          this.db.exec('ROLLBACK');
          for (const active of this.handles.values()) { try { active.directory.closeSync(); } catch {} }
          this.handles.clear();
          throw error;
        }
        processed++;
      }
      if (!this.db.prepare('SELECT 1 FROM queue LIMIT 1').get()) this.db.prepare("UPDATE state SET phase='complete',completed=? WHERE id=1").run(now());
      const status = this.status();
      return { processed, state:status.scan.state, ...status };
    } finally { this.scanning = false; }
  }
  status() {
    const state = this.db.prepare('SELECT generation,phase,started,completed FROM state').get();
    return { hostId:this.policy.hostId, scan:{...state,state:state.phase === 'scanning' ? 'running' : state.phase}, pending:this.db.prepare('SELECT count(*) AS n FROM queue').get().n,
      counts:{ total:this.db.prepare('SELECT count(*) AS n FROM files').get().n, byDomain:this.db.prepare('SELECT domain,count(*) AS count FROM files GROUP BY domain').all(), byContentState:this.db.prepare('SELECT content_state AS state,count(*) AS count FROM files GROUP BY content_state').all() },
      coverage:{ roots:this.policy.roots, configuredExclusions:this.policy.excludePrefixes, metadataOnlyPrefixes:this.policy.metadataOnlyPrefixes, metadataOnlyDirectoryNames:this.policy.metadataOnlyDirectoryNames ?? [], summary:this.db.prepare('SELECT kind,count(*) AS count FROM coverage WHERE generation=? GROUP BY kind').all(state.generation), recent:this.db.prepare('SELECT path,kind,reason,observed_at FROM coverage WHERE generation=? ORDER BY id DESC LIMIT 100').all(state.generation) },
      freshness:{ unverified:this.db.prepare('SELECT count(*) AS n FROM files WHERE generation<>?').get(state.generation).n, semantics:'Last observed metadata; unseen files are retained as unverified, never inferred deleted. Concurrent directory changes may require another generation.' } };
  }
  search({ query='', domain=null, limit=50, offset=0 }={}) {
    int(limit,1,200,'limit'); int(offset,0,1000000,'offset');
    if (typeof query !== 'string' || query.length > 1000 || (domain !== null && typeof domain !== 'string')) throw new Error('Invalid search');
    const tokens = query.match(/[\p{L}\p{N}_-]+/gu) ?? [];
    const match = tokens.map(t => `"${t.replaceAll('"','""')}"`).join(' AND ');
    const where = `(f.path LIKE ? ESCAPE '!'${match ? ' OR f.path IN (SELECT path FROM texts WHERE texts MATCH ?)' : ''}) AND (? IS NULL OR f.domain=?)`;
    const literalPath = `%${query.replaceAll('!','!!').replaceAll('%','!%').replaceAll('_','!_')}%`;
    const args = [literalPath,...(match ? [match] : []),domain,domain];
    const total = this.db.prepare(`SELECT count(*) AS n FROM files f WHERE ${where}`).get(...args).n;
    const items = this.db.prepare(`SELECT f.path,f.kind,f.size,f.domain,f.classification_prefix AS classificationPrefix,f.confidence,f.content_state AS contentState,f.observed_at AS observedAt,f.generation,(f.generation=(SELECT generation FROM state)) AS currentGeneration FROM files f WHERE ${where} ORDER BY f.path LIMIT ? OFFSET ?`).all(...args,limit,offset);
    return {items,total};
  }
  suggestions({limit=50}={}) {
    int(limit,1,200,'limit');
    const destinations = new Map(this.policy.domains.filter(d => d.destination).map(d => [d.id,d.destination]));
    const domainIds = [...destinations.keys()];
    const rows = this.db.prepare(`SELECT path,domain,classification_prefix AS classificationPrefix,confidence,observed_at AS observedAt,generation FROM files WHERE kind='file' AND (domain='unknown'${domainIds.length ? ` OR domain IN (${domainIds.map(()=>'?').join(',')})` : ''}) ORDER BY path LIMIT ?`).all(...domainIds,limit);
    const currentGeneration = this.db.prepare('SELECT generation FROM state').get().generation;
    return rows.map(f => ({path:f.path,domain:f.domain,action:'review-only',suggestedDestination:destinations.get(f.domain) ?? null,evidence:{classificationPrefix:f.classificationPrefix,confidence:f.confidence,observedAt:f.observedAt,currentGeneration:f.generation === currentGeneration},uncertainty:'Path classification only; ownership, references, duplicate identity and suitability for relocation are unverified. No action is executed.'}));
  }

  close() {
    if (this.closed) return; this.closed = true;
    for (const h of this.handles?.values() ?? []) { try { h.directory.closeSync(); } catch {} }
    this.db?.close();

  }
}
