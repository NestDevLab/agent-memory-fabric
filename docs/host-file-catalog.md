# Host file catalog

The host catalog inventories explicitly configured local roots into a private SQLite database. It is an administrative discovery tool, separate from the AMF corpus, curated memory, and ingestion pipelines. It never moves/deletes source files or promotes content into memory. Domain labels use configured path prefixes first. Optional filename hints provide proposal labels with lower confidence only when no prefix applies; neither labels nor hints establish ownership or grant access.

Requires Linux, mounted `/proc/self/fd`, and Node.js 24 or newer with `node:sqlite` and FTS5 (validated on Node.js 24.14.1). There are no additional dependencies.

## Policy

Keep the policy and actual host/domain/root mappings private. Generic example:

```json
{
  "schema": "amf.host-file-catalog-policy/v1",
  "hostId": "example-host",
  "roots": ["/srv/example-documents"],
  "excludePrefixes": ["/proc", "/sys", "/dev"],
  "metadataOnlyPrefixes": ["/srv/example-documents/generated"],
  "metadataOnlyDirectoryNames": ["node_modules", ".git"],
  "domains": [
    {
      "id": "example",
      "prefixes": ["/srv/example-documents/project"],
      "nameHints": ["alpha", "alpha-team"],
      "destination": "/srv/proposed-example"
    }
  ],
  "content": {
    "enabled": true,
    "maxBytes": 131072,
    "extensions": [".txt", ".md"]
  },
  "limits": {"maxDirectoryEntries": 100000}
}
```

Paths must be normalized and absolute. Longest boundary-safe prefix wins: `/project` does not classify `/project-other`. Equal-length conflicting matches become `unknown` with confidence 0. A configured match has confidence 1 **for the path rule only**, with its matching prefix recorded as provenance and `classificationBasis: "configured-prefix"`. Optional `domain.nameHints` defaults to `[]` and accepts literal ASCII alphanumeric segments separated by single hyphens, at most 64 characters per hint. With no matching prefix, hints are compared case-insensitively against whole basename tokens; punctuation separates tokens, so `alpha` matches `alpha-plan.pdf` but not `alphabets.pdf`, and `alpha-team` matches the adjacent token group in `alpha-team-plan.pdf`. Exactly one matching domain receives confidence 0.5, prefix `null` and `classificationBasis: "filename-hint"`; conflicting hints remain `unknown` with confidence 0. Conflicting prefix rules remain unknown without falling back to hints. Filename hints express proposals only and confer no authority or permission. Root overlaps are deduplicated. Virtual trees `/proc`, `/sys`, `/dev` must be explicitly excluded when a root can include them. Add host-specific virtual mounts and network/storage exclusions to the policy; the catalog cannot identify every filesystem type.

Generated/cache trees must be explicitly listed in `metadataOnlyPrefixes` or optional `metadataOnlyDirectoryNames` (default `[]`). Directory names must be safe single components of letters, digits, dot, underscore or hyphen, excluding `.` and `..`. Every file beneath a matching directory component is inventoried as metadata without reading its content; traversal still enumerates all entries and does not exclude the subtree. Status coverage includes the configured names. Changing policy requires a separate database, preventing old indexed text from surviving a newly tightened policy accidentally. The catalog excludes its entire dedicated database parent, including journal, lock, and other state files.

## CLI and API

```sh
node scripts/amf-host-catalog.mjs --config /srv/private-catalog/policy.json --database /srv/private-catalog/state/catalog.sqlite scan --max-entries 10000 --budget-ms 2000
node scripts/amf-host-catalog.mjs --config /srv/private-catalog/policy.json --database /srv/private-catalog/state/catalog.sqlite status
node scripts/amf-host-catalog.mjs --config /srv/private-catalog/policy.json --database /srv/private-catalog/state/catalog.sqlite search --query example --domain example --limit 50 --offset 0
node scripts/amf-host-catalog.mjs --config /srv/private-catalog/policy.json --database /srv/private-catalog/state/catalog.sqlite suggestions --limit 50
```

All output is JSON. Search matches the literal query against metadata paths, including files without indexed content, or matches literal tokens through FTS. SQL and FTS operators are never taken from the query. Results contain metadata without source text. An empty query lists inventory. Search returns `{items,total}`; items include classification provenance, content state, observation time, and `currentGeneration`. Suggestions include metadata evidence and uncertainty, use `action: "review-only"`, and never execute operations or expose content. Known or uniquely hinted files outside their domain's configured `destination` receive `reviewKind: "organization-proposal"` and the concrete `suggestedDestination` of that directory plus the source basename. Files already beneath the destination boundary are omitted. Protected paths, sensitive-content records, hardlinks and unreadable records are omitted. Real target proposals are streamed from SQL-filtered candidates before any unknown-domain `classification-review` entries, whose destination remains `null`; an early block of unknown inventory cannot hide later eligible proposals. Evidence names the `configured-prefix` or `filename-hint` basis, matching prefix or hints, confidence and freshness. Ownership, references, duplicate identity and destination collisions remain unknown: suggestions neither inspect a destination nor claim that a move is safe. Unknown files remain in inventory and coverage regardless of suggestion limits.

Import `HostFileCatalog` from `src/host-file-catalog.mjs` and construct with `{databasePath,policy}`. Methods:

- `await scan({maxEntries=10000,budgetMs=2000,restart=false})`: bounded queue work, returning `processed`, `state` and status fields.
- `status()`: `scan.state` (`idle`, `running`, `complete`), generation, pending work, counts by domain/content state, coverage errors/exclusions and freshness.
- `search({query='',domain=null,limit=50,offset=0})` and `suggestions({limit=50})`.
- `close()`: close handles/database and release the native SQLite connection lock.

A completed catalog remains complete on subsequent `scan()` calls. Start another generation with `scan({restart:true})`; `restart` does not discard a running generation. This permits a periodic caller to drain one generation without continuously rereading completed trees.

## Safety, persistence and limitations

The database parent must be dedicated, owned by the current user, and private (0700); one missing final directory can be created. The database must be an owned 0600 regular file with one link. The catalog uses SQLite rollback journaling inside this directory. `locking_mode=EXCLUSIVE` and an initial exclusive transaction retain a native SQLite lock for the connection lifetime, with a bounded busy timeout. Only one catalog connection can own the database; this includes status/search CLI instances. Do not run a standalone CLI against the same database while an administrative server owns it; use that server's read interface.

The operating system releases the native lock when the process exits, including SIGKILL. No PID sentinel or manual unlink is needed. Reopen the existing database to resume its persisted queue. SQLite transactions preserve committed inventory and queue progress across crashes; the test suite verifies a killed child process followed by immediate reconnect/resume.

Traversal uses descriptor-anchored directory components and `O_NOFOLLOW`, including ancestors. Symlinks and special files are metadata-only, never content-read or traversed. Regular files with multiple hardlinks are `metadata-only-hardlink` and never content-read or proposed for reorganization, preventing an innocuous hardlink alias from bypassing protected-path rules. Link count is included in the stat signature and rechecked before and after reads. Source path strings never become shell commands. Permission errors and inaccessible paths are coverage errors. Credentials paths are rejected before content reads; allowlisted regular files are read through a descriptor with `O_NOFOLLOW` and `O_NONBLOCK`, a hard byte bound, and stat identity/change checks. Text requires strict UTF-8 without NUL. Recognizable private keys, common tokens and credential assignments are refused without storing their content. Pattern detection cannot recognize every possible unlabelled secret: use narrow roots/extensions, path exclusions, and metadata-only policy for confidential trees.

Unchanged stat signatures (device, inode, size, nanosecond mtime/ctime, mode and link count) preserve existing indexed text without rereading. Renames are treated conservatively as a newly observed path; the old path remains unverified. The catalog is not a filesystem snapshot: concurrent directory mutations can change enumeration order. Files not observed in a newer generation remain explicitly unverified, never tombstoned or inferred deleted. Last-observed text can still match search for an unverified path; callers must show freshness. An observed read/inspection error removes that path's search text.

Directory entries are consumed individually using `opendir`, never loaded into an unbounded array. Queue progress and enumeration offsets persist. On restart, rebuilding an iterator skips its saved offset in bounded work units; this adds work for large directories. Enumeration has an explicit per-directory cap, recorded as incomplete coverage. Batches stop between work units at their time/entry budget; synchronous filesystem calls themselves cannot be interrupted, so an unresponsive filesystem can exceed the time budget. Errors and historical coverage grow with scan generations; plan private database storage accordingly.

Run focused checks with:

```sh
node --test scripts/test-host-file-catalog.mjs
```
