# Private host administration

This optional host-local AMF component inventories files using the host catalog,
serves read-only administrative JSON, and composes independent capture and memory
quality evidence. It requires Node.js 24 and Linux. It does not promote files into
canonical memories, move files, replay dead letters or mutate remote AMF policy.

The catalog, editorial documents and curated memories are separate stores. A file
inventory is not proof that its contents were acquired, delivered to a document
vault, selected for curation or retrieved correctly in another session.

## Configuration

Supply `--config /absolute/private/config.json` to `scripts/amf-host-admin.mjs`.
Configuration, policy, bearer and optional quality report must be owner-held regular
files with mode 0600 in private 0700 directories. Symlinks are rejected. Example
values below are placeholders; host topology belongs in private deployment config.

```json
{
  "schema": "amf.host-admin-config/v1",
  "bind": "127.0.0.1",
  "port": 18776,
  "policyPath": "/srv/example-private/catalog-policy.json",
  "databasePath": "/srv/example-private/catalog/catalog.sqlite",
  "tokenFile": "/srv/example-private/admin.token",
  "scanIntervalMs": 1000,
  "scanBudgetMs": 1000,
  "scanMaxEntries": 5000,
  "rescanIntervalMs": 3600000,
  "healthProbe": {
    "command": "/usr/local/bin/node",
    "args": ["/srv/example/skills/agent-memory-health/scripts/amf-health.mjs", "--config", "/srv/example-private/health.json", "--json"],
    "intervalMs": 60000,
    "timeoutMs": 120000
  },
  "qualityReportPath": "/srv/example-private/quality.json"
}
```

The first generation resumes in bounded batches. A completed generation is stable
until `rescanIntervalMs`. A stopped/killed process releases SQLite's native lock;
another owner can resume committed traversal state. File operations on a blocked
filesystem can outlast a batch budget. Exclude external mounts explicitly rather
than claiming host-local coverage of unknown remote storage.

## Administrative API

Every request needs `Authorization: Bearer <host-administration credential>`.
Load the credential directly from its protected process binding; never put it in
arguments, URLs, browser storage, plans or logs. Only loopback is supported.

| GET endpoint | Result |
| --- | --- |
| `/v1/status` | Catalog coverage/freshness, capture report and quality evidence |
| `/v1/files?query=&domain=&limit=50&offset=0` | Metadata and acquisition state; no file body |
| `/v1/suggestions?limit=50` | Evidence-backed review candidates; no apply operation |

Empty domain filters should be omitted. Queries are bounded, duplicates/unknown
parameters are rejected, and all write methods are denied. Responses use no-store.
The service does not expose arbitrary filesystem paths as read commands.

Oikuma connects server-to-server to this fixed origin and holds the bearer only on
its backend. Each Oikuma request must check an explicitly configured platform
administrator and current application ownership, including a second check after
the upstream read. Hiding a navigation entry is not authorization. No CORS, public
listener, anonymous route, arbitrary proxy or browser-held credential is required.

## Evidence and quality

An absent, malformed, failed or stale probe is unknown. Health reports expire after
five minutes. Disabled collectors remain visible and are neutral only when their
capture paths are independently verified inactive. `critical` takes precedence;
incomplete scans, collection errors, unknown quality or unverified old entries keep
the overall state degraded.

An optional `amf.memory-quality-report/v1` contains `generatedAt`, `overall` and
`checks` (`id`, `status`, finite numeric `metric`, `unit`, `summary`). Include only
aggregate evidence, never records, source bodies, secrets or user conversations.
Quality expires after one day. Suggested independent checks:

- Canonical coverage, age, provenance and lifecycle consistency.
- Positive retrieval cases with known expected records and relevant ordering.
- Absent-fact cases; distinguish lexical and semantic candidate behavior.
- ACL and revocation negatives through actual scoped consumers.
- Document delivery queues, extraction failures and current corpus coverage.
- Fresh-session recall, latency distribution and bounded resource use.

Positive hits alone do not prove precision; good local tests do not prove the live
service uses that source revision. Semantic distance thresholds need calibration
against representative positives and negatives. Curation follows the existing
proposal/review/apply lifecycle; do not turn catalog discovery into automatic fact
acceptance. Reorganization suggestions require a separate explicit apply workflow.
