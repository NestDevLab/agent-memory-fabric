# Recall consumer provisioning

`scripts/amf-provision-recall-consumer.mjs` provisions the dedicated Vitae recall consumer. It is
separate from RAW ingestion and cannot create a collector, ingest key, cursor, lease, proposal or
decrypt capability.

The contract is fixed and versioned:

- actor: `agent:vitae`;
- mode: `read_only_scoped`;
- permissions: `memory:search`, `memory:read`, `sessions:read`,
  `purpose:conversation_recall`;
- scopes: `agent:vitae`, `person:joseph`, `relationship:vitae:joseph`,
  `room:vitae:joseph-dm`;
- dedicated context signing key version: `ctx-vitae-v1`.
- exact delegated RAW session owner: `ct110-hermes-vitae`.

The operator supplies private regular files for the local auth registry, policy and server context
key ring. Existing context keys and the server's current signing version remain unchanged; the
provisioner appends `ctx-vitae-v1`. The private handoff contains only the new bearer, a single-key
consumer context ring and a non-secret manifest. The server auth registry stores only the bearer
SHA-256 digest. Its `sessionOwnerActors` and `contextKeyVersions` arrays are fixed and cannot be
supplied through the CLI. The delegated owner must already be an active, non-delegating RAW ingest
actor in the registry. No RAW key is read or written.

The provisioned consumer can use a non-empty `sessions_search.query` to match
normalized user/assistant text after exact room context authorization, and can
pass the same optional `query` to the redacted transcript request. Search is
bounded to the newest 256 events per candidate session; older events remain
available through ordinary transcript pagination but are outside one text-search
window unless a signed time window selects them. Candidate scanning continues
through server-MACed keyset cursors in bounded 64-session pages. The context
signs the canonical route scopes, which the Fabric checks against the provisioned
allowlist and an independently provisioned, HMAC-signed session-route manifest. The manifest binds
the authenticated actor, conversation kind and exact canonical room scope to the complete opaque
context-tag map. A token for another room cannot self-assert an allowed scope. For REST GET session/transcript calls, deliver the context token only
through `X-AMF-Context-Token`; the dedicated Vitae key rejects query-string tokens.

An operator may repeat `--scope` to add exact canonical `room:`, `person:` or `relationship:`
scopes needed by an approved group/topic context. Extras are sorted, unique, bounded to 32 and
included in the manifest `scopeSetSha256`; wildcard, `agent:`, `domain:` and `shared:` additions are
rejected. Native room/person identifiers must be resolved to canonical scope names before this step
and must not be committed to source.

The backup root and handoff parent must already exist with mode `0700`. Inputs must be regular,
single-link, non-symlink files owned by root or the service owner with no group/other permissions.
Live provisioning requires root. The transaction uses an exclusive lock, byte-for-byte backups,
prepared replacements, Linux directory descriptors pinned through `/proc/self/fd`, directory
fsyncs and rollback; a persistent parent-path swap aborts without writing the replacement tree.
A rollback failure preserves the lock for manual recovery.

Run the zero-write preflight first:

```bash
node scripts/amf-provision-recall-consumer.mjs \
  --auth-registry /private/auth-registry.json \
  --policy /private/policies.json \
  --context-key-ring /private/context-key-ring.json \
  --handoff /private/handoffs/vitae-recall \
  --backup-root /private/backups \
  --backend-user-id openmemory \
  --service-owner-uid 1000 \
  --scope room:vitae:approved-group-topic \
  --scope person:approved-participant \
  --scope relationship:vitae:approved-participant \
  --dry-run
```

The dry-run performs complete validation without a lock, random generation, backup, temporary file
or handoff write. Run the same command as root without `--dry-run` only after reviewing its safe
metadata output. Do not pass secrets on the command line.

Provision the signed route separately from a private `0600` input. The input has schema
`amf.session-route-input/v1` and contains `bindings` with exactly `actor`, `canonicalScope`,
`conversationKind` and `contextTags`. Context tags must already be opaque HMAC tags; literal native
identifiers are rejected. The current context-ring key signs every binding.

```bash
node scripts/amf-provision-session-routes.mjs \
  --input /private/vitae-session-routes.input.json \
  --context-key-ring /private/context-key-ring.json \
  --manifest /private/session-routes/session-route-manifest.json \
  --service-owner-uid 1000 \
  --dry-run
```

Review the metadata-only output, then run the same command as root without `--dry-run`. The tool
pins private parent directories through `/proc/self/fd`, verifies existing signatures, rejects
duplicate route identities, and reports dry-run results as a read-only snapshot. A live run takes
the exclusive lock before reading or merging the current manifest, then rechecks its inode and
SHA-256 digest both before preparation and immediately before publication. It writes a timestamped
`0600` backup on update and atomically replaces and fsyncs the manifest. Initial creation uses an
atomic no-replace link and fails closed if a target appears concurrently. A concurrent cooperative
writer receives `session_route_lock_held` and must
retry, at which point it merges the newly committed routes. The tool never prints keys or opaque tags. Mount the
whole manifest directory at `/run/amf-session-routes`; it must be owned by the service UID with
mode `0700`, while the manifest must be owned by root or the service UID with mode `0600`.

Rollback restores all three server files from the reported backup directory while the service is
stopped, then removes the handoff. Never copy its bearer or context key into logs or source control.
