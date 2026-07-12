# RAW collector provisioning

`scripts/amf-provision-raw-collector.mjs` provisions one least-privilege RAW
collector identity and a private client handoff. It never accepts a bearer or
cryptographic key on the command line and never emits one to stdout or stderr.

The operator supplies private, regular, non-symlink files for the auth registry,
production policy, ingest key ring, and routing key ring. All must have no
group/other permissions. The backup root and handoff parent must already exist
with mode `0700`. Live provisioning requires effective UID `0` so it can always
preserve the existing owner and group of bind-mounted files. A dry-run may run
as the explicit service owner and is strictly read-only: it creates no lock,
backup, staging path, handoff, key material, or other filesystem write.

```bash
node scripts/amf-provision-raw-collector.mjs \
  --auth-registry /private/auth-registry.json \
  --policy /private/policy.json \
  --ingest-key-ring /private/ingest-key-ring.json \
  --routing-key-ring /private/routing-key-ring.json \
  --actor ct110-hermes-vitae \
  --source-instance ct110-hermes-vitae \
  --key-id ct110-hermes-vitae-v1 \
  --handoff /private/handoffs/ct110-hermes-vitae-v1 \
  --backup-root /private/backups \
  --service-owner-uid 1000 \
  --dry-run
```

Remove `--dry-run` only after reviewing the safe metadata result. The committed
actor is always active, `scoped` to `agent:<actor>`, and has exactly
`memory:status` plus `raw:ingest`. The server stores only the SHA-256 bearer
digest. The handoff directory and every contained file are private; it contains
the generated bearer, the actor-bound ingest key, shared digest/logical/routing
material, independent client-only cursor and lease keys, and a non-secret
manifest.

Provisioning fails if any existing authorization contains the actor or source
instance, or if the key id, policy entry, handoff, or lock already exists. This
CLI intentionally has no rotation mode: safely
rotating a live collector must preserve its bearer and client-side cursor,
lease, and outbox access while carrying both old and new ingest keys. Add that
only with a separately reviewed migration contract and old-handoff input that
never places secrets in argv.

Before changing anything, the CLI validates every current document and checks
that all ingest, digest, logical, and routing master keys are 32-byte and
mutually distinct. It creates a durable backup, stages private files, then
replaces the ingest ring and policy before activating the bearer in the auth
registry. Each file replacement is temp-file + fsync + atomic rename while
preserving the original owner, group, and mode. A handled failure restores the
original bytes and removes the handoff; the backup remains as recovery evidence.
Every input path component must be owned by root or the explicit service owner
UID and must not be a symlink. Input files must have exactly one hard link and
are opened with `O_NOFOLLOW`; even a root operator cannot bypass these checks.

The lock is `<auth-registry>.collector-provision.lock`. A surviving lock means
the process did not complete its normal cleanup. Stop and review the backup,
staging paths, and all three server documents before removing it; do not retry
or edit the JSON files ad hoc. A failed rollback deliberately preserves this
lock so partial state cannot be retried as if it were clean.

Production currently bind-mounts registry/key files individually into the
container. After an atomic host-side replacement, recreate the container so the
bind mounts resolve the new inodes; a plain process or container restart is not
a substitute. Verify authenticated status and an actor/source/key negative test
before transferring or activating the handoff.
