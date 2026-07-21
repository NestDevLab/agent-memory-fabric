# V3 migration safety v1

## Manifest and gates

The versioned migration manifest is declarative evidence, not an execution
recipe. It contains no filesystem paths, globs, shell commands, or data copies.
Each signed manifest contains exactly one phase body: `pause`, `rollback`,
`reconciliation`, or `cleanup`; other phase bodies are forbidden. A migration
pause reports `paused`, never healthy.

## Pause and rollback

Pause evidence preserves collector cursors, pending outboxes,
acknowledgements, dead letters, source checkpoints, and native transcript
authority. Each is identified and digested; pause evidence is signed.

The pause generator accepts one strict, content-free aggregate checkpoint file:

```json
{
  "schema": "amf.migration-pause-checkpoints/v1",
  "manifestId": "pause-manifest-example",
  "revision": 1,
  "keyId": "migration-key-example",
  "pause": {
    "state": "paused",
    "collectorCursor": { "id": "collector-cursor-example", "digest": "sha256:<64 lowercase hex characters>" },
    "pendingOutbox": { "id": "pending-outbox-example", "digest": "sha256:<64 lowercase hex characters>" },
    "acknowledgements": { "id": "acknowledgements-example", "digest": "sha256:<64 lowercase hex characters>" },
    "deadLetters": { "id": "dead-letters-example", "digest": "sha256:<64 lowercase hex characters>" },
    "sourceCheckpoint": { "id": "source-checkpoint-example", "digest": "sha256:<64 lowercase hex characters>" },
    "nativeTranscriptAuthority": { "id": "native-authority-example", "digest": "sha256:<64 lowercase hex characters>" },
    "evidence": { "id": "pause-evidence-example", "digest": "sha256:<64 lowercase hex characters>" }
  }
}
```

Unknown fields, non-pause phase bodies, and path-like or command-like fields are
not accepted. The HMAC key is supplied only through an explicit owner-only
regular file with this shape:

```json
{
  "schema": "amf.migration-signing-key/v1",
  "keyId": "migration-key-example",
  "key": "<canonical base64 encoding of 32 to 64 random bytes>"
}
```

Before the pause, deployment configuration records an owner-only roster with the
stable opaque collector IDs reported by every enabled collector. The roster is
authoritative; it is not inferred from the checkpoint files supplied during the
pause. It uses schema `amf.migration-pause-collector-roster/v1` and binds the
manifest identifier, revision, signing-key identifier, and a sorted unique list
of `pause-collector-<64 lowercase hex characters>` identifiers.

Combine every per-collector checkpoint into one deterministic checkpoint set.
The command requires exact equality with the roster, rejects mixed metadata and
duplicate collector IDs even when their state digests differ, and binds each
collector ID, child evidence digest, and checkpoint category into
domain-separated aggregate digests. The aggregate uses a `pause-set-` evidence
identifier so a raw per-collector checkpoint cannot enter the signing path. The
output contains no collector name or input path.

```sh
npm run operator:migration-pause -- aggregate \
  --roster /absolute/collector-roster.json \
  --input /absolute/collector-a.json \
  --input /absolute/collector-b.json \
  --output /absolute/checkpoints.json
```

Generation recomputes the aggregate from the retained roster and child
checkpoints before signing. It creates an owner-only manifest atomically and
refuses to replace an existing target. The ordinary `verify` operation checks
the manifest signature for the runtime fence. The `verify-set` operation also
recomputes exact collector membership and checkpoint state for M2 acceptance.
All paths must be absolute and verification is read-only:

```sh
npm run operator:migration-pause -- generate \
  --input /absolute/checkpoints.json \
  --roster /absolute/collector-roster.json \
  --checkpoint /absolute/collector-a.json \
  --checkpoint /absolute/collector-b.json \
  --key-file /absolute/key.json \
  --output /absolute/pause-manifest.json
npm run operator:migration-pause -- verify --manifest /absolute/pause-manifest.json --key-file /absolute/key.json
npm run operator:migration-pause -- verify-set \
  --manifest /absolute/pause-manifest.json \
  --roster /absolute/collector-roster.json \
  --input /absolute/collector-a.json \
  --input /absolute/collector-b.json \
  --key-file /absolute/key.json
```

The tool emits only bounded identifiers and state; it never prints key material
or checkpoint digests. Retain the private roster and every child checkpoint with
the signed manifest so exact set verification remains reproducible.

Rollback references signed pause evidence and names immutable source and target
checkpoints, a compatibility-route revision, and a recovery-copy identifier and
digest with restore-test state.
Rollback never destroys either archive. A failed or absent restore test blocks
rollback readiness.

## Reconciliation and cutover

Reconciliation references signed pause and rollback readiness evidence. It
records counts, stable IDs, payload and logical digests, time ranges, edits,
replacements, tombstones, conflicts, the paused interval, replay queues, and
source checkpoints in one checkpoint-and-digest binding. A complete record has
`completeness=1` and `unresolvedMismatchCount=0`; tolerance is reporting only.
Any mismatch blocks cutover. A pending reconciliation is valid evidence but is
not cutover-ready.

## Cleanup boundary

Cleanup names exact legacy object identifiers and digests only: no wildcard or
range target is valid. Its own body references a complete reconciliation
manifest, signed catalog-unreferenced proof, a passed cutover canary, and one
recovery copy with a passed restore test.
Destructive execution is separately explicitly approved and is not implemented
by this contract.

## Manifest integrity

The `payloadDigest` is `sha256:` plus the lowercase SHA-256 of canonical JSON
for the complete manifest with `integrity` omitted. The signature is
HMAC-SHA-256 over the domain-separated canonical JSON tuple
`["amf.migration-manifest/v1/integrity", payloadDigest, keyId]`, encoded as
unpadded base64url. Verifiers authenticate the referenced key ID and reject a
digest or signature mismatch before accepting phase evidence.

## Verification

Conformance fixtures cover ready evidence and blocked states. The contract test
checks signatures, digests, phase coverage, semantic gate ordering, exact
cleanup targets, and the no-path/no-command manifest boundary.

## Runtime pause fence

RAW ingest remains active by default. To activate the central fence, configure
both `AMF_MIGRATION_PAUSE_MANIFEST_PATH` and
`AMF_MIGRATION_PAUSE_KEY_PATH` with absolute paths to owner-only files. A
missing pair, unsafe file, malformed key, invalid manifest, digest mismatch, or
signature mismatch prevents server startup.

After successful verification, `POST /v2/ingest/raw-events` returns the bounded
`migration_paused` error before request-body parsing, decryption, storage, or
audit mutation. Read and status routes remain available. Status reports RAW
ingest as verified, `paused`, and `degraded`, with only the manifest identifier
and revision. Health monitoring propagates that verified state to collector
checks, so an intentionally inactive collector is degraded rather than healthy
or critically inactive. Unverified pause-shaped data never suppresses a
collector failure.
