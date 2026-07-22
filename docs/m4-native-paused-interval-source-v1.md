# M4 native paused-interval source v1

`createM4NativePausedIntervalSource` is a pure injected M4 coordinator source
for phase `paused-native`. It has no filesystem, network, archive, outbox
replay, cutover, or cleanup dependency.

Its exact authority document is:

```json
{
  "schema": "amf.m4-native-paused-interval-authority/v1",
  "pauseEvidence": { "manifestId": "…", "digest": "sha256:…", "signature": "…" },
  "source": { "id": "…", "digest": "sha256:…" },
  "sourceBinding": "hmac-sha256:source-v1:…",
  "interval": {
    "startExclusive": 41,
    "endInclusive": 99,
    "chain": { "id": "…", "digest": "sha256:…" }
  },
  "initialCheckpoint": { "id": "…", "digest": "sha256:…" }
}
```

Before opening a reader, `verifyPauseEvidence` must return exactly the signed
pause evidence, `nativeTranscriptAuthority`, and `sourceCheckpoint`. They must
match the authority's pause evidence, source, and initial checkpoint. This is
not a legacy cursor. `sourceBinding` is a key-derived opaque binding for the
reader's runtime/source identifier.

The injected reader receives `{schema, source, interval}` and returns an exact
`amf.m4-native-paused-reader/v1` wrapper. The wrapper reaffirms source,
interval, chain, runtime, and source ID before records are accepted. Its
completion callable is invoked only at natural exhaustion and must attest the
exact source, end-inclusive position, and chain; a missing or mismatched
attestation fails closed. A callable prevents an unobserved rejection when a
bounded source exits early.

Records are strictly ascending `{native, value, sessionHint}` entries. Native
metadata contains runtime, source and message identifiers, `position`, and a
validated source timestamp. Native session/message IDs must exactly equal the
Codex or Claude fields that the existing filters use. The accepted slice is
`(startExclusive, endInclusive]`; system, tool, reasoning, empty, and malformed
records are excluded.

Public IDs, tags, and checkpoints are deterministic opaque values derived from
the injected 32-byte key and canonical native-ID tuples. They never derive from
text, paths, or timestamps. `occurredAt` is the validated native source
timestamp, so delivery-envelope `sentAt` and nonce do not affect payload
digests. Checkpoints contain only opaque values.

The source emits at most `maxEvents + 1` rows for the coordinator completion
probe. Per source and per batch, it visits at most
`M4_NATIVE_PAUSED_MAX_VISITED_RECORDS` (10,000) while filtering or locating a
resume checkpoint, then fails closed. Later composite/operator work can shard
sources when a paused interval is larger. It closes the iterator on bound exit
and every error. If closing is the only failure, it fails content-free as
`m4_native_paused_reader_close_failed`; an earlier source failure remains
authoritative.

Repeated native identities use a semantic digest that excludes only transport
integrity and source position/order, while retaining the validated source
timestamp and all normalized event semantics. Exact semantic repeats are
skipped; changed text or timestamp fails closed as
`m4_native_paused_duplicate_conflict`. Visible conflict materialization belongs
to the later replay/archive slice.
