# M4 preserved unified-index bridge v1

`prepareM4PreservedUnifiedIndex` is the Fabric-owned boundary between the
preserved raw-queue plugin and the M4 unified logical-group source. It does not
create an archive, cut over a queue, recover a queue, or read live state.

## Injected dependencies

The caller supplies a Fabric group-replay authority, a preserved queue reader,
a preserved observation decoder, and the migration source tag. The reader owns
the queue format and pause binding. The decoder owns envelope decoding and
projection construction. Fabric snapshots the reader methods and obtains the
reader authority once before any queue is opened.

The returned value contains only two unified index attestations and their
materializers:

- `preserved-outbox`
- `preserved-deadletter`

Each attestation is exactly `amf.m4-unified-logical-index/v1`, has
`complete: true`, and maps `recordDigest` directly from the reader's
`envelopeDigest`. Projection variants are copied as bounded,
logical-message-id-sorted digest pairs. The bridge enforces one million total
entries, 512 GiB total caller ciphertext, and 128 variants per entry; callers
may lower the first two bounds.

## Enumeration binding

For both source kinds, the bridge calls `reader.open` with the exact
pause-checkpoint and interval returned by `reader.authority()`. It consumes the
entire iterator, then validates the completion schema, source kind, pause
checkpoint, end position, and chain against that same snapshot. Iterator close
errors never replace a primary error.

Every yielded ciphertext buffer is caller-owned. The bridge wipes it in a
`finally` block whether indexing succeeds, the decoder fails, a bound fails,
or validation fails. Indexes and error codes contain no plaintext or
ciphertext; materializers return the M4-approved minimal observation only.

## Materializers

Each materializer reopens exactly one indexed position through
`reader.openPositions`, using the captured pause binding. Before decoder
materialization it checks the reopened `legacyEventId` and `envelopeDigest`
against the locator's event id and record digest. It validates completion and
wipes the reopened ciphertext in all paths. The decoder receives only the
Fabric authority plus raw record and a minimal request:
`logicalMessageId`, configured `sourceTag`, and `migrationSequence`.

The bridge returns only the M4 minimal observation shape:
`eventId`, `sessionId`, `sourceTag`, `migrationSequence`, `projection`, and
`visibleText`.

## Verification

Run the synthetic contract suite:

```sh
node --test scripts/test-m4-preserved-unified-index.mjs
```

To run the optional real-adapter path through the unified source and delivery
test, point `AMF_RAW_ADAPTER_PATH` at a raw-adapter checkout:

```sh
AMF_RAW_ADAPTER_PATH=/path/to/mem0-scoped-agent-plugin node --test scripts/test-m4-unified-logical-group-source.mjs
```
