# M4 V2 Observation Reader v1

`readM4V2Observation` is a one-row migration boundary. It accepts one strict
mapped v2 catalog row, its encrypted client envelope, and caller-owned key and
authorization dependencies. It returns only the observation wrapper consumed
by the M4 v2 conversation projector.

The reader validates the exact catalog metadata and projection, then preflights
the production ciphertext format, declared envelope/projection binding, key
authorization, and canonical base64 before any binding or audit callback. The
catalog content and payload digests must match the envelope. The injected
binding verifier receives the opaque catalog owner/source tags and the declared
envelope actor/source identities only. A durable decrypt audit acknowledgement
is required immediately before decryption; AES-GCM AAD and tag authentication
occur during that decryption step.

Catalog logical-message canonicalization may select either the signed transport
projection's primary logical ID or one of its signed logical ID aliases. The
reader decrypts against the untouched transport projection, then returns a
separate safe projection clone whose key version and logical ID are the
accepted catalog entry. Its aliases are rebuilt from every other signed entry,
including the former primary, in deterministic order. An unrelated catalog
logical ID is rejected before callbacks.

The returned wrapper has only `eventId`, `sessionId`, `sourceTag`,
`migrationSequence`, `projection`, and `visibleText`. `visibleText` is emitted
only for supported user/inbound or assistant/outbound text conversations.
Authoritative deletions and non-conversation observations are authenticated and
then return `null`. Eligible text is complete, never truncated, and is bounded
to 65,536 code points and 262,144 UTF-8 bytes. Text parts are exact text,
input_text, or output_text parts, with at most 100 parts.

The reader does not return encrypted envelopes, raw records, plaintext objects,
catalog content IDs, owner tags, actor/source identities, paths, or payloads.
Errors use fixed content-free codes. It performs no catalog query, filesystem
access, checkpointing, replay, backfill, cutover, deletion, deployment, or live
operation. The caller owns injected keys and callbacks.

This pure boundary alone satisfies no M4 roadmap checkbox. Concrete catalog
enumeration, durable replay coordination, reconciliation, and controlled live
evidence remain separate work.
