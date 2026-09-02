# Session capsule ranking v1

`session-capsule-ranking/v1` is a private, source-only implementation of the
Capability MCP v2 `capability-mcp-v2-rank/v2` ordering. It accepts only
already-authorized capsule envelopes and never calls a provider, broadens
authorization, reads a transcript, or exposes provider/native scores.

Each envelope has an opaque `rid_*` resource ID, bounded `redactedText` and
bounded `anchors`, explicit B1-domain `authorityClass`, explicit canonical UTC
`recencyAt`, optional `freshnessAt`, and optional `expiresAt`. Missing
`freshnessAt` is the explicit `unknown` freshness bucket. Authority and
recency are never inferred from public capsule provenance or text. Future
freshness or recency timestamps reject that candidate; an expiry at or before
`rankedAt` excludes it.

The normalized query must be non-empty and at most 512 code points. Exact
admission requires equality with an explicit normalized anchor; lexical and
bounded fuzzy lanes use only normalized bounded redacted text and anchors.
Lexical tokens retain up to 512 code points. The fuzzy evaluator separately
compares Unicode code points, considers at most 4,096 deterministic
comparisons, and never reads beyond 48 code points per token. The vector lane accepts only an
injected ordered list of opaque resource IDs: it accepts no vector score.
Unknown vector IDs are ignored and repeated vector IDs retain their first
position. Only the union of these four lanes is ranked; every resource is
deduplicated by opaque ID before ranking.

The deterministic comparator is exact anchor, authority class, freshness,
reciprocal-rank fusion over lane positions with `k=60`, recency, then opaque
resource ID. Freshness uses whole non-negative seconds: current (0..86400),
recent (86401..604800), aged (604801..2592000), then old. UTC timestamps accept
only canonical second (`...:ssZ`) or millisecond (`...:ss.sssZ`) forms, which
normalize to the same instant. Opaque ID ties use ASCII byte-order, not locale
collation. Output contains only `id`, one-based `position`, and one to five
reasons from the frozen enum `exact_anchor`, `authority`, `freshness`,
`hybrid_similarity`, and `recency`; lexical, fuzzy, and vector membership is
reported only as `hybrid_similarity`. It contains neither authority/freshness
classes nor ordinals, text, timestamps, lane positions, or native/vector
scores.
