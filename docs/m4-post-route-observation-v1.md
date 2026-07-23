# M4 post-route observation v1

This module creates and verifies `amf.m4-post-route-observation/v1`: signed,
content-free evidence for a route that is already active. Its exact signed fields
are `schema`, `manifestId`, `revision`, derived `state`, derived
`requiresRollback`, `routeExecution`, `policy`, `observations`, and `integrity`.

The order is shadow canary, cutover authorization, route executor, then active
post-route observation. `routeExecution` binds the R1 execution ID/revision,
R1 integrity payload digest, authorization evidence, target route revisions,
post-change digest, and the integrity-bound `readinessState: passed`.

The policy has a strict UTC, nanosecond-safe start/end window of at most 24 hours,
one to 10,000 samples, queue and latency ceilings, an allowed 5xx ceiling, and
the exact ordered M4 canary failure categories. Observations must remain within
that window, be strictly increasing, and satisfy valid latency ordering. Equal
thresholds pass; any exceeded ceiling or nonzero required category derives
`state: failed` and `requiresRollback: true`.

Integrity is a domain-separated HMAC-SHA256 over canonical JSON using an
`amf.migration-signing-key/v1` key. Verification rejects malformed shapes,
unsafe numbers, invalid timestamps, noncanonical key material, digest drift,
and signature/key mismatch with fixed, content-free errors. Neither API accepts
paths, service/topology data, configuration bytes, nor content.

A failed observation is evidence that rollback is required. Rollback remains a
separately confirmed executor action: this module never executes rollback or
cleanup, and it does not authorize either operation.
