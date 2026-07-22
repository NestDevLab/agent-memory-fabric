# M4 cutover canary v1

`amf.m4-cutover-canary/v1` is an independent signed, content-free evidence
record. It is not a new phase of `amf.migration-manifest/v1`.

The signed policy fixes a UTC observation window, maximum sample count, queue
depth and age ceilings, latency ceilings, the permitted HTTP 5xx count, and an
exact list of failure categories that must remain zero. Supplied aggregate
observations bind their own nanosecond-safe subwindow and include a configuration
rollback drill with two distinct checkpoints.

State is derived rather than accepted from the caller. Evidence is `passed`
only when all samples remain within the signed bounds, all required failure
categories are zero, and the rollback drill passed. Threshold failures and a
failed rollback drill produce signed `failed` evidence for audit.

The module does not collect metrics, read content, scrape services, switch
routes, authorize cleanup, or mutate live state.
