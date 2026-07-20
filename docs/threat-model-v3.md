# V3 threat model

## Scope and protected layers

The model covers the native source, signed outbox, transport, archive, catalog,
MCP boundary, proposal and canonical memory layers, document layer, and operator
boundary. Native source remains the transcript authority. Raw tool payloads,
reasoning content, and other excluded raw content are not admitted to recall or
canonical memory merely because they are observable at a source.

## Controls and verification

| Risk | Control and verification evidence | Decision |
| --- | --- | --- |
| Plaintext at rest | Plaintext is the default; owner and access controls, scoped authorization, audit, and restore tests remain mandatory. | Fail closed for unauthorized access. |
| Optional encryption | AES encryption and key rotation are policy-driven, explicit choices; visibility never implies encryption policy. Compress before encryption when both are selected. | Fail closed on declared encryption failure. |
| Authorization and scope | Purpose-bound authorization is checked at source, MCP, proposal, canonical, and document boundaries. Denied probes do not reveal content. | Fail closed. |
| Integrity and replay | Signed outbox envelopes bind digest, key ID, and nonce. Transport requires authenticated HTTPS/TLS plus replay-window and nonce verification; duplicate stable ID plus digest is a retry, changed payload is a conflict. Signature and tamper tests provide evidence. | Fail closed. |
| Audit outage | Mutations requiring durable audit, including conflict resolution, stop when audit cannot append. | Fail closed. |
| Conflict suppression | Unresolved conflicts are quarantined from recall, extraction, retention deletion, and canonical promotion; operators see content-free metadata and digests. | Fail closed. |
| Provider ambiguity | Provider identity and route revision are explicit; fallback cannot silently change semantic ownership. | Fail closed. |
| Backup and recovery | Immutable checkpoints, recovery-copy digests, and restore-test state gate rollback and cleanup. | Fail closed. |
| Minimization | Each layer stores only its declared purpose data; proposal and document layers retain provenance and scope. | Fail closed for out-of-scope content. |

## Residual risks

Authorized operators can still make manual resolution mistakes. Plaintext can
leak through host access and recovery copies; owner, access, and backup policy
control that residual risk. Append-only evidence,
expected-revision guards, acknowledgement-gated notification, bounded retries,
and recovery testing limit impact but do not remove these risks. Availability may
fail open only for read-free health reporting; writes, promotion, destructive
cleanup, and conflict resolution never fail open.
