# Session Context Capsule v1

`SessionContextCapsule` is a bounded, derived retrieval projection used with
Capability MCP v2 `context_recall`. It is not a transcript, memory record,
provider result, ledger item, or PAM task-state object. The executable
conformance manifest is
`config/contracts/amf.session-context-capsule-v1.schema.json`.

## Boundary, adapter mapping, and authorization

`manual_recall`, `automatic_notice`, and `explicit_expand` are private adapter
modes in this projection contract. They are not public MCP tools or standalone
public requests. The only public surface remains Capability MCP v2's five
tools. The adapter maps manual recall to `search(delivery="results")`, automatic
notice to `search(delivery="notice")`, and explicit expansion to
`read(id=<rid_*>)`. Search defaults to `delivery="results"` when omitted.

Every private adapter request carries v2 `ScopeRef[]` values and purpose
`context_recall`. Scope identity is `(tenantId, scopeId)`; `type` is descriptive
only. The capsule layer reauthorizes the current grant before it returns a
capsule, emits a notice, or expands a reference. A revoked, absent, expired,
scope-mismatched, or unauthorized capsule/expansion returns the same
non-disclosing `not_found` result through the mapped MCP operation.

Internal capsule IDs and snippet references are bounded opaque identifiers.
Every public capsule or expansion reference uses the existing MCP `rid_*`
resource-reference scheme. An expansion reference binds its capsule, ScopeRef
identity set, purpose, current grant, expiry, and redaction policy. It cannot
be used as a generic transcript locator or across a changed
scope/purpose/grant. The private adapter maps bounded capsule and excerpt
projections into the normal MCP search/read resource envelope; it never exposes
the private mode request or introduces a sixth tool.

## Derived capsule

A capsule contains only bounded, redacted snippets and safe metadata:
provenance, observation time, freshness/expiry state, relevance and overlap,
contradiction state, and supersession state. It never includes raw transcript
objects, messages, participant identities, providers, locators, task records,
or PAM/ledger state. `stale`, `present`, and `superseded` states remain visible
when a capsule is admitted; they are never silently upgraded or resolved.
Expired capsules are not admitted.

Manual recall returns at most ten capsules, each with at most three snippets of
at most 512 characters. An explicit expansion returns at most five redacted
excerpt items of at most 1024 characters. Expansion is a separately authorized
read; it does not return a raw or complete transcript.

## Notice-only automatic awareness

Automatic awareness uses `search(delivery="notice")` and produces only a
`notice_only` response after current-grant
reauthorization. Its bounded candidate count includes authorized, admitted,
non-expired capsules only. A denied or revoked notice returns the same
`not_found` shape as no authorized match. A notice returns no capsule IDs,
snippets, excerpts, transcript content, provenance payload, or automatic
prompt injection. A client must make a separate
`search(delivery="results")` and, if needed, a separate authorized
`read(id=<rid_*>)` expansion request.

No automatic behavior writes PAM, a management ledger, canonical memory, or
any source transcript. This contract specifies a projection boundary only and
does not claim a runtime hook or deployment.
