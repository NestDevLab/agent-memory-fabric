# Scope substrate v1

The substrate supplies stable scope references for cataloging and routing. It
does not implement role-based access control.

## ScopeRef

```json
{
  "tenantId": "<tenant-id>",
  "type": "<descriptive-type>",
  "scopeId": "<scope-id>"
}
```

The identity of a scope is `(tenantId, scopeId)`. `type` describes the scope
and is not part of its identity or, by itself, an authorization decision.
Implementations must reject missing or non-canonical identity fields rather
than silently normalizing them.

## Relations and orthogonal data

- Optional hierarchy relations may connect scopes. A relation is metadata, not
  an inherited grant.
- A scope may have N:M memberships with resources. Every relation and
  membership carries provenance with a source, required assertion, and observed
  time. Membership
  describes association and never grants access.
- Subjects, roles, policies, grants, tags, domains, and routes remain
  orthogonal concepts. References between them must be explicit.
- v1 has no RBAC engine. Authorization remains the responsibility of the
  owning policy/AMF boundary.

## Compatibility and migration

Existing v1 scope behavior is preserved. A legacy identifier may be retained
only when an explicit, reviewed mapping supplies the target `ScopeRef`.
Migration must not infer identity, hierarchy, membership, role, or grant from
names, prefixes, paths, or historical usage. Unknown or ambiguous mappings
fail closed and remain unresolved until an owner supplies evidence.

## Contract validation

The published JSON Schema rejects missing provenance assertions and malformed
objects. The conformance validator applies the schema and then rejects duplicate
logical scope identities with competing types, cross-tenant relations,
cross-tenant memberships, and references to unknown scopes. These cross-row
rules are explicit contract validation, rather than inferred hierarchy or grant
logic.
