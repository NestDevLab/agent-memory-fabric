# Scope migration v1

This contract defines a deterministic, no-write inventory and plan for legacy
scope values. It is a planning boundary only: it does not create scopes, change
policies, write data, revoke grants, or reissue credentials.

## Inputs and output

The conformance manifest contains a declared canonical catalogue, an inventory
of opaque source references and legacy values, and one plan row for every
inventory row. Its `mode` is always `dry-run` and `writeOperations` is always
an empty array. Each inventory row declares one of `scope`, `grant`, `bundle`,
`record`, `route`, or `cursor`; kinds prevent a legacy value from being treated
as a scope by default. A dry run produces a canonical projection ordered by
`legacyId`; its SHA-256 digest binds authority evidence, known tenants,
canonical scopes, every observed candidate, full inventory row, and every plan
decision. It must be identical when the same manifest is run again, and change
when catalogue or collision evidence changes.

### Canonical digest bytes

The digest is `sha256:` plus the lowercase hexadecimal SHA-256 of the UTF-8
bytes of the dry-run projection. It uses the JSON Canonicalization Scheme
(JCS), RFC 8785, over this bounded contract domain:

1. Values are null, booleans, Unicode-scalar strings, safe integers, arrays,
   or objects. Non-finite values, fractions, integers outside
   `[-9007199254740991, 9007199254740991]`, binary values, and host-language
   sentinel values are rejected. Full RFC 8785 floating-point serialization is
   intentionally outside this safe-integer digest domain.
2. Strings use ECMAScript `JSON.stringify` JSON-string serialization. Lone
   UTF-16 surrogates are rejected before serialization.
3. Object member names are sorted lexicographically by UTF-16 code units, as
   RFC 8785 requires, and emitted without whitespace.
4. Arrays retain their declared order. Optional `observedCandidates` is
   omitted when absent; it is never rendered as JavaScript `undefined`, `null`,
   or an empty substitute.

The synthetic conformance fixture has this exact vector:

```text
sha256:078077e81b5d5b5e1eb6ceaa6c64c41fe44b9b97f5266104190f62e3e6903306
```

Implementations must reproduce this vector and the same digest after any
object-key permutation that preserves the manifest values.

Additional escaping, Unicode, UTF-16 key-order, and safe-integer vectors are
published in `scripts/fixtures/scope-migration-v1-jcs-vectors.json` and are
executed by the conformance test.

| Vector | SHA-256 digest |
| --- | --- |
| controls, quote, backslash, BMP Unicode, astral scalar | `b7d7059b80dd2918190f3cc0cf1ed1b189f7ba45cc5f5d22e32cb7daee21b185` |
| UTF-16 key order (`A`, astral scalar, BMP `U+E000`) | `4dd477277eed6b46b9464a562a31e6f3d9468c616e5d61548a1468ef420ecc1b` |
| safe integer boundaries | `cdfe8c5f0fe5b941154823a78e4e43f50a0f0ea884c3e23245d272553f2461c5` |

The catalogue contains explicit `ScopeRef` values from scope substrate v1.
`ScopeRef` identity remains `(tenantId, scopeId)`: `type` is descriptive and
does not authorize an operation. The inventory may describe candidate scopes as
evidence, but candidates are not a grant, a hierarchy, or a mapping decision.
`authorityEvidence` identifies the reviewed authority snapshot that permits the
plan to be evaluated; it is evidence only and does not authorize a write.

## Dispositions

Every legacy value receives exactly one disposition.

| Disposition | Required plan evidence | Effect of the dry run |
| --- | --- | --- |
| `map` | Explicit canonical `target` in the catalogue and `mappingEvidence` | Report the reviewed mapping only |
| `block` | Classification only | Report a fail-closed denial; do not substitute a scope |
| `expire-and-reissue` | `reissueRequestId` | Report the request; do not expire or issue anything |

The contract never derives a target tenant, scope, type, hierarchy relation,
membership, role, or grant from a legacy string, prefix, path, owner label, or
historical use. A map row is valid only when its target is already declared in
the canonical catalogue and carries an explicit reviewed evidence reference.
Unknown and ambiguous input remains fail-closed until an owner supplies that
evidence.

## Required legacy classifications

The inventory/plan must classify naked values, two-segment values, owner-first
and type-first values, prefixed values, wildcards, duplicate values, unknown
tenants, collisions, and stale opaque references. Classification describes the
observed legacy representation; it does not turn that representation into a
canonical identity.

- A naked value has no tenant boundary.
- A two-segment value has a syntactic tenant-like first segment, but becomes a
  map only with reviewed evidence.
- Owner-first, type-first, and prefixed values are legacy encodings, never
  hierarchy evidence.
- Wildcards are never expanded by this contract.
- A duplicate is a repeated raw legacy value; it must still receive its own
  plan row.
- An unknown tenant is not added to the catalogue by the plan.
- A collision requires two or more explicitly observed canonical candidates
  and is blocked rather than resolved by a name or type preference.
- A stale opaque reference is expired and reissued through a separately owned
  process; this contract neither follows nor reuses it.

## Conformance boundary

The accompanying test intentionally implements only the JSON-Schema keywords
used by the published schema, then performs the cross-row checks explicitly.
It verifies one-to-one inventory coverage, all six inventory kinds, catalogue
membership for map targets and observed candidates, collision evidence,
syntactic classifications, digest binding for authority/catalogue/candidate/
inventory/decision changes, and unchanged source/fixture content across
repeated dry runs. It also proves the published digest vector and optional
candidate/key-order portability. It is not a general JSON-Schema evaluator or
a migration executor.
