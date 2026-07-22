# M4 preservation proof v1

`amf.m4-preservation-proof/v1` is signed, content-free evidence that approved
conversation selectors use encryption with plaintext reads closed before a
cutover authorization can be issued. It validates the existing content
protection policy instead of defining a second policy system.

The proof re-verifies a separately signed, bounded selector-scope snapshot from
the scope authority. The supplied policy must have the exact signed revision and
canonical digest, and the proof must cover every signed selector in order. For
each selector it binds a complete aggregate disposition: each scanned legacy
plaintext object is either retained through an encrypted read path or assigned
to an exact later cleanup target. The two disposition counts must sum to the
scanned count.
The scope verification key is a configured trust anchor outside preservation
input and cannot reuse the preservation signing authority.

The proof separately binds preserved aggregates for proposals, canonical
memories, and documents in a fixed order. Those classes cannot be closure
selectors or cleanup classes. A passed policy restore test and the previous
policy revision are also required. Evidence identifiers and digests are unique,
and all inputs are strict and bounded.

The adjacent scope collector reads only its supplied selector source and active
policy. Neither module changes a policy, re-envelops content, reads payloads,
switches a route, authorizes deletion, or executes cleanup.
