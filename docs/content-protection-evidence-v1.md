# Content protection evidence v1

This evidence answers one bounded question: when an operator explicitly enables
AES-256-GCM for a content class, does `deflate-raw` before encryption reduce the
complete stored envelope enough to justify the added codec step? It does not
change the plaintext default and does not apply to native transcript storage.

## Method

Run:

```sh
npm run measure:content-protection
```

The command builds 16 deterministic synthetic records for each of
`conversation`, `proposal`, `canonical-memory`, and `document`. Each class has a
different representative payload size and mixes repeated prose with
deterministic high-entropy text. It compares three complete serialized variants:

1. plaintext envelope;
2. AES-256-GCM envelope without compression;
3. fixed-level `deflate-raw` followed by AES-256-GCM.

The measurement uses the production protector. Before enabling the third
variant, it computes the complete candidate envelope size, derives class-bound
evidence, runs the real compressed protection path, and requires the resulting
serialized size to match the candidate. This avoids using fabricated evidence
to justify the measurement itself.

SQLite uses one physical database per variant. The report includes logical and
serialized bytes per class, real allocation from `stat.blocks` normalized to
4 KiB blocks, and 64 indexed point reads. PostgreSQL is opt-in:

```sh
AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL=postgresql://... \
  npm run measure:content-protection
```

It uses one temporary table per variant and reports `pg_column_size` aggregates
plus the same 64 point reads. The measurement disables sequential scans while
checking and timing that path, so `indexedPlan` proves index capability rather
than the planner's natural choice for a 64-row synthetic table. PostgreSQL
filesystem blocks are intentionally not inferred; SQLite provides the
physical-file comparison. Query timings are emitted as observed, non-normative
values and are not committed as portable performance expectations.

## Synthetic result

One accepted SQLite run produced:

| Variant | Serialized bytes | Allocated 4 KiB blocks |
|---|---:|---:|
| Plaintext | 282,968 | 91 |
| AES-256-GCM | 289,048 | 91 |
| Deflate before AES | 54,592 | 19 |

The same run produced these complete-envelope savings relative to AES without
compression:

| Content class | AES bytes | Deflate-before-AES bytes | Savings |
|---|---:|---:|---:|
| Conversation | 47,702 | 10,902 | 36,800 |
| Proposal | 25,814 | 8,342 | 17,472 |
| Canonical memory | 36,822 | 9,926 | 26,896 |
| Document | 178,710 | 25,422 | 153,288 |

A PostgreSQL 16 test run completed all three variant matrices and all indexed
point reads. It reported aggregate stored datum sizes of 103,341 bytes for
plaintext, 289,112 bytes for AES, and 54,848 bytes for deflate-before-AES.
PostgreSQL reduced some compressible plaintext datum sizes internally; this
result does not assume that behavior is portable to other backends.

## Decision

Compression is available only on an explicit AES rule. Acceptance of that
policy change requires a positive sample count, arithmetically consistent
complete-envelope totals, and at least 64 bytes of savings for the same content
class. All four synthetic classes passed that threshold. The runtime does not
accept caller-attested measurement numbers. Plaintext rules never compress and
never resolve keys. Ciphertext is never compression input.

These results justify enabling `deflate-raw` as an opt-in pre-encryption policy
choice. They do not justify enabling encryption or compression globally, and
they are not a production capacity forecast.
