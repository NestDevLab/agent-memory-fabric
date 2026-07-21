# M4 V2 Archive Source v1

`createM4V2ArchiveSource` is a bounded internal source for the M4 coordinator.
It reads only canonical v2 logical groups, retrieves client ciphertext by
content ID, authenticates each mapped observation through the v2 observation
reader, and projects it with the production v3 projector. It never uses v1
rows or session compatibility views.

Rows are ordered projection events with compact checkpoints. Checkpoint IDs
contain only canonical logical-ID hashes and checkpoint digests bind group
metadata, event digests, and output position. Resume rebuilds only the
checkpoint group before continuing after it; it does not scan from the archive
start. Checkpoints and errors never contain plaintext. Rows contain only the
filtered v3 conversation content needed for the backfill; they exclude native
RAW/base64 material and system/tool content.

This source does not itself backfill, write an archive, cut over, deploy, or
close an M4 roadmap checkbox.
