# Cross-Phase Identity Publication Reader v1

The publication reader is a read-only consumer for an immutable, content-free identity publication. It validates the private root artifact, signed traversal completion, registry authority MAC, coverage, page descriptors, and page contents before exposing the verified signed authority and a page loader.

The reader never scans, copies, modifies, or deletes RAW data. It does not create missing page namespaces or artifacts. Missing, substituted, tampered, unsafe, or mismatched inputs fail closed.

Paused-native replay should use the publication-backed resolver factory rather than injecting an unverified registry authority or page loader. Source-tag authority remains separately supplied and separately keyed; optional post-cutoff lookup remains an independent callback.

Close readers when finished. Closure is idempotent and makes further page loads or resolver calls fail deterministically.
