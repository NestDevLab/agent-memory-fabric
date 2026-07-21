# M4 Conversation Archive Sink v1

`M4ConversationArchiveSink` adapts a production Conversation Archive v1
adapter to the acknowledgement contract used by
`ConversationEventPlaintextOutbox`. It validates each complete v3 event and
its integrity envelope before touching the archive. The supplied event ID and
payload digest must exactly match the outbox delivery binding.

The sink maps tombstones to `archive.tombstone`; every other valid v3 state is
sent unchanged to `archive.append`. It derives the archive-only idempotency key
from the event ID using the established `cevt_` to `cai_` mapping. The archive
key is never included in acknowledgements or errors.

Only exact `stored` and `duplicate` archive outcomes are accepted. The sink
does not retry, alter event relationships, or expose event content. Inputs are
validated before archive mutation and the delivered event is a defensive copy.
Errors use fixed, content-free codes.

This adapter does not open an outbox, checkpoint progress, verify migration
gates, execute a backfill, reconcile archives, or satisfy an M4 roadmap
checkbox.
