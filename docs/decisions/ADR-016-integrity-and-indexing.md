# ADR-016: SHA-256-bound approved index

## Decision
Store SHA-256 for original bytes and normalized text, recheck before approval, attach server-owned hash/version/status metadata to chunks, and mark `INDEXED` only after Qdrant succeeds.

## Consequences
Integrity failure quarantines. Index failure is durable `INDEX_FAILED`, never success. Delete uses Qdrant version-filter removal before terminal `DELETED`.
