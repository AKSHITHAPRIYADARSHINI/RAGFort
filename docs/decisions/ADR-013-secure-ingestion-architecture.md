# ADR-013: Secure ingestion gateway

## Context and problem
Uploads are untrusted while Qdrant is only a derived index.

## Decision
Use an explicit server-side pipeline and SQLAlchemy document/version authority before any Qdrant write.

## Alternatives and reasoning
Direct upload-to-vector indexing is simpler but violates approval and provenance invariants. A separate service was deferred to keep Phase 3 observable and testable.

## Implications
The pipeline is fail-closed, durable, and extensible; it adds a relational dependency. Phase 4 supplies identity/tenant policy.
