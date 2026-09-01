# ADR-002: Qdrant as planned vector database

## Context
RAGFort needs explicit vector metadata filtering and isolated retrieval observability.

## Decision
Prefer Qdrant, evaluated against pgvector, Weaviate, and Milvus. Use it only as a derived index; PostgreSQL remains policy source of truth.

## Alternatives and reasoning
pgvector simplifies operations but competes with transactional workload; Weaviate/Milvus add capabilities and operational complexity. Qdrant provides focused vector operations and payload filtering. Server-side tenant/ACL predicates and result revalidation remain mandatory regardless of database capability.

## Implications
Dedicated retrieval scaling is possible. It introduces another dependency and consistency/deletion workflow. Phase 2 validates a thin adapter; no vector DB is installed in Phase 1.
