# ADR-009: Deterministic bounded chunking

Use configurable character chunks (default 1600 with 300 overlap), preserving complete sentence boundaries where possible and deterministic IDs derived from document/version/index. This is simple and measurable for synthetic fixtures. It preserves arbitrary metadata for Phase 3/4; it is not secure ingestion.
