# ADR-008: Deterministic development embedding adapter

Use `HashEmbeddingService` (256 dimensions, normalized token-hash vectors) for the controlled corpus, CI, and reproducible measurements. `sentence-transformers`/BGE remains an adapter candidate when model download and benchmark infrastructure are available. This avoids opaque downloads in CI; its retrieval quality is not a production claim.
