# ADR-010: Cosine retrieval baseline

Use Qdrant cosine distance with normalized vectors, configurable top-K (default 5), a configurable score threshold, and optional server-owned metadata filters. Evaluation measured equal recall/hit rate for K 3/5/8 on the small corpus; K=5 is retained to supply bounded multi-source context while security filters arrive later.
