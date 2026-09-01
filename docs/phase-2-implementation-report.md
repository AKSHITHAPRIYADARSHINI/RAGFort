# RAGFORT — PHASE 2 IMPLEMENTATION REPORT

## 1. Context

Phase 1 froze the zero-trust architecture at `phase-1-complete`. Phase 2 builds the first explicit RAG vertical slice over a controlled 20-document synthetic corpus. Secure ingestion, identity, authorization, attack detection, output DLP, and observability remain deferred.

## 2. Introduction

Documents are normalized and chunked, embedded, and indexed as a derived Qdrant search index. A question is embedded, retrieved with optional server-owned filters, converted into a bounded `ContextPackage`, passed to a generation protocol, and returned with citations originating from retrieval metadata.

## 3. Tech Stack

| Technology | Version | Purpose and tradeoff |
|---|---:|---|
| FastAPI/Pydantic | existing Phase 1 ranges | Typed API and safe envelopes; explicit boundaries. |
| qdrant-client/Qdrant | 1.19 / Compose 1.19.0 | Derived cosine vector index with payload filters; adds a service. |
| HashEmbeddingService | 256 dimensions | Reproducible local/CI baseline; not production semantic-model quality. |
| Next.js/React | 15.3.2/19.1.0 | Accessible Ask UI; browser only calls FastAPI. |
| pytest/Ruff | existing ranges | Tests and static checks. |

## 4. Objective

Provide a measurable, testable RAG path while retaining separate embedding, retrieval, context, generation, and citation boundaries for later policy/firewall controls.

## 5. Problem

The implementation had to preserve document identity, bound context, avoid invented citations, represent no-evidence separately from outage, and avoid model-only fallback. The selected deterministic fixture corpus and adapter architecture keep each decision reproducible.

## 6. Solution

`DocumentChunker` → `HashEmbeddingService` → `QdrantRetriever` indexes the development corpus. `QueryService` orchestrates query embedding → retrieval → `ContextBuilder` → `ExtractiveGenerationService` → `CitationFormatter`. `POST /api/v1/query` maps known failures to safe envelopes. The Ask UI has a centralized API client and success, loading, insufficient-context, and safe-error states.

## 7. How We Resolved It / Techniques and Approaches

Deterministic IDs use SHA-256 document/version/index. Context uses complete chunks and a token estimate. Retrieval filters are accepted now but only future server policy will derive them. The generator never creates citations; citations are deduplicated retrieval metadata. Empty retrieval skips generation; retrieval failure raises `RAG_RETRIEVAL_UNAVAILABLE` without fallback. Unit, API, and in-memory-Qdrant integration tests cover these properties.

## 8. Visuals and Diagrams

```mermaid
flowchart TD
 U[User]-->FE[Next.js Ask UI]-->API[FastAPI Query API]-->QS[Query Service]-->ES[Embedding Service]-->R[Retriever]-->Q[(Qdrant)]
 Q-->R-->CB[Context Builder]-->G[Generation Service]-->C[Citation Formatter]-->API
```

```mermaid
flowchart LR
 D[Phase 2 development corpus]-->N[Normalize]-->C[Chunk]-->E[Embed]-->Q[(Qdrant)]
```

```mermaid
sequenceDiagram
 participant U as User
 participant F as Frontend
 participant A as FastAPI
 participant Q as Qdrant
 participant G as Generator
 U->>F: Ask
 F->>A: POST /api/v1/query
 A->>Q: embedded Top-K search
 Q-->>A: chunks
 A->>G: bounded context
 G-->>A: grounded answer
 A-->>F: answer + retrieval sources
```

Phase 2 is Query → Retrieval → Context → LLM/provider → Answer. Phase 4 inserts identity/policy/ACL filters, Phase 5 query/context detection, and Phase 6 output firewall/monitoring.

```text
┌──────────────────────────────────────────────────────────────┐
│ RAGFort                                                      │
├───────────────┬──────────────────────────────────────────────┤
│ ● Ask         │ Ask your knowledge base                      │
│ Documents*    │ [ What would you like to know?             ] │
│ Security*     │                         [ Ask → ]            │
│ Activity*     │ Answer and retrieved source cards            │
│ Tests*        │ Grounded in N sources                        │
│ Settings*     │ *Future phase                                │
└───────────────┴──────────────────────────────────────────────┘
```

## 9. Result

**Implemented:** controlled corpus, chunker, deterministic embeddings, Qdrant adapter, bounded context, extractive grounded provider, retrieval-derived citations, query API, Ask UI, evaluation runner, and tests. **Designed:** a sentence-transformer/OpenAI-compatible adapter path. **Deferred:** all Phase 3+ security controls.

## 10. Output

Measured evaluation: 20 documents/20 chunks, average chunk size 153.15 characters, 256 dimensions, cosine/dot normalized vectors. At K=5: Precision@K 0.20, Recall@K 1.0, Hit Rate@K 1.0, MRR 0.9; exact run latency evidence is versioned in `evaluation/results/phase2-retrieval.json`. Citation mapping: tested retrieval-derived only. E2E generation latency: **NOT MEASURED**. The live Docker Qdrant path was seeded and exercised, while the versioned metric runner measures deterministic retrieval computation rather than container round-trip latency.

Final validation: `ruff check .` passed; `pytest` passed with 10 tests; `compileall -q backend` passed; `python -m evaluation.run` passed; frontend TypeScript lint and Next.js production build passed; `docker compose config` passed. Docker Compose started healthy Qdrant and API containers, and the composed API returned both the expected grounded remote-work answer and explicit `insufficient_context` for the unsupported stock-price question. The browser Ask flow was manually exercised for grounded, insufficient-context, and retrieval-outage states.

Phase 2 files include the explicit RAG modules under `backend/app/rag/`, API and seeding support, the controlled evaluation corpus/questions/results, Ask UI, unit/integration/functional coverage, ADR-008 through ADR-012, Compose configuration, and this report. Known limitations: the deterministic hash embedding is a reproducible baseline rather than a production semantic model; measured end-to-end generation latency is not available; and the local Python 3.13 release-candidate environment cannot run `pip-audit` because of its `tomli` extension-cache error. CI retains Python 3.12 dependency scanning. Phase 3 prerequisites are the frozen Phase 2 contracts and corpus/index boundary, not production ingestion behavior.

Endpoint matrix: Ask → `POST /api/v1/query`; readiness → `GET /health/ready`; sources are in the query response. All other UI API endpoints are **NOT IMPLEMENTED — FUTURE PHASE**.

Final security review: no browser Qdrant/LLM client, no frontend secret config, no raw environment endpoint, no model-only fallback, explicit filters/context/generation/citation boundaries, and no Phase 1 invariant contradiction found. UI build and TypeScript lint pass.

## Completion status

**Status: PASS.** Docker-hosted Qdrant 1.19.0 was seeded with 20 documents and 20 chunks. Live API and browser evidence verified: (1) the remote-work question returned the expected answer and the Remote Work Policy source, (2) the stock-price question returned `insufficient_context`, and (3) stopping Qdrant yielded HTTP 503 / the safe UI error state before restarting it. The outage path did not invoke a model-only fallback. `phase-2-complete` is eligible after final validation and Git review. Phase 3 is not started.
