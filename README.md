# RAGFort

RAGFort is a planned zero-trust security platform for Retrieval-Augmented Generation (RAG) applications. It treats user input, documents, retrieved context, and model output as untrusted until applicable controls have evaluated them.

## Current status

**Phase 1 — architecture and engineering foundation.** The repository contains a health-only FastAPI service, validation scaffolding, and version-controlled security architecture. It does not contain a RAG pipeline, authentication implementation, document ingestion, vector search, an LLM integration, or security detections yet.

## Phase 3 status

Phase 3 delivers a development secure-ingestion boundary for UTF-8 TXT and Markdown: bounded validation, deterministic scan findings, SHA-256 provenance, review/quarantine, explicit development approval, approved-only indexing, and derived-index deletion. Identity, tenant enforcement, RBAC/ABAC, broad attack detection, output DLP, and production hardening remain future work. See `docs/phase-3-implementation-report.md` for evidence and limitations.

## Local validation

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

To run the health-only API:

```powershell
uvicorn backend.app.main:app --reload
```

`GET /health/live` confirms process liveness. `GET /health/ready` reports readiness only for the Phase 1 foundation; later phases will add fail-closed dependency checks.

See [docs/phase-1-completion-report.md](docs/phase-1-completion-report.md) after Phase 1 is complete.
