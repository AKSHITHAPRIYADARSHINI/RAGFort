# RAGFort

RAGFort is a zero-trust security platform for Retrieval-Augmented Generation (RAG) applications. It treats user input, documents, retrieved context, and model output as untrusted until applicable controls have evaluated them.

## Current status

**Phase 5 release candidate; closure is pending authenticated browser validation and final review.** The application includes authenticated RAG queries, secure document ingestion, tenant-scoped retrieval with PostgreSQL authorization, deterministic prompt-attack detection, malicious retrieved-context filtering, and minimized security-event persistence. Phase 5 implementation and validation evidence is recorded in `docs/phase-5-implementation-report.md` and its linked QA, runtime, and review reports. Attack results apply to the documented synthetic corpus; they do not establish protection against every novel attack.

The frontend uses Next.js 15.5.26. Automated validation is recorded as 128 passing tests plus Python lint/compile, frontend TypeScript/build, and controlled evaluation checks. The authenticated browser gate and final release board are still pending, so Phase 5 is not marked complete.

Earlier phase reports remain available: `docs/phase-1-completion-report.md`, `docs/phase-2-implementation-report.md`, `docs/phase-3-implementation-report.md`, and `docs/phase-4-implementation-report.md`.

## Local validation

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

To run the full local stack, configure the development identity provider values in `.env.keycloak.local`, then start Docker Compose:

```powershell
docker compose up --build
```

The API is available at `http://localhost:8000`, the frontend at `http://localhost:3000`, and the local Keycloak realm at `http://localhost:8080/realms/ragfort-local`. Compose uses local development services and synthetic data. See `.env.keycloak.example` for the required configuration shape.

For implementation scope, limitations, and validation evidence, start with [the Phase 5 report](docs/phase-5-implementation-report.md) and [release ledger](docs/phase-5-implementation-ledger.md).
