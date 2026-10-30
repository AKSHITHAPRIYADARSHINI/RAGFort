# RAGFort

RAGFort is a zero-trust security platform for Retrieval-Augmented Generation (RAG) applications. It treats user input, documents, retrieved context, and model output as untrusted until applicable controls have evaluated them.

## Current status

**Phase 5 COMPLETE.** The application includes authenticated RAG queries, secure document ingestion, tenant-scoped retrieval with PostgreSQL authorization, deterministic prompt-attack detection, malicious retrieved-context filtering, and minimized security-event persistence. The final release matrix and independent review board passed. Phase 5 implementation and validation evidence is recorded in `docs/phase-5-implementation-report.md` and its linked QA, runtime, and review reports. Attack results apply to the documented synthetic corpus; they do not establish protection against every novel attack.

The frontend uses Next.js 15.5.26. Final validation passed 128 pytest tests, Ruff, Python compilation, the 24-record Phase 5 controlled evaluation, frontend TypeScript lint/build, runtime readiness, and nine authenticated production browser scenarios through OIDC/PKCE. The five review roles reported PASS. See the Phase 5 runtime report for scenario outcomes and request IDs, and the QA report for the frozen matrix and residual non-blocking advisories.

Earlier phase reports remain available: `docs/phase-1-completion-report.md`, `docs/phase-2-implementation-report.md`, `docs/phase-3-implementation-report.md`, and `docs/phase-4-implementation-report.md`.

## Local validation

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

To run the local API and its dependencies, configure `.env.keycloak.local` as described in [`docker/keycloak-local.md`](docker/keycloak-local.md), then start Compose:

```powershell
docker compose up --build
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm ci
npm run dev
```

The frontend is available at `http://localhost:3000`, the API at `http://localhost:8000`, and local Keycloak at `http://localhost:8080/realms/ragfort-local`. Compose uses local development services and synthetic data.

For implementation scope, limitations, and validation evidence, start with [the Phase 5 report](docs/phase-5-implementation-report.md) and [release ledger](docs/phase-5-implementation-ledger.md).
