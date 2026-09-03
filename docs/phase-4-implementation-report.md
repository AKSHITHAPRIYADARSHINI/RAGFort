# RAGFort Phase 4 implementation report

## 1. Context

Phase 4 begins from the clean `phase-3-complete` checkpoint on branch
`phase-4-identity-secure-retrieval`.  Phase 1 designed the zero-trust boundaries,
Phase 2 established explicit RAG components, and Phase 3 added an approved-only
development ingestion lifecycle.  This phase makes identity, policy, tenant, and
classification authoritative before vector retrieval.

## 2. Introduction

Semantic search ranks related chunks but does not understand identity.  Phase 4
therefore constructs a validated principal, evaluates deterministic RBAC plus ABAC,
and passes only a server-derived filter to Qdrant.  It must never retrieve broadly
and remove unauthorized chunks later.

## 3. Tech Stack

Current runtime dependencies are FastAPI, SQLAlchemy, PostgreSQL, Qdrant, React and
Next.js.  Phase 4 will add only an OIDC/JWT validation library if the existing
dependencies cannot perform standards-compliant asymmetric JWT validation.  Exact
versions and validation evidence are recorded at closure.

## 4. Objective

Deliver an authenticated trusted principal, deterministic RBAC/ABAC policy,
tenant-scoped documents and pre-retrieval Qdrant filtering, plus a minimal
permission-aware browser experience.  Phase 5 detection and Phase 6 output controls
remain out of scope.

## 5. Problem

The inherited Phase 2 fixture index and Phase 3 payloads do not have tenant, ACL,
current-version, or role metadata.  They are not safe to query once access control is
enabled.  The cutover must backfill/reseed security metadata and fail closed for
legacy or malformed points.

## 6. Solution

The proposed path is OIDC token validation → canonical principal lookup → policy
decision → typed server-owned retrieval scope → filtered Qdrant search → authoritative
metadata revalidation → context and generation.  Document APIs receive the same
principal and action-specific policy checks.

## 7. How We Resolved It / Techniques and Approaches

Specialist reviews consolidated the following decisions: use provider-independent
OIDC rather than custom passwords; combine RBAC endpoint permissions with ABAC
tenant/classification/document state/role constraints; source tenant and roles from
the canonical principal, never a request body; use a short token lifetime plus a
database authorization epoch for revocation; and do not introduce a cache in this
phase.

## 8. Visuals and Diagrams

```mermaid
flowchart TD
  U[User] --> I[OIDC provider]
  I --> T[Signed access token]
  T --> V[FastAPI token validator]
  V --> P[Trusted principal]
  P --> PE[RBAC + ABAC policy]
  PE --> F[Server-owned Qdrant filter]
  F --> R[Filtered retrieval]
  R --> C[Authorized context]
  C --> G[Generation]
```

## 9. Result

**In progress.** This document records design evidence only until implementation,
tests, local runtime validation, and a secret review are complete.  No Phase 4
security claim is made yet.

### Runtime evidence recorded September 2, 2026

- Keycloak 26.1.4 is healthy in Docker; OIDC discovery, JWKS retrieval, realm
  provisioning, and real synthetic-user token issuance succeeded.
- PostgreSQL canonical identity resolution was verified with a Keycloak-issued
  ACME Employee token: `GET /api/v1/me` returned HTTP 200, `tenant_acme`, and
  the database-authoritative `viewer` role.
- Authenticated pre-filtered retrieval was verified with the Phase 4 marker
  corpus: ACME → ACME was grounded; ACME → GLOBEX and HR → Finance returned
  `insufficient_context` without citations; Finance Reader → Finance returned
  the authorized finance citation.
- The Docker API image now contains the controlled corpus and the corpus seeder
  resolves its fixture paths independently of the container working directory.
- Full pytest passed: **53 tests**. Ruff, Python compilation, evaluation,
  frontend TypeScript lint/build, and Compose configuration validation passed.

Measured from the runtime marker probes:

| Metric | Result |
| --- | ---: |
| `cross_tenant_leakage` | 0 |
| `forbidden_chunks` | 0 |
| `forbidden_citations` | 0 |

Phase 4 cannot close yet: a browser authorization-code callback/session, real
logout and session-expiry E2E, runtime authorization-epoch and disabled-account
mutation tests, and the final browser regressions remain unverified.

### Browser-session evidence

The local browser flow now uses PKCE authorization code login through Keycloak.
FastAPI exchanges the code and retains the access token only in its local
server-side session store; the browser receives an opaque `HttpOnly`, `SameSite`
cookie and frontend JavaScript never receives a bearer token. Browser automation
verified the unauthenticated sign-in gate, Keycloak login, callback to the
authenticated Ask page, and an ACME grounded answer with its permitted citation.
The in-memory local store is intentionally lost on API restart, which safely
returns the browser to the sign-in gate. Production session persistence and a
distributed revocation store remain Phase 8 work.

## 10. Output

Initial output: ADR-018 and this implementation report.  The final update will list
source modules, migrations, test evidence, browser validation, exact metrics, commits,
limitations, and Phase 5 readiness.

Runtime commits during this block include local Keycloak profile/client fixes,
container corpus fixes, and classified department-reader policy wiring. The
`phase-4-complete` tag is intentionally not present.
