# API Design

All future application endpoints are versioned under `/api/v1`. The API, not the browser, performs authentication, tenant resolution, authorization, retrieval, model calls, and audit/event writes.

## Envelope and safety

Success: `{"success":true,"data":{},"request_id":"req_..."}`. Error: `{"success":false,"error":{"code":"ACCESS_DENIED","message":"You do not have permission to access this resource."},"request_id":"req_..."}`. Request IDs are generated server-side. Public errors never include stack traces, SQL, file paths, credentials, service topology, raw prompts, or system policy.

## Endpoint connection map

| UI | Endpoint | Method | Authorization | Purpose |
|---|---|---|---|---|
| Ask | `/api/v1/query` | POST | Authenticated + query policy | Secure RAG request (Phase 2+) |
| Ask status | `/api/v1/query/{request_id}` | GET | Owner or tenant-scoped analyst | Safe request status |
| Documents | `/api/v1/documents` | GET/POST | Authenticated + document ABAC; contributor to upload | Authorized inventory/upload |
| Document | `/api/v1/documents/{id}` | GET/DELETE | Document ABAC + explicit delete permission | Metadata or deletion workflow |
| Document workflow | `/api/v1/documents/{id}/scan`, `/api/v1/documents/{id}/approve`, `/api/v1/documents/{id}/quarantine` | POST | Privileged document role + tenant scope | Phase 3 lifecycle |
| Security | `/api/v1/security/overview`, `/api/v1/security/events` | GET | Analyst+ and tenant scope | Redacted metrics/events |
| Security event | `/api/v1/security/events/{id}` | GET | Analyst+ and tenant scope | Protected event detail |
| Tests | `/api/v1/tests`, `/api/v1/tests/run`, `/api/v1/tests/runs/{id}`, `/api/v1/tests/runs/{id}/results` | GET/POST | Analyst+; run needs authorized suite | Actual test evidence |
| Activity | `/api/v1/audit`, `/api/v1/audit/{id}` | GET | Analyst+ tenant scope; user may later see own limited data | Audit trail |
| Auth | `/api/v1/auth/me`, `/api/v1/auth/logout` | GET/POST | Authenticated | Session identity/logout |
| Health | `/health/live`, `/health/ready` | GET | Live public process-only; ready internal/gateway-protected | Minimal operational state |

Mutations will require an idempotency key when replay could create a new action. Cookie auth requires CSRF defenses; bearer auth requires validated OIDC issuer/audience and short expiry. Every resource lookup independently applies tenant and ABAC predicates.

## Planned contracts

`QueryRequest` intentionally excludes a client-supplied `tenant_id`; a trusted `RequestContext` supplies tenant, user, roles, authorization epoch, and policy version. `QueryAssessment` returns decision, risk, signal references, and a normalized-query reference. `RetrievalBundle` contains only authorized, approved, integrity-valid chunks with immutable document/version/chunk IDs, classification, hash, and trace. `ContextPackage` has structural source delimiters and provenance. `OutputAssessment` returns allow/redact/block and evidence references. These interfaces are Phase 2+ contracts, not endpoints implemented today.

## Phase 3 document endpoints

All endpoints use the standard envelope and server-created request ID. Phase 3 uses a clearly labelled development-only operator action; it does not claim identity, RBAC, ABAC, or tenant authorization.

| UI | Endpoint | Method | Behavior |
|---|---|---|---|
| Documents | `/api/v1/documents` | GET | Safe lifecycle summaries only. |
| Upload | `/api/v1/documents` | POST multipart | Validates, extracts, scans, hashes, and returns REVIEW_REQUIRED or QUARANTINED. |
| Detail | `/api/v1/documents/{id}` | GET | Safe metadata; never body/paths/raw hashes. |
| Security | `/api/v1/documents/{id}/security` | GET | Safe finding categories and descriptions. |
| Rescan | `/api/v1/documents/{id}/scan` | POST | Revalidates stored immutable version. |
| Approve | `/api/v1/documents/{id}/approve` | POST | Development-only explicit transition and gated index attempt. |
| Quarantine | `/api/v1/documents/{id}/quarantine` | POST | Excludes/removes derived vectors. |
| Delete | `/api/v1/documents/{id}` | DELETE | Marks deletion pending and removes derived vectors. |
