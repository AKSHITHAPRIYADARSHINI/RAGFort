# RAGFort Threat Model

## Scope and assumptions

Phase 1 is a new repository foundation. No runtime RAG or controls existed at baseline. This model designs a multi-tenant enterprise deployment in which a browser reaches a Next.js frontend and authenticated FastAPI API over HTTPS; PostgreSQL is the policy/audit source of truth, Qdrant is a future vector store, and model/embedding providers are external boundaries. These assumptions require validation before deployment.

## Assets and actors

Protected assets: tenant/user/role claims; documents, chunks, ACLs, classifications and provenance; approved embeddings/index; secrets and system policies; query/context/output data; security events/audits; policy/test configuration; and availability of critical security dependencies.

Actors include anonymous attackers, authenticated malicious users, malicious tenants/document authors, compromised employees or insiders, supply-chain attackers, and attackers holding a service credential. They can submit malformed or adversarial input, upload documents, enumerate APIs, abuse legitimate access, alter metadata, or target CI/dependencies. They are not assumed to have direct database access unless a service credential is compromised.

## Boundaries and entry points

1. User/device → frontend: query, session material, and browser state are untrusted.
2. Frontend → API: the API validates authentication and owns all privileged operations.
3. API → identity/policy: claims, tenant, roles, and attributes are validated and fresh.
4. Policy → retriever/vector store: authorized scope is applied before search and checked again on results.
5. Upload → ingestion: file, metadata, extracted text, and embedded instructions are hostile until approved.
6. Retriever/context → LLM: retrieved text is untrusted data, never policy or tools instruction.
7. LLM → output firewall → user: output is untrusted until release validation.
8. Security stages → event/audit store: telemetry needs integrity, minimization, and restricted access.
9. CI/dependency/image source → pipeline: build artifacts and dependencies are a supply-chain boundary.

## Priority abuse paths

| ID | Abuse path and impact | Priority | Preventive control | Detection/corrective response |
|---|---|---|---|---|
| T01 | Direct injection tries to override rules or extract system policy. | High | Query guard before retrieval; fixed server policy. | Block, emit injection event, no retrieval/LLM. |
| T02 | Indirect instructions in documents influence the model. | Critical | Scan, approval, hash/provenance, context isolation. | Quarantine/exclude; indirect-injection event. |
| T03 | Missing/malformed filters expose another tenant's chunks. | Critical | Server-derived scope, pre-search tenant/ACL predicate, result revalidation. | Deny, trace, isolation regression. |
| T04 | User obtains unauthorized document. | High | RBAC+ABAC before retrieval. | Deny and audit decision. |
| T05 | Document/vector metadata tampering changes content/ranking. | High | Immutable versions and SHA-256 validation. | Quarantine and reindex known-good version. |
| T06 | Output exposes PII, secrets, or restricted content. | High | Output firewall/DLP release gate. | Redact/block with minimized event. |
| T07 | Repeated queries reconstruct corpus or exploit cache. | High | Scope-bound cache, quotas/rate limits. | Extraction/anomaly detection; throttle/block. |
| T08 | Revoked permissions remain usable. | High | Short-lived credentials, authorization epoch and cache invalidation. | Stale-authority denial and audit. |
| T09 | A scanner/authz/event dependency fails and traffic proceeds. | Critical | Explicit fail-closed dependency gate. | Safe error and security-service-failure event. |
| T10 | Logs preserve raw sensitive data. | Medium | Field allowlist, redaction, restricted evidence store. | Schema/privacy tests and access audit. |
| T11 | A direct data-service call bypasses the API. | High | Private networking/service credentials; no browser secrets. | Connection monitoring and deployment controls. |
| T12 | Dependency or build compromise changes policy/artifact. | High | Pinned reviewable dependencies, protected CI, later provenance/SBOM. | CI audit and vulnerability evidence. |

## Control matrix

| Domain | Deterministic enforcement | Detection | Corrective/observability |
|---|---|---|---|
| Injection | Query guard decision gate | Rules, obfuscation/semantic signals | Block, event, rate escalation |
| Ingestion | Approval + integrity preconditions | Hidden-content/injection/PII scans | Quarantine, remove from index |
| Retrieval | Tenant RBAC/ABAC filters + result validation | Retrieval anomaly signals | Deny, trace, cache invalidation |
| Output | Release gate | DLP/secret/unsafe-output signals | Redact/block, event |
| Availability | Dependency policy | Health/failure telemetry | Deny/quarantine/safe error |
| Audit | Required event acknowledgement | Pipeline health | Durable outbox later or fail closed |

Risk is qualitative until Phase 5 measurement: cross-tenant leakage and control bypass are critical because impact is high even with constrained likelihood. No effectiveness percentage is claimed.
