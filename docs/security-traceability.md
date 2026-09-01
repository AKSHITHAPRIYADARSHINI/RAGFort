# Security Traceability Matrix

This matrix creates the implementation and evidence chain from threat to invariant, control, delivery phase, and planned test identifier. Planned identifiers are not evidence of an implemented test.

| Threat | Invariant | Control | Phase | Planned test |
|---|---|---|---:|---|
| T01 Direct injection | INV-002, INV-006 | Pre-retrieval query guard; fixed server policy | 5 | `RAG-INJECT-DIR-001` |
| T02 Indirect injection | INV-007, INV-012 | Ingestion scan/approval; context firewall | 3, 5 | `RAG-INJECT-IND-001` |
| T03 Cross-tenant access | INV-001, INV-011 | Server tenant scope; pre-search ACL filter; result revalidation | 4 | `AUTH-XTENANT-001` |
| T04 Unauthorized retrieval | INV-002, INV-006 | RBAC + ABAC before retrieval | 4 | `AUTH-RBAC-001` |
| T05 Tampering | INV-003 | Immutable version and SHA-256 integrity gate | 3 | `DOC-HASH-001` |
| T06 Sensitive output | INV-004 | Output DLP/release gate | 6 | `DLP-001` |
| T07 Corpus extraction/cache | INV-009 | Scope-bound cache, quotas, behavioral detection | 4, 5 | `RAG-EXTRACT-001` |
| T08 Stale authorization | INV-009 | Revocation epoch and cache/session invalidation | 4 | `AUTH-REVOKE-001` |
| T09 Control failure | INV-005 | Fail-closed dependency gates | 4–6 | `REL-FAIL-001` |
| T10 Unsafe logging | INV-008 | Minimized event schema and protected evidence | 5, 6 | `EVENT-PRIVACY-001` |
| T11 Data-service bypass | INV-011 | API-only privileged access; private service networking | 8 | `DEPLOY-BOUNDARY-001` |
| T12 Supply-chain compromise | INV-005, INV-008 | Dependency audit, later lock/provenance/SBOM | 1, 8 | `CI-DEPS-001` |

The intended lifecycle is: **threat → requirement → control → phase → test → measured evidence**. The traceability matrix is updated whenever a control or test is delivered.
