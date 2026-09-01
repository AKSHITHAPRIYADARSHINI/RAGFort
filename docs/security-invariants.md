# Security Invariants

These are non-negotiable future implementation properties. A feature that violates one is not releasable.

| ID | Invariant | Enforcement evidence |
|---|---|---|
| INV-001 | Tenant A must never retrieve Tenant B data. | Server-derived tenant scope on every store operation; retrieval trace and isolation tests. |
| INV-002 | Unauthorized chunks must never reach the LLM. | Policy decision precedes search; returned metadata is revalidated before `ContextPackage`. |
| INV-003 | Integrity-failing documents never participate in retrieval. | Immutable version hash check; mismatch quarantines/excludes. |
| INV-004 | Generated responses pass output-security validation before release. | Output-release gate; scanner failure withholds response. |
| INV-005 | Critical security-control failure never silently bypasses security. | Explicit dependency gates and failure tests. |
| INV-006 | The LLM never makes authorization decisions. | RBAC/ABAC policy service is deterministic and server-side. |
| INV-007 | Unapproved documents never enter the production index. | Approval state is a mandatory index precondition. |
| INV-008 | Security-sensitive actions create minimized, auditable telemetry. | Correlated append-oriented event/audit record. |
| INV-009 | Revoked access invalidates relevant sessions and caches. | Authorization epoch/policy version in session and cache keys. |
| INV-010 | Deleted information is removed from source, indexes, and caches under a deletion workflow. | Tombstone, purge jobs, and purge evidence. |
| INV-011 | Tenant and authorization context are server-derived, never client authority. | Validated identity claims and canonical server lookup. |
| INV-012 | Retrieved context is data, never executable instruction. | Fixed system policy, structural delimiters, provenance, and context firewall. |

Deterministic enforcement (identity, tenant validation, RBAC/ABAC, approvals, integrity, quotas, cache scoping, output release) must not depend on an LLM or classifier. Detection may add risk signals or invoke a policy-configured block, but may not grant access or override a deterministic denial.
