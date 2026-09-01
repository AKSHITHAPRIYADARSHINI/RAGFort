# Testing Strategy

No pass-rate is claimed beyond the two Phase 1 health-contract tests. Future tests use synthetic fixtures with no real secrets or enterprise content.

| Layer | Scope | Acceptance property |
|---|---|---|
| Unit | Policy predicates, schemas, invariant logic | Deterministic deny conditions are reproducible. |
| API/contract | Envelopes, request IDs, errors, health | No sensitive internals are disclosed. |
| Integration | Stores, policy, retrieval boundaries | Tenant/ACL predicates always precede retrieval. |
| Authorization | RBAC, ABAC, revocation, cache | Unauthorized/cross-tenant retrieval returns zero chunks. |
| Security/adversarial | Direct/indirect injection, poisoning, tampering, DLP | Block/quarantine/withhold happens at the expected gate. |
| Reliability | Authz/scanner/vector/LLM/event failures | Safe denial/error; no fallback bypass. |
| Performance | p50/p95, error rate, per-stage latency | Baselines are measured, not invented. |
| Regression/evaluation | Versioned corpus and 500+ Phase 7 target | Security regressions block release. |

Adversarial coverage plans normal queries; direct override/system-prompt extraction; Unicode/encoded/multiturn injection; indirect/split-chunk injection; poisoning; unauthorized and cross-tenant retrieval; stale permissions/cache leakage; PII/secret exposure; corpus extraction; tampering; retrieval manipulation; malformed metadata; rate abuse; and each critical dependency failure.

Phase gates require every delivered invariant to have unit and integration evidence, event schema/privacy assertions, and negative tests proving that no LLM call occurs after an authorization/injection block where applicable.
