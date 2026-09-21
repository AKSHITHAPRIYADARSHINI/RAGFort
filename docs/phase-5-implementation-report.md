# RAGFort Phase 5 implementation report

## Status

**In progress.** This report records implemented, locally verified Phase 5
controls. Runtime and authenticated browser evidence are recorded only after
their actual execution.

## Implemented security path

```text
authenticated request -> canonical Phase 4 context -> bounded input analysis
-> deterministic policy -> Phase 4 scoped Qdrant/PostgreSQL retrieval
-> retrieved-context inspection -> context -> grounded generation/citation
```

`BLOCK` returns a stable `SECURITY_POLICY_REJECTED` response before embedding,
retrieval, context construction, generation, or citations. Detector, context
inspection, and required security-event persistence failures return
`SECURITY_ANALYSIS_UNAVAILABLE` and do not continue processing.

Phase 4 remains intact: detector output never creates or changes a
`RetrievalScope`; Qdrant remains a candidate index and PostgreSQL remains its
final authorization/lifecycle authority.

## Implemented components

- `backend/app/security/normalization.py`: bounded NFKC security-analysis view
  with control-character removal and whitespace normalization; original text is
  not mutated.
- `backend/app/security/detector.py` and `policy.py`: deterministic multi-signal
  taxonomy and explainable `ALLOW`, `ALLOW_AND_LOG`, or `BLOCK` policy.
- `backend/app/security/context_guard.py`: treats every Phase-4-admitted chunk
  as untrusted reference data, records internal provenance, and drops malicious
  indirect instructions before `ContextBuilder`.
- `backend/app/security/events.py` and `audit.py`: minimized structured event
  contract and SQL-backed `security_events` persistence. Raw prompts, chunks,
  credentials, cookies, tokens, and detector rules are excluded.
- `backend/migrations/phase5_security_events.sql`: additive schema migration.
- `evaluation/phase5_attack_evaluation.py`: repeatable controlled-corpus gate.

The current local generator is extractive and has no tools. The context guard and
source delimiters establish the trust boundary needed for a future provider, but
prompt wording is not represented as an authorization control.

## Synthetic evaluation evidence

The version-controlled corpus has 15 synthetic attack cases and 8 benign
controls. It contains no real secrets. The evaluation tests detection, policy,
retrieval execution expectation, context decision, evidence expectation, and
latency. It exits nonzero if an expected case fails.

| Metric | Controlled-corpus result |
| --- | ---: |
| attack_detection_rate | 1.0 |
| attack_block_rate | 0.667 |
| false_positive_rate | 0.0 |
| false_negative_rate | 0.0 |
| indirect_injection_detection_rate | 1.0 |
| malicious_context_admission_rate | 0.0 |
| cross_tenant_leakage | 0 |
| forbidden_chunks | 0 |
| forbidden_citations | 0 |

These values apply only to the controlled corpus. Pattern-based detection can
miss novel attacks or flag novel benign language; Phase 4 authorization remains
the primary confidentiality boundary.

## Local validation recorded

- Full pytest: 93 passing tests.
- Ruff: passing.
- Python compilation: passing.
- Phase 5 evaluator: passing.
- Frontend TypeScript lint and production build: passing.

## Remaining release evidence

- Authenticated browser E2E for benign, blocked, extraction, role-claim,
  cross-tenant, indirect-injection, and Finance Reader scenarios.
- Live Docker service readiness and explicit dependency-failure probes.
- Independent application-security/code review and final release matrix.
