# Phase 5 release-candidate implementation ledger

Scope frozen to P5-REQ-001–015 and inherited Phase 4 invariants. The baseline is
`c52b0f2`; final evidence/remediation belongs to the closure commit containing this
ledger, identified by the annotated `phase-5-complete` tag only after board approval.
No tag or completion is implied by a pending row.

| Requirement | Threat / invariant | Owner / implementation | Executed expected → actual evidence | Reviewer / release status |
| --- | --- | --- | --- | --- |
| P5-REQ-001 | TM-001, INV-005 | Backend: main.query, analyzer | BLOCK skips retrieval/context/generation/citations; observed corpus call counters and query API tests pass | Authorization + Code: PASS |
| P5-REQ-002 | TM-002 | Detection: normalization.py | Original input unchanged; bounded normalization, Unicode/control variants tested | AppSec: PASS; expansion-cap debt |
| P5-REQ-003 | TM-003, INV-001/002 | Backend: QueryBody, canonical context | Client tenant/role/scope/score/decision fields rejected with 422 before query service | AppSec + Authorization: PASS |
| P5-REQ-004 | TM-001–009 | Detection: detector.py | 15 attack cases cover established taxonomy; actual analyzer/category observations pass | QA + Code: PASS |
| P5-REQ-005 | TM-001/006 | Detection: policy.py | Deterministic ALLOW/ALLOW_AND_LOG/BLOCK; actual handler responses, 10/15 attacks blocked | QA + Code: PASS |
| P5-REQ-006 | TM-007 | Backend: safe error envelopes | Block/unavailable results omit context, sources and detector internals; API tests and runtime bodies inspected | AppSec + Runtime: PASS |
| P5-REQ-007 | TM-006/007, INV-005 | Backend: analyzer.py | Unexpected errors/malformed results now typed unavailable; detector fault 503, zero downstream calls, recovery grounded | AppSec fix independently reviewed by Code: PASS |
| P5-REQ-008 | TM-005/009, INV-012 | Context: context_guard.py, service.py | Three malicious chunks presented, three dropped, zero admitted; context failure skips construction/generation | QA + Runtime: PASS |
| P5-REQ-009 | TM-005, INV-012 | Context: generated phase5_provenance | Admitted copy retains document/version/chunk/auth/inspection state; vector-supplied provenance overwritten; no citation/prompt exposure | AppSec fix independently reviewed by Code: PASS |
| P5-REQ-010 | TM-005, INV-012 | ContextBuilder + extractive provider | Untrusted source delimiters; provider has no tools or secondary retrieval; malicious authorized fixture excluded | Code: PASS; browser indirect check pending |
| P5-REQ-011 | TM-007/008, INV-008 | Backend: events.py, audit.py, route callback | Input and context events persist before sensitive continuation; actual SQL rows minimized; mandatory failure 503 and recovery pass | AppSec + Runtime: PASS |
| P5-REQ-012 | TM-003/004, INV-001/002/006/011 | Authorization: SQL validator, RetrievalScope | Forced ALLOW leaves canonical ACME viewer unchanged; foreign results/citations denied; seven authoritative stale-vector mutations denied | Independent Authorization: PASS, 44 checks |
| P5-REQ-013 | TM-001–009 | Evaluation: phase5_attack_evaluation.py | 24 executed records: 15 attacks, 8 benign, one extra ALLOW isolation probe; all nine metrics derive from observations; 18 integrity regressions pass | QA + Code: PASS |
| P5-REQ-014 | TM-007 | Frontend: page.tsx, cookie-only client | Distinct grounded/insufficient/rejected/unavailable UI; TypeScript/build tests, authenticated scenarios pending final patched frontend | Browser gate pending |
| P5-REQ-015 | TM-001–009 | Release coordinator: report/review records | Separate unit/corpus/runtime/browser/review evidence with request IDs and scope qualifications | Final board pending |

## Evidence references

- [Implementation report and metric methodology](phase-5-implementation-report.md).
- [Independent AppSec / Security Architect review](phase-5-application-security-review.md).
- [Independent code review](phase-5-independent-code-review.md).
- [Independent QA matrix](phase-5-qa-review.md).
- [Runtime configuration, outages and recovery](phase-5-runtime-validation.md).
- Authorization evidence: `tests/integration/test_phase5_independent_authorization.py`,
  `test_phase5_authorization_regression.py`, `test_phase4_secure_retrieval.py`,
  auth-core/runtime and identity/document API test modules.

Release-blocking findings corrected during freeze: constant/inferred evaluator
metrics (P5-REQ-013/015), omitted context events (011), unexpected detector failures
(007), discarded inspection provenance (009), vulnerable Next.js dependency
(inherited T12 / CI-DEPS-001). Next.js 15.5.26 remediation requires final dependency,
frontend and browser verification. No new functional features were added.
