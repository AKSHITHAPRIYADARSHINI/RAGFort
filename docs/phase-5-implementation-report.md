# RAGFort Phase 5 implementation report

## Status

**Release-candidate freeze; closure pending final board.** Production changes are
limited to existing requirements. This report separates executed test, corpus,
runtime, browser and review evidence. No Phase 6 work is included.

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
controls, plus one separate cross-tenant probe that actually receives detector
ALLOW. All 24 executed records pass. The runner calls the production query
handler with a fixture-authenticated ACME viewer, isolated in-memory SQL authority
and Qdrant, actual context inspection, generation, citations and an observed event
sink. This is controlled integration evidence, not live OIDC or PostgreSQL evidence.
It exits nonzero when expectations or critical admission invariants fail.

| Metric | Controlled-corpus result |
| --- | ---: |
| attack_detection_rate | 1.0 |
| attack_block_rate | 0.6666666666666666 (10/15) |
| false_positive_rate | 0.0 |
| false_negative_rate | 0.0 |
| indirect_injection_detection_rate | 1.0 |
| malicious_context_admission_rate | 0.0 |
| cross_tenant_leakage | 0 |
| forbidden_chunks | 0 |
| forbidden_citations | 0 |

Within the controlled Phase 5 evaluation corpus, these measured values apply only
to the executed synthetic cases. Pattern-based detection can
miss novel attacks or flag novel benign language; Phase 4 authorization remains
the primary confidentiality boundary.

### Metric derivation and correction

The previous evaluator assigned constant zero to leakage, forbidden chunks and
forbidden citations. It inferred retrieval/event execution from policy, counted
expectation mismatches as false negatives, and counted context drops as detection.
Those were insufficient release measurements and have been replaced.

| Input evidence | Observation and counter | Aggregation / reported metric |
| --- | --- | --- |
| Labeled attack corpus; actual route analyzer and guard results | Cases with observed input or malicious-context detection | detected attacks / 15 = attack_detection_rate; undetected attacks / 15 = false_negative_rate |
| Actual query-handler responses for labeled attacks | SECURITY_POLICY_REJECTED responses | blocked attacks / 15 = attack_block_rate |
| Labeled benign corpus; observed detections | Benign cases with a detection | detected benign cases / 8 = false_positive_rate |
| Malicious fixture chunk IDs presented to the actual guard | Presented IDs, detected IDs, dropped IDs | detected malicious chunks / 3 = indirect_injection_detection_rate |
| Actual ContextBuilder output for indirect cases | Presented malicious IDs also present in admitted context | admitted malicious chunks / 3 = malicious_context_admission_rate |
| Retrieved chunks, constructed context, actual answer and citations | Foreign tenant payload or unique foreign marker observed in any protected output; affected case counted once | sum of affected executed cases = cross_tenant_leakage |
| Actual admitted context and independent fixture eligibility labels | Each chunk not in expected authorized/safe set | sum = forbidden_chunks |
| Actual formatted sources and expected chunk/document mapping | Each forbidden chunk citation or mismatched document identity | sum = forbidden_citations |

Every execution records the fixture-authenticated tenant, target tenant where
applicable, expected tenant, retrieved/admitted chunks, context, response,
citations, foreign markers, event count and retrieval/generation calls. The SQL
authority is exercised with foreign tenant, classification, ACL, lifecycle,
old-version and stale-vector fixtures. Eligibility labels are independent of the
implementation under test. No-sample rates are explicitly null; the release gate
rejects an empty corpus or unmeasured malicious-admission result.

The two metric test modules contain **18 passing tests**, including injected
foreign/forbidden chunks, sources with mismatched document IDs, foreign response
and context markers, missed detections, malicious admitted context and zero
denominators. These demonstrate that deliberately unsafe observations cannot
produce the reported perfect admission metrics.

## UNIT/INTEGRATION TEST EVIDENCE

Independent QA executed **128 passing pytest tests**, Ruff, Python compilation,
and the Phase 2 retrieval evaluator (20 documents; recall/hit 1.0 at k=3/5/8,
MRR 0.9). The focused security/authorization matrix passed 47 tests. The independent
authorization review passed 44 checks including forced Phase 5 ALLOW at the real
handler, tenant isolation, ACL/classification, department snapshot consistency,
current version, lifecycle, stale vectors, disabled accounts, epoch and IDOR/BOLA.
See [QA evidence](phase-5-qa-review.md) and
`tests/integration/test_phase5_independent_authorization.py`.

## LIVE RUNTIME EVIDENCE

[Runtime evidence](phase-5-runtime-validation.md) records actual PostgreSQL-backed
canonical identity, lifecycle and final authoritative revalidation; Qdrant candidate
retrieval; Keycloak issuer/JWKS; and source hashes of 36 backend files matching the
running image. Five prefixed synthetic fixtures were added without replacing
unrelated records. The poisoned fixture intentionally models an already-authorized
document and bypasses ingestion solely for this evaluation.

Actual PostgreSQL stop/query/start returned generic 500 with no answer/citation,
then recovered to grounded 200. Qdrant stop/query/start returned
RAG_RETRIEVAL_UNAVAILABLE 503, then grounded 200. Neither falls back to SQLite or
model-only responses. Exact request IDs and recovery results are in the runtime report.

Separate **container-process fault injection**, using live PostgreSQL/Qdrant and a
database-resolved synthetic principal, tested detector, context inspector and
mandatory event sink failure. Each returned SECURITY_ANALYSIS_UNAVAILABLE 503,
with zero context/generation/citation calls; input detector/event failures also
had zero retrieval calls. Each recovered to grounded 200. This harness bypasses
OIDC only in its isolated process and is not represented as a browser or listening
API fault injection.

Actual direct and indirect PostgreSQL security events passed allowlisted-field
and credential/raw-payload checks. No event-read API exists; event-read tenant
authorization is therefore not applicable. No dashboard was added.

## AUTHENTICATED BROWSER EVIDENCE

Pending final patched-frontend scenarios. Real ACME OIDC authorization-code login
with S256 PKCE and HttpOnly session has been observed; scenario results will be
recorded only after their execution.

## INDEPENDENT REVIEW EVIDENCE

- [Application security and architecture](phase-5-application-security-review.md):
  three reproduced requirement gaps corrected (context events P5-REQ-011,
  detector availability P5-REQ-007, context provenance P5-REQ-009). Dependency
  review subsequently found vulnerable Next.js; compatible 15.x remediation is
  being verified before final approval.
- [Independent code review](phase-5-independent-code-review.md): PASS for reviewed
  code and 59 focused tests; includes independent scrutiny of production fixes.
- [QA](phase-5-qa-review.md): executed results and dependency/secret-pattern review.
- [Runtime/DevSecOps](phase-5-runtime-validation.md): PASS for scoped runtime gates.
- Final Security Auditor and final board: pending all preceding evidence.

## SQLite artifact and generated files

Read-only inspection traced untracked `ragfort-documents.db` to a functional
blocked-query test that used the real SQL event sink. It contained exactly two
synthetic events and zero documents/versions/identities. The test now isolates its
sink; the artifact was removed after investigation and explicitly ignored.
Runtime PostgreSQL configuration was verified independently. There is no automatic
PostgreSQL-to-SQLite failure fallback. Tool caches and temporary test/browser
artifacts are ignored and excluded from release evidence/commits.

## Non-blocking technical debt

Bounded NFKC expansion may merit a normalized-output cap; PostgreSQL outage currently
uses generic safe 500; evaluator records use dynamic dictionaries; migration/ORM
performance-index sets differ; datetime/httpx deprecations remain. Developer-only
pip/pytest advisory findings are recorded in QA evidence. These are not claims of
production deployment readiness or generalized injection prevention.
