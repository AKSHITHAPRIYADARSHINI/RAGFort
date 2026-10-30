# RAGFort Phase 5 implementation report

## Status

**PHASE 5 COMPLETE.** The final release matrix and independent review board
passed on the closure commit. Production changes are limited to the existing
Phase 5 requirements. This report records executed test, corpus, runtime,
browser, and review evidence. No Phase 6 work is included.

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

All nine requested scenarios passed against the rebuilt production frontend
(Next.js 15.5.26), matching API source, live PostgreSQL/Qdrant, and local Keycloak.
The ACME Employee session used the actual OIDC authorization-code flow with
S256 PKCE and an HttpOnly session; its canonical `tenant_acme`/`viewer` identity
was unchanged through eight scenarios. A separate Finance Reader browser context
authenticated through the same flow and retained its canonical
`tenant_acme`/`finance_reader`/`viewer` identity.

| Scenario | Observed result |
| --- | --- |
| Benign ACME retrieval | 200 grounded with the ACME fixture and marker |
| Direct injection | 403 `SECURITY_POLICY_REJECTED`, no answer or sources |
| System-prompt extraction | 403 `SECURITY_POLICY_REJECTED`, no answer or sources |
| Role manipulation | 403 `SECURITY_POLICY_REJECTED`; canonical roles unchanged |
| ACME-to-GLOBEX attack | No foreign marker, document, chunk, or citation; response used an authorized ACME security-training source |
| Explicit GLOBEX marker query | 200 insufficient context with no sources |
| Indirect malicious document | 200 insufficient context; null answer and zero sources; live event recorded `drop_chunk` |
| Benign cybersecurity terminology | 200 grounded in the ACME security-training fixture |
| Finance Reader query | 200 grounded with `FINANCE-ORCHID-815` and only authorized ACME sources |

The cross-tenant attack returning a harmless authorized ACME answer is expected
under the Phase 4 design: a detector decision never expands retrieval scope, and
server-side tenant/ACL authorization remains the confidentiality boundary. Exact
request IDs, response/source identities, and live event evidence are in the
[runtime report](phase-5-runtime-validation.md). The repeatable browser runners
are `evaluation/phase5_browser_cases.js` and
`evaluation/phase5_finance_browser_case.js`.

## FINAL INDEPENDENT REVIEW BOARD

Each reviewer reported **PASS** after examining the frozen release matrix and
production browser evidence. No reproducible violation of an existing Phase 4 or
Phase 5 requirement remains.

| Reviewer | Result | Evidence |
| --- | --- | --- |
| AppSec and Security Architecture | PASS | Safe block/unavailable envelopes, minimized live events, indirect context exclusion, controlled evaluation evidence, and preserved canonical retrieval scope; see [AppSec review](phase-5-application-security-review.md) |
| Authorization | PASS | 47 focused security/Phase 4/5 tests plus real ACME and Finance Reader role/tenant browser sessions |
| Independent Code | PASS | Browser runner assertions cover safe errors, no foreign output, zero malicious context sources, and Finance source eligibility |
| QA | PASS | Full test/evaluation/lint/build matrix passed; see [QA review](phase-5-qa-review.md) |
| Runtime/DevSecOps | PASS | 36/36 API source hashes match; all services healthy; five readiness endpoints returned HTTP 200; live event rows inspected |

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
