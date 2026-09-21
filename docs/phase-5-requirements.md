# Phase 5 requirements

Phase 5 adds deterministic adversarial-input and retrieved-context controls as
defense in depth. It never grants access, alters a `RetrievalScope`, or replaces
the Phase 4 authorization boundary.

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| P5-REQ-001 | Analyze each valid protected query before embedding/retrieval. | A `BLOCK` decision performs no embedding, retrieval, context build, generation, or citation. |
| P5-REQ-002 | Preserve original input and normalize a bounded security-analysis copy. | Unicode/control/whitespace variants are analyzed without mutating the query used by normal processing. |
| P5-REQ-003 | Use explicit server-owned detection and policy contracts. | Clients cannot supply score, category, decision, tenant, role, or scope. |
| P5-REQ-004 | Use deterministic multi-signal attack classification. | Direct injection, extraction, role/tenant manipulation, exfiltration, retrieval/context manipulation, encoded payloads, and tool-abuse language have corpus coverage; a single phrase is not decisive. |
| P5-REQ-005 | Separate detector scoring from enforcement. | Policy returns only `ALLOW`, `ALLOW_AND_LOG`, or `BLOCK` deterministically. |
| P5-REQ-006 | Return non-sensitive blocked/unavailable responses. | No detector rules, thresholds, sources, context, citations, or model-only answer are disclosed. |
| P5-REQ-007 | Fail closed when input analysis cannot establish a result. | Detector/normalizer failure prevents protected retrieval and maps to a stable availability result. |
| P5-REQ-008 | Inspect Phase-4-authorized chunks before context construction. | Malicious indirect instructions are dropped or block the request before context, generation, and citation. |
| P5-REQ-009 | Preserve server-only context provenance. | Admitted chunks retain document/version/chunk, Phase 4 admission, and Phase 5 inspection state. |
| P5-REQ-010 | Make prompt trust levels structurally explicit. | System/application instructions remain fixed; user query and retrieved material are untrusted data. |
| P5-REQ-011 | Create minimized structured security events. | Events contain safe IDs, subject/tenant, category, score/action, versions, stage/outcome, and timing; no raw prompt, chunk, token, cookie, or rule text. |
| P5-REQ-012 | Preserve Phase 4 independently of detection. | A detector `ALLOW` cross-tenant attack still has zero forbidden chunks/citations and no tenant leakage. |
| P5-REQ-013 | Supply synthetic attack and benign corpora plus a repeatable evaluator. | The evaluator reports expected/actual decision, admission, event, latency, detection/block/false-positive/false-negative rates, and exits nonzero on critical invariant failure. |
| P5-REQ-014 | Keep client UX minimal and safe. | UI distinguishes grounded, insufficient-context, security rejection, and unavailable states without detector internals. |
| P5-REQ-015 | Record implementation and release evidence honestly. | Ledger links requirement, threat, owner, invariant, tests, actual result, reviewer, commit, and evidence. |

Critical release assertions for the controlled corpus are:

```text
cross_tenant_leakage = 0
forbidden_chunks = 0
forbidden_citations = 0
malicious_context_admission_rate = 0
```

Rates describe only the version-controlled synthetic corpus; they are not a
claim of universal prompt-injection prevention.
