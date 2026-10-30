# Independent Phase 5 code review

Code Reviewer: PASS for reviewed code and executed component evidence, 2026-09-29.
This is not a release-board decision or a substitute for authenticated browser,
live PostgreSQL/Qdrant failure recovery, or final frozen matrix evidence.

Reviewed the production changes to input analysis, context inspection, query
orchestration and minimized event persistence, plus evaluator metric derivation,
configuration, SQLite initialization and the additive security-event migration.
No remaining reproducible violation of an existing critical requirement was
identified in this review.

The context callback persists detected inspections before building context or
generating an answer. Persistence failure propagates through the existing typed
security-availability response. The context guard adds server-generated provenance
to a copied chunk and replaces any vector-supplied provenance. The input analyzer
wraps unexpected detector exceptions and rejects malformed detector output.
These changes preserve the authoritative retrieval scope and Phase 4 SQL validator.
The exact event metadata allowlist fixes the previous accidental rejection of
`context_decision` without admitting arbitrary metadata keys.

The evaluator executes the production query handler with isolated SQL/Qdrant
fixtures. Counters observe retrieval results, constructed context, emitted sources,
responses and context inspections. Two evaluator corrections were made by this
reviewer at the coordinator's direction: observe the detector invocation performed
by the actual route instead of running a separate preliminary analysis; and
validate source chunk/document identity against independent fixture mappings so
an allowed chunk ID cannot hide a forbidden document citation. These narrow
evaluator edits should also be considered by the final independent auditor.

Executed command:

```text
.venv/Scripts/python.exe -m pytest tests/security/test_phase5_metric_integrity_review.py tests/security/test_phase5_evaluation.py tests/functional/test_query_api.py tests/unit/test_context_guard.py tests/unit/test_security_contracts.py tests/unit/test_security_events.py tests/unit/test_query_service.py -q --basetemp=.pytest-code-review-tmp
```

Result: 59 passed. Focused Ruff check of the evaluator and reviewer test file:
PASS. Negative controls cover retrieved foreign content, foreign markers in
context/response, forbidden sources with allowed chunk IDs, empty denominators,
and missed indirect detection, in addition to the coordinator's forbidden chunk,
source and malicious-admission regressions. Test observations apply only to the
controlled Phase 5 corpus and component fixtures.

Configuration inspection shows one configured SQL session factory is shared by
canonical identity, lifecycle and final retrieval validation. The default local
configuration uses SQLite when DATABASE_URL is absent; it does not catch a
PostgreSQL failure and switch databases. Running-container PostgreSQL configuration
must be established by the runtime reviewer. The reported local SQLite artifact
origin is consistent with the formerly unmocked event sink in functional tests;
the current test module isolates it with an in-memory sink.

Non-blocking technical debt: evaluator records use dynamically shaped dictionaries
rather than a typed evidence model; migration SQL and ORM index sets differ in
performance indexes (not confidentiality semantics); existing datetime/httpx
deprecation warnings remain. No new dependency was introduced by the reviewed
production fixes. Dependency vulnerability scanning remains a separate release
matrix check.
