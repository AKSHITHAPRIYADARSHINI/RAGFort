# Independent Phase 5 QA review

Date: 2026-09-29. Baseline commit: `c52b0f23f4e21e6f81386d0c91206b153245a9d2` plus the frozen candidate changes. This review did not implement the Phase 5 integration or evaluator. Initial board result: BLOCKED pending the dependency remediation and outstanding authenticated browser/runtime evidence below.

## Executed unit/integration and controlled-corpus evidence

All commands ran from the repository root unless stated otherwise; Python executable was `.venv/Scripts/python.exe`.

| Command | Actual result |
| --- | --- |
| `python -m pytest -p no:cacheprovider --basetemp=.pytest-qa-final-tmp` | 128 passed, 668 deprecation warnings, 13.52 seconds |
| `python -m ruff check .` | All checks passed |
| `python -m compileall -q backend evaluation tests` | Exit 0 |
| `npm run lint` (frontend) | TypeScript check exit 0 |
| `python -m pytest -p no:cacheprovider --basetemp=.pytest-qa-focused-tmp tests/security tests/integration/test_phase4_secure_retrieval.py tests/integration/test_phase5_authorization_regression.py tests/integration/test_phase5_independent_authorization.py tests/unit/test_context_guard.py` | 47 passed, 591 deprecation warnings, 5.94 seconds |
| `python -m evaluation.run` | Exit 0; 20 documents/chunks; recall and hit rate 1.0 at k=3,5,8; MRR 0.9; precision 1/3, 0.2, 0.125 respectively |
| `python -c "from evaluation.phase5_attack_evaluation import evaluate; import json; r=evaluate(); print(json.dumps({'corpus':r['corpus'],'metrics':r['metrics'],'executed_records':len(r['records']),'passed_records':sum(x['passed'] for x in r['records'])},indent=2))"` | Exit 0; all 24 executed records pass (15 attack, 8 benign, one additional cross-tenant ALLOW probe) |
| `python -m pip check` | No broken requirements found |
| `git diff --check` | Exit 0; informational LF/CRLF conversion warnings only |

Within the controlled Phase 5 evaluation corpus, the measured rates are:

| Metric | Value |
| --- | --- |
| attack_detection_rate | 1.0 |
| attack_block_rate | 0.6666666666666666 (10/15) |
| false_positive_rate | 0.0 |
| false_negative_rate | 0.0 |
| indirect_injection_detection_rate | 1.0 |
| malicious_context_admission_rate | 0.0 |
| cross_tenant_leakage | 0 |
| forbidden_chunks | 0 |
| forbidden_citations | 0 |

These are synthetic fixtures with an in-memory SQL authority and Qdrant instance, not live OIDC/browser evidence. The Phase 2 runner regenerated the tracked retrieval JSON with actual timings; it does not reseed runtime services.

The two metric test modules contain 18 tests, including the real corpus checks and injected negative observations. Independent inspection confirms aggregation reads observed retrieval, context, response, and citations rather than assigning final perfect metrics. Negative controls deliberately admit a foreign chunk, forbidden policy chunks (classification, ACL, lifecycle, version, stale state), a foreign citation, and malicious context. Additional controls change detection outcomes, inject foreign response/context markers, mismatch an allowed chunk ID with a foreign document citation, and exercise undefined zero denominators. The release gate rejects forbidden outcomes. The independent authorization module forces Phase 5 ALLOW at the query handler and observes the unchanged canonical viewer identity and ACME RetrievalScope; SQL authority mutations override stale vector metadata across seven authorization/lifecycle cases.

## Dependency and secret-pattern review

`npm audit --json --cache ../.npm-cache` initially exited 1 with three vulnerable dependency groups: Next 15.3.2 (critical), postcss (high), and sharp (high). The [Next.js vendor advisory](https://nextjs.org/blog/CVE-2025-66478) confirms the React Flight RCE applies to this App Router architecture. This violates the existing confidentiality/integrity boundary and is a RELEASE BLOCKER. Registry verification `npm view next@15.5.26 version --cache ../.npm-cache` returned `15.5.26`; its exact pin is the scoped remediation being validated. No unrelated direct dependencies are being upgraded.

Python dependency audit initially encountered an installed `tomli` extension error. The audit was rerun with the standard-library `tomllib` injected for that audit process only, without changing repository/runtime code:

`python -c "import sys,tomllib,runpy; sys.modules['tomli']=tomllib; sys.argv=['pip-audit','--progress-spinner','off','--cache-dir','.pip-audit-cache']; runpy.run_module('pip_audit',run_name='__main__')"`

After the sandbox network restriction was resolved through explicit escalation, this exited 1 with 14 advisory rows (including duplicate advisory IDs) in two developer/build packages: pip 24.2 and pytest 8.4.2. No installed runtime dependency advisory rows were returned; the local ragfort distribution cannot be audited against PyPI. These developer-tool findings are NON-BLOCKING TECHNICAL DEBT absent evidence of an exposed runtime path. This result does not claim a clean all-environment vulnerability scan.

A repository scan over backend, frontend, evaluation, tests, and docs for private-key PEM headers, AWS access-key IDs, GitHub token patterns, and OpenAI project-key patterns returned no matches. This is a limited pattern review, not proof that every possible secret format is absent. Test fixtures deliberately contain synthetic markers/identities. Runtime event minimization is reviewed separately with actual runtime evidence.

## Final frozen-candidate rerun

On resumption, independently reran the current candidate without changing production code or dependencies:

| Gate | Actual final result |
| --- | --- |
| Full pytest, `--basetemp=.pytest-qa-resume-tmp` | 128 passed, 668 warnings, 14.14 seconds |
| Focused security/Phase 4/Phase 5/context suite | 47 passed, 591 warnings, 7.50 seconds |
| Both metric-integrity modules | 18 passed, 504 warnings, 4.63 seconds |
| Ruff / Python compilation / pip check | All passed |
| Phase 2 evaluation | Exit 0; 20 documents/chunks, recall/hit 1.0 and MRR 0.9 at each k |
| Phase 5 evaluation | Exit 0; 24/24 records pass; 15 attacks, 8 benign; all nine metrics unchanged from the table above |
| Frontend TypeScript lint | Exit 0 |
| Frontend production build, Next 15.5.26 | Exit 0; three prerendered routes; compiled and type checked |
| `git diff --check` | Exit 0, LF/CRLF notices only |

The initial sandboxed build failed on Windows ancestor-directory `readlink` permission. The authorized escalated rerun completed successfully; no application change was needed. Next reported multiple ancestor lockfiles when choosing the tracing root; this build warning is non-blocking technical debt.

The final `npm audit --json --cache ../.npm-cache` completed its registry query and exited 1: zero critical, one moderate group (Next via PostCSS), two high groups (PostCSS and sharp). It no longer reports a direct Next advisory. The original Next RCE blocker is resolved by 15.5.26. This is not a claim that npm audit is clean.

Residual PostCSS advisory IDs are GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp, and GHSA-r28c-9q8g-f849. The maintainer advisories describe [untrusted CSS stringification into HTML](https://github.com/postcss/postcss/security/advisories/GHSA-qx2v-qp2m-jg93) and [attacker-controlled CSS source-map loading](https://github.com/postcss/postcss/security/advisories/GHSA-6g55-p6wh-862q). Repository inspection finds only checked-in CSS and no user-CSS compilation or HTML stringification surface. Residual sharp IDs are GHSA-f88m-g3jw-g9cj and GHSA-rgj7-g3m4-5g8c; the [maintainer advisory](https://github.com/lovell/sharp/security/advisories/GHSA-rgj7-g3m4-5g8c) requires processing untrusted image input. This frontend has no image upload/serving route, next/image use, remote-image patterns, or custom rewrite configuration. Backend document uploads are not exposed as frontend image assets. These applicability conclusions are source-based inferences, not exploit tests. No reproducible violation of an established release invariant was found for these remaining advisories, so they are NON-BLOCKING TECHNICAL DEBT; reevaluate before adding CSS/image processing surfaces.

Deprecation warnings in datetime handling and the Starlette/httpx test-client adapter remain NON-BLOCKING TECHNICAL DEBT. Runtime failure/recovery evidence is separately recorded in `docs/phase-5-runtime-validation.md`; it is not relabeled as browser evidence here. Final authenticated browser evidence and clean closure commit remain the coordinating agent's release gates. The executed unit/integration, metric, controlled-corpus, build, and dependency-applicability QA gates PASS.
