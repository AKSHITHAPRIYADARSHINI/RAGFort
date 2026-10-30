# Phase 5 application security and architecture review

Reviewed 2026-09-29 against existing P5-REQ-001 through P5-REQ-015 and inherited
Phase 4 authorization boundaries. This review uses the security-best-practices
skill; production deployment hardening beyond these requirements is not a release gate.

Application Security Reviewer: PASS. Security Architect: PASS. The independent
final review verified the three code fixes and the patched Next.js 15.5.26
dependency; remaining dependency advisories are classified below by reachability.
Separate runtime/browser/release evidence gates still apply. This review
does not substitute unit tests for live runtime evidence.

## Findings corrected during this review

1. RELEASE BLOCKER, P5-REQ-011: `QueryService` discarded context inspections, so
   authorized documents containing detected indirect injection produced no security
   event. The real query service now reports each detected context inspection to
   the authenticated route before context construction; the route persists only
   minimized, canonically attributed evidence. Required persistence failure returns
   `SECURITY_ANALYSIS_UNAVAILABLE`, without context, generation, or citations.
   The metadata allowlist previously rejected its own `context_decision` member
   because `context` contains `text`; exact allowlist validation corrects this.
2. RELEASE BLOCKER, P5-REQ-007: unexpected detector exceptions/malformed output
   escaped the established availability contract. `InputSecurityAnalyzer` now wraps
   unexpected detector failures in the existing typed unavailable exception and
   validates the result type. Failure still cannot proceed to protected retrieval.
3. RELEASE BLOCKER, P5-REQ-009: admitted context lost server-only inspection
   provenance. The context guard now attaches its generated provenance to an
   admitted chunk copy, replacing any vector-supplied provenance. ContextBuilder
   retains it, while context text and citations do not expose it. A regression
   verifies all required fields and that supplied provenance cannot override it.

The original reviewer implemented these fixes at the coordinating agent's direction.
A fresh independent reviewer subsequently inspected the final patch and reran the
same five test modules using `--basetemp=.pytest-appsec-final`: **41 passed** in
2.24 seconds, with one existing Starlette/httpx deprecation warning. The temporary
test directory was removed after the run. No production edits were made by the
independent reviewer.

Independent source traces confirm that `backend/app/main.py:353` canonically
attributes context events and supplies the callback to the production query;
`backend/app/rag/service.py:79` invokes that callback before context construction;
`backend/app/security/audit.py:68` translates SQL persistence failures into the
typed security-availability failure. `backend/app/security/analyzer.py:15` validates
detector output and wraps unexpected exceptions. The context guard replaces
vector-supplied `phase5_provenance`; ContextBuilder preserves the admitted object,
while CitationFormatter exports only its explicit source fields. These findings
independently confirm closure of the three code blockers above.

## Executed unit/integration evidence

Command: `.venv/Scripts/python.exe -m pytest tests/functional/test_query_api.py
tests/unit/test_context_guard.py tests/unit/test_security_contracts.py
tests/unit/test_security_events.py tests/unit/test_query_service.py
--basetemp=.pytest-review-tmp4`

Result: **41 passed**, one existing Starlette/httpx deprecation warning.
Focused Ruff check passed after formatting correction.

- New negative tests: context event persistence failure stops context construction;
  detector RuntimeError and malformed detector return fail with typed unavailability;
  client tenant, role, scope, risk score, and decision fields are rejected with 422
  before the query service executes.
- Context event test inspects actual event identity, tenant, request correlation,
  drop decision, source, absence of raw payload, and empty answer/citation result.
- Existing tests cover malicious chunks dropped, missing provenance, malformed
  context detector output, benign security vocabulary, minimized SQL event fields,
  and input event persistence failure.
- Direct controlled probe: established ASCII, zero-width, and fullwidth injection
  variants return BLOCK; benign prompt-injection/data-exfiltration discussion ALLOW.
- Adversarial length probes: 16,384-character base64 input ~24 ms; 14,880-character
  repeated near-match ~23 ms; 16,384-character NFKC expansion ~899 ms. These timings
  are diagnostic observations on this machine, not performance guarantees.
- Route enumeration: one protected query route (`/api/v1/query`); no security-event
  read surface. Event visibility authorization is therefore not applicable.
- Code inspection: bounded regex wildcards, fixed input-length normalization,
  server-created request IDs, fixed event category/indicator codes, exact metadata
  allowlist, SQL parameterized persistence, generic public errors. No query/chunk
  logging statement was found in the application security path.

## SQLite artifact investigation

`ragfort-documents.db` was untracked (159,744 bytes). Read-only SQLite inspection
found zero documents, document versions, tenants, users, roles, memberships, or
membership roles. Exactly two security events existed, both with synthetic
`usr_query_test`, `tenant_acme`, `det_test`, `/api/v1/query`, `blocked` values.

`test_query_api_blocks_direct_injection_before_query_service` replaced the detector,
policy, identity and query service but did not replace `get_security_event_sink`.
That sink initializes the default `sqlite:///./ragfort-documents.db` through
`get_document_session_factory`. This explains the file and its contents. An
autouse in-memory event fixture now isolates this test module. The file contains
only synthetic test evidence and must not be committed. This observation alone
does not establish the running container's database; the runtime review must
independently verify its PostgreSQL configuration.

## Non-blocking technical debt

- NFKC can expand a bounded original input: the synthetic maximum expansion probe
  grew 16,384 original characters to 294,912 normalized characters. The work remains
  bounded but a normalized-output cap may improve resource controls later.
- Existing local development OIDC/session and extractive-generation deployment
  restrictions remain as documented; this review introduces no production-hosting
  requirements or generalized prompt-injection prevention claim.

## Dependency-audit release blocker: corrected

The original release candidate pinned Next.js 15.3.2 and React/React DOM 19.1.0 in
`frontend/package.json`. `frontend/src/app/layout.tsx` is an App Router server
layout. The maintainer's [React Server Components RCE advisory](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp)
identifies affected Next.js App Router releases and unauthenticated remote code
execution. Version 15.3.2 is affected. This is a RELEASE BLOCKER against inherited
threat T12 and dependency evidence gate CI-DEPS-001 (`docs/threat-model.md:40`,
`docs/security-traceability.md:18`), which map supply-chain compromise to INV-005
and INV-008. Executing attacker-controlled code in the serving process defeats
artifact integrity and permits access to that process's files and credentials.

The additional maintainer [Windows-hosted RCE advisory](https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36)
covers versions before 15.5.24 on a Windows filesystem. The coordinator subsequently
confirmed the original frontend was a Windows Next server (PID 24388).
The cross-platform App Router RCE is sufficient to block independently.

Evidence is the reproducible dependency inventory/audit plus maintainer-confirmed
application configuration. No RCE exploit was executed against the user's host.
The final candidate pins Next.js **15.5.26**, with regenerated lockfile. Independent
inspection of the installed package also returned 15.5.26. QA executed the final
audit (zero critical advisories), TypeScript check (PASS), and production build
(PASS). Patched live frontend restart and browser evidence are separate coordinator
gates; this code/dependency review does not claim their completion.

Remaining npm audit groups are NON-BLOCKING TECHNICAL DEBT for this candidate:

- PostCSS: GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp,
  GHSA-r28c-9q8g-f849. The [upstream advisory](https://github.com/advisories/GHSA-6g55-p6wh-862q)
  requires attacker-controlled CSS; this application compiles checked-in CSS and
  exposes no CSS processing/upload feature. The Next moderate group is inherited
  from PostCSS, rather than an outstanding direct Next RCE advisory.
- Sharp: GHSA-f88m-g3jw-g9cj and GHSA-rgj7-g3m4-5g8c. The [maintainer advisory](https://github.com/advisories/GHSA-f88m-g3jw-g9cj)
  applies to processing untrusted images. Source inspection found no image imports,
  user image hosting, Next API routes, server actions, middleware or custom config.
  The built server config has empty image domains/remotePatterns; the routes
  manifest has no rewrites. Thus no attacker-image path to the decoder was found.
  This is a scoped reachability assessment, not a claim that Sharp is patched.
- QA's Python audit found advisory rows only in developer/build packages pip and
  pytest, with no demonstrated application runtime path. Their remediation is debt.

No remaining finding reproduces a violation of the established Phase 4/5 critical
invariants. Reassess the above reachability if CSS/image processing or deployment
exposure changes. Audit exit status remains nonzero; it is not recorded as a
zero-vulnerability scan.

All detector observations apply only to controlled synthetic inputs. Live service
failure/recovery, browser sessions, event rows from live attacks, and the final
frozen matrix are owned by the release coordinator and remain separate evidence.
