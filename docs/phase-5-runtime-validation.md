# Phase 5 controlled runtime evidence

Runtime/DevSecOps reviewer: PASS for the controlled local runtime gates below.
This is not authenticated browser evidence. All observations were executed on
2026-09-29 after rebuilding the API from the frozen production sources.

## Configuration and recovery

Inside the running API, the document session factory engine reported dialect
`postgresql`, host `postgres`. `get_request_context_dependency` supplies this
factory to `SqlAlchemyRequestContextResolver`; document lifecycle uses the same
factory, and `get_query_service` supplies its PostgreSQL authoritative version
validator to Qdrant retrieval. No SQLite fallback was used by this container.
The running objects were `ContextSecurityGuard` and `SqlAlchemySecurityEventSink`.
Qdrant candidate URL was `http://qdrant:6333`; Keycloak issuer was
`http://localhost:8080/realms/ragfort-local` with internal Keycloak JWKS URL.

SHA-256 comparison of all 36 `backend/app/**/*.py` files in the running container
against the workspace found zero differences after the rebuild. This verifies
source identity rather than relying on image creation time or the Phase 1
`/health/ready` endpoint. API, PostgreSQL, Qdrant and Keycloak all reported healthy
after the outages. `pg_isready` reported accepting connections. API liveness,
frontend `http://localhost:3000`, Qdrant health and Keycloak realm discovery each
returned HTTP 200. `docker compose config --quiet` exited 0.

## Controlled corpus setup

The first baseline returned insufficient context. Investigation found 26 Qdrant
candidates but no corresponding authoritative viewer-accessible PostgreSQL marker
documents. This was correct Phase 4 rejection of non-authoritative candidates.
`evaluation/phase5_runtime_seed.py` inserted five explicitly named `p5_*` synthetic
documents and versions into PostgreSQL and five corresponding Qdrant chunks.
It preserved unrelated lifecycle records and did not reset the collection.

The indirect fixture intentionally bypasses ingestion scanning solely to model an
already-authorized poisoned document. Its authorization remains legitimate; its
text must still pass query-time context security. This is not a production
admission path. The other fixtures cover ACME, GLOBEX, Finance ACL/classification,
and benign security training. Re-running the seed checks existing fixture content.

## Listening API dependency outages

Reproduction: `.venv/Scripts/python.exe -m evaluation.phase5_runtime_probes --execute-outages`.
This uses the existing isolated `ragfort-runtime-test` OIDC password-grant client
and silently reads synthetic credentials from ignored local configuration. It
is distinct from the browser PKCE flow. Each service is restored in `finally`.

| Observation | Actual result | Request ID |
| --- | --- | --- |
| Authorized baseline | 200, grounded, one citation | `req_ef50f13834de4399b4c849155eccdbd2` |
| PostgreSQL stopped | 500 `INTERNAL_ERROR`, no answer or citation | `req_d9be277c701c481b812aad036396e05e` |
| PostgreSQL recovery | 200, grounded, one citation | `req_df352b90b8f349279fd69d8a6a95b470` |
| Qdrant stopped | 503 `RAG_RETRIEVAL_UNAVAILABLE`, no answer or citation | `req_3f95efca34fd48f79f9d8884987d8ad0` |
| Qdrant recovery | 200, grounded, one citation | `req_9e944452676d44ce8b9f3ccec8b576aa` |

The HTTP outage observations establish no response/citation fallback. Internal
call counts are measured separately below, not inferred from these HTTP bodies.
PostgreSQL's generic 500 is safe and fails closed. Mapping this condition to a
typed 503 is non-blocking technical debt; the established gate does not require
a specific PostgreSQL error status.

## Isolated container-process fault injection

Reproduction: `Get-Content evaluation/phase5_container_faults.py -Raw | docker compose exec -T api python -`.
The harness executes production route and services in a separate container
process with live PostgreSQL and Qdrant, canonical database-resolved ACME identity,
and explicit test-only failed dependencies. It bypasses OIDC in that process and
does not alter the listening API. Therefore these are container-process runtime
observations, not live HTTP listener outage or browser observations.

| Fault | Actual result | Retrieval / context / generation / citation calls |
| --- | --- | --- |
| Detector unavailable | 503 `SECURITY_ANALYSIS_UNAVAILABLE` | 0 / 0 / 0 / 0 |
| Context inspection unavailable | 503 `SECURITY_ANALYSIS_UNAVAILABLE` | 1 / 0 / 0 / 0 |
| Event persistence unavailable | 503 `SECURITY_ANALYSIS_UNAVAILABLE` | 0 / 0 / 0 / 0 |

Request IDs respectively: `req_a357d1cfcd2c41378461eab57a123655`,
`req_3d86dac07e24427b98f1dc12667546b7`, and
`req_7a5ddcd5bdcd411da64a7ef69d6d4fe3`. Removing each injected failure returned
200 grounded. Ruff passed for all three new evaluation scripts.

## Actual security event inspection

Live direct injection returned 403 `SECURITY_POLICY_REJECTED`, zero citations,
request `req_453ec4d0c986439da1a8757634d35a17`. Live indirect query
`ORBIT-INDIRECT-551` returned 200 insufficient context, zero citations, request
`req_60c65a9872a042c7b703e4c817794ae6`. Two corresponding PostgreSQL events were
inspected: canonical tenant `tenant_acme`, actions `block`, outcomes `blocked`
and `drop_chunk`. Direct safe metadata contained only `source=input_security`;
indirect metadata contained `source=context_security`, `context_decision=drop_chunk`,
and `retrieval_executed=true`.

The table has only event/time/request/detection/subject/tenant IDs, categories,
severity, risk score, policy action, detector/policy version, route, outcome,
indicator codes and safe metadata. Actual rows passed metadata allowlist and
credential/bearer/JWT/cookie/raw-attack/fixture-marker pattern checks. No raw
prompt, full chunk, credentials, or internal detector rules were stored. There
is no event-read route, so a tenant event-read authorization probe is inapplicable.

Within the controlled Phase 5 runtime scenarios, these observations satisfy the
reviewed runtime gates. They make no claim about unseen attacks.
