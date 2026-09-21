# ADR-019: Phase 5 adversarial-input and context defense

## Context

Phase 4 establishes canonical identity, RBAC/ABAC, a server-owned
`RetrievalScope`, Qdrant candidate filtering, and PostgreSQL authoritative
candidate admission. User queries and retrieved text remain untrusted. An
approved document is authorized data, not application instruction.

## Decision

Add local deterministic security analysis at two narrow boundaries:

```text
authenticated request -> canonical context -> query validation -> input analysis
-> Phase 5 policy -> Phase 4 secured retrieval -> context inspection
-> context construction -> grounded generation -> citation
```

Input analysis runs before embedding/retrieval. A `BLOCK` result returns a stable
policy response without protected retrieval. `ALLOW` and `ALLOW_AND_LOG` continue
through the unchanged Phase 4 path. Detection never contributes tenant, role,
classification, ACL, lifecycle, or Qdrant filters.

Context inspection runs only after the existing Qdrant and PostgreSQL admission
path, but before `ContextBuilder`. It can allow, log, drop a chunk, or block the
request. Dropped chunks never reach context, generation, citations, or the API.

Both guards use bounded normalization and deterministic multi-signal indicators.
They fail closed: exception, malformed decision, or required security-event
persistence failure prevents further protected processing and returns a generic
security-service-unavailable response. No model-only fallback is allowed.

Security events are minimized server-side evidence. They use allowlisted IDs,
categories, scores, versions, stage/outcome, and timings; they do not retain raw
prompts, retrieved content, credentials, cookies, tokens, or detector rules.
Event dashboards/read APIs are not Phase 5 scope.

## Consequences

- Phase 4 remains the confidentiality authority even if every Phase 5 detector
  signal is missed or deliberately returns `ALLOW`.
- Deterministic patterns provide measurable defense in depth, not universal
  prompt-injection prevention.
- The current extractive generator has no tool interface, but its contract will
  explicitly distinguish fixed trusted instructions from untrusted question and
  reference material for future providers.
- The implementation adds no production LLM classifier or new dependency.

## Alternatives rejected

- Treat detector output as authorization: violates Phase 4 invariants.
- Prompt wording alone: cannot establish an authorization or execution boundary.
- Scan only user input: misses malicious instructions in authorized documents.
- Persist raw prompts/chunks: creates a second sensitive corpus.
