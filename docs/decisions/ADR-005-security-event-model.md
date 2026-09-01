# ADR-005: Minimized structured security events

## Context
RAG security must be auditable without creating a second sensitive corpus.

## Decision
Use versioned append-oriented event records with identifiers, stage/category/severity/action/risk, policy version, redacted signal references, outcome/latency, and retrieval/LLM/exposure flags.

## Alternatives and reasoning
Raw request logging is convenient but unsafe. Unstructured logs are hard to correlate. Separate protected evidence references preserve investigability with minimization.

## Implications
Event write acknowledgement is a security dependency for critical paths. Telemetry is planned for Phase 5/6; schema/privacy tests accompany it.
