# ADR-007: Next.js client with API-only access

## Context
The browser needs a polished experience without authority over data services or security policy.

## Decision
Use Next.js/React/TypeScript/Tailwind in Phase 2, calling only authenticated FastAPI endpoints.

## Alternatives and reasoning
Direct browser access to data/vector/LLM providers would leak secrets and bypass policy. Next.js supports a responsive enterprise UI while FastAPI stays the authority.

## Implications
No client-side authorization is trusted. The UI uses progressive disclosure and actual API evidence, never fabricated security results. Phase 1 documents UI only.
