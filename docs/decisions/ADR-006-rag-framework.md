# ADR-006: Direct RAG orchestration

## Context
Abstraction can obscure authorization filters, context assembly, and prompts.

## Decision
Use explicit project-owned query, retrieval, context, generation, and output interfaces; evaluate LangChain/LlamaIndex only behind non-authoritative adapters.

## Alternatives and reasoning
Frameworks accelerate prototypes but may hide security-sensitive behavior. Direct orchestration makes checkpoints observable and testable.

## Implications
More implementation work, but durable control over filters and failure gates. Phase 2 creates the baseline implementation behind these interfaces.
