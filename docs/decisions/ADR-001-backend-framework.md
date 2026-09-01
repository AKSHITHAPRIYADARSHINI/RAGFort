# ADR-001: FastAPI backend

## Context
RAGFort needs explicit, typed server-side security boundaries.

## Decision
Use Python 3.12+ with FastAPI and Pydantic v2; add SQLAlchemy/Alembic only when persistence begins.

## Alternatives and reasoning
Node/Express and Django were considered. FastAPI provides typed contracts and a small async API surface without a framework dictating security-sensitive orchestration.

## Implications
Strict validation reduces malformed input ambiguity; async supports I/O concurrency. The tradeoff is Python dependency hygiene and explicit middleware discipline. Phase 1 implements health only; Phase 2 tests API contracts.
