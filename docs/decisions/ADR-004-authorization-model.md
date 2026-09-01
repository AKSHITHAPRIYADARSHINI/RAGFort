# ADR-004: RBAC plus ABAC

## Context
Roles alone cannot represent tenant, classification, ownership, purpose, and document constraints.

## Decision
Use RBAC for coarse privileges and ABAC for tenant/document/context constraints, evaluated before retrieval.

## Alternatives and reasoning
RBAC-only is too coarse; LLM authorization is prohibited. This deterministic policy model is explainable and testable.

## Implications
Every query derives scope server-side, applies it pre-search, and records policy version. Complexity is managed with policy tests. Phase 4 implements it.
