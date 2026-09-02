# ADR-015: Explicit approval state machine

## Decision
Safe scans produce `REVIEW_REQUIRED`; high-confidence instruction/hidden-Unicode signals produce `QUARANTINED`; only explicit development approval can start indexing.

## Tradeoff
Manual review delays availability but prevents parser/scan success from becoming automatic trust. Phase 4 replaces the development control with real authorization.
