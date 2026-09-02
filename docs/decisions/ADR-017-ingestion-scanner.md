# ADR-017: Minimized deterministic ingestion signals

## Decision
Use separate deterministic checks for suspicious instructions, hidden Unicode, and sensitive-data-like patterns; store category/severity/safe description rather than raw evidence.

## Security and tradeoff
This supports early quarantine/review without claiming universal prompt-injection or DLP prevention. Broader query/context detection remains Phase 5 and output DLP Phase 6.
