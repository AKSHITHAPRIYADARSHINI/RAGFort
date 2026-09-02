# ADR-014: Narrow file allowlist and byte validation

## Decision
Support UTF-8 TXT and Markdown only, with a 1 MB limit, safe filename extraction, and binary/text consistency checks.

## Alternatives and reasoning
Extension-only validation and broad Office support were rejected because they widen parser attack surface without adequate test coverage.

## Implications
Browser MIME is advisory. Unsupported, empty, malformed, encrypted, or parser-failing content cannot reach indexing.
