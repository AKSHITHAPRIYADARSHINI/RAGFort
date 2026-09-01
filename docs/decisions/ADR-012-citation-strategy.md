# ADR-012: Retrieval-derived citations

`CitationFormatter` attaches document and chunk identifiers only from the bounded `ContextPackage`. The generator cannot create source identity. This makes citation correctness independently testable and preserves provenance for later security controls.
