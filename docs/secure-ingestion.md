# Secure document ingestion

Phase 3 establishes an explicit boundary between untrusted uploads and the active RAG index. Supported types are UTF-8 TXT and Markdown. The server checks filename safety, an allowlisted extension, non-zero bounded bytes (1 MB), and text/binary consistency. Browser MIME is advisory only.

The pipeline is `validate -> extract -> normalize -> scan -> provenance/hash -> review or quarantine -> explicit development approval -> chunk/embed/index`. UTF-8 decoding is bounded and parser failures stop the pipeline. Text is NFKC-normalized before scanning; zero-width/bidi controls are removed and recorded as a high-severity finding. The deterministic scanner identifies instruction-like phrases, hidden Unicode, and synthetic sensitive-data patterns. It stores only category, severity, and safe description.

SHA-256 is recorded separately for original bytes and normalized content. Qdrant is a derived index only. Approved chunks carry server-owned version, classification, approval, index-state, content-hash, and scan-status metadata. A high-severity finding quarantines before indexing. A sensitive-data finding remains review-required. No browser can write Qdrant.

Phase 3 is not Phase 5: these are conservative ingestion signals, not a universal prompt-injection defense. Phase 4 must replace the development-only approval control with server-derived principal, tenant, and ABAC enforcement.
