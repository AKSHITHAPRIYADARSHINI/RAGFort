# ADR-011: Extractive local generation with no fallback

Generation is a protocol. Phase 2 uses an extractive development provider that selects only retrieved evidence. Any retrieval failure stops before generation; an OpenAI-compatible adapter may be added later behind the same protocol. This baseline grounding instruction is not an injection defense.
