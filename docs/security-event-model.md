# Security Event Model

Events are immutable, schema-versioned, UTC-correlated records. The base record includes `event_id`, `request_id`, `correlation_id`, `timestamp`, `stage`, `category`, `severity`, `risk_score` (0–100), `action`, pseudonymous `tenant_id`/`user_id`, `policy_version`, signals (`rule_id`, detector, confidence, evidence reference), `retrieval_executed`, `llm_called`, `data_exposed`, outcome, and latency. Store no raw prompt, document body, model output, secret, or unrestricted PII by default.

Categories: `PROMPT_INJECTION`, `INDIRECT_PROMPT_INJECTION`, `DOCUMENT_POISONING`, `UNAUTHORIZED_ACCESS`, `CROSS_TENANT_ACCESS`, `SENSITIVE_DATA`, `SECRET_EXPOSURE`, `DOCUMENT_INTEGRITY`, `CORPUS_EXTRACTION`, `RETRIEVAL_ANOMALY`, `RATE_LIMIT`, `POLICY_VIOLATION`, and `SECURITY_SERVICE_FAILURE`.

Severity is `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`; actions are `ALLOW`, `ALLOW_MONITOR`, `REDACT`, `THROTTLE`, `DENY`, `BLOCK`, and `QUARANTINE`. Risk scoring is versioned and explainable. A deterministic violation blocks independently of score.
