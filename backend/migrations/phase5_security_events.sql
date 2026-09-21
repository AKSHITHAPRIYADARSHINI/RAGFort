-- Phase 5: minimized structured security event evidence.
-- Raw prompts, chunks, credentials, cookies, tokens, and detector rules are
-- intentionally absent. The application creates this table additively through
-- SQLAlchemy metadata for local/dev SQLite compatibility.
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(40) PRIMARY KEY,
    occurred_at TIMESTAMP NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    detection_id VARCHAR(64) NOT NULL,
    subject_id VARCHAR(64),
    tenant_id VARCHAR(64),
    categories_json TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_score INTEGER NOT NULL,
    policy_action VARCHAR(24) NOT NULL,
    detector_version VARCHAR(64) NOT NULL,
    policy_version VARCHAR(64) NOT NULL,
    route VARCHAR(128) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    indicator_codes_json TEXT NOT NULL,
    safe_metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_security_events_request_id ON security_events (request_id);
CREATE INDEX IF NOT EXISTS ix_security_events_tenant_id ON security_events (tenant_id);
