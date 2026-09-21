"""Minimal, payload-safe contracts for Phase 5 security evidence.

Security events are internal audit evidence.  They deliberately retain security
decisions and opaque correlation identifiers, never the untrusted request body,
credentials, or detector implementation details.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import uuid4

from backend.app.security.models import (
    AttackDetectionResult,
    PolicyAction,
    SecurityPolicyDecision,
    Severity,
)

_SafeMetadataValue = str | int | bool
_FORBIDDEN_METADATA_NAMES = frozenset(
    {
        "payload",
        "prompt",
        "query",
        "text",
        "token",
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "cookie",
        "password",
        "secret",
        "credential",
    }
)
_SAFE_METADATA_FIELDS = frozenset(
    {
        "context_decision",
        "failure_stage",
        "retrieval_executed",
        "source",
    }
)
_SAFE_INDICATOR_CODE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")


def _require_nonempty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} is required")


@dataclass(frozen=True)
class SecurityEvent:
    """Structured, non-client-facing record of a security decision."""

    event_id: str
    occurred_at: datetime
    request_id: str
    detection_id: str
    subject_id: str | None
    tenant_id: str | None
    categories: tuple[str, ...]
    severity: Severity
    risk_score: int
    policy_action: PolicyAction
    detector_version: str
    policy_version: str
    route: str
    outcome: str
    indicator_codes: tuple[str, ...] = ()
    safe_metadata: Mapping[str, _SafeMetadataValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value, name in (
            (self.event_id, "event_id"),
            (self.request_id, "request_id"),
            (self.detection_id, "detection_id"),
            (self.detector_version, "detector_version"),
            (self.policy_version, "policy_version"),
            (self.route, "route"),
            (self.outcome, "outcome"),
        ):
            _require_nonempty(value, name)
        if self.subject_id is not None:
            _require_nonempty(self.subject_id, "subject_id")
        if self.tenant_id is not None:
            _require_nonempty(self.tenant_id, "tenant_id")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be in the range 0..100")
        if any(not category.strip() for category in self.categories):
            raise ValueError("categories cannot contain blank values")
        if any(not code.strip() for code in self.indicator_codes):
            raise ValueError("indicator_codes cannot contain blank values")

        safe_metadata = dict(self.safe_metadata)
        for key, value in safe_metadata.items():
            _require_nonempty(key, "safe_metadata key")
            normalized_key = key.casefold()
            if normalized_key not in _SAFE_METADATA_FIELDS or any(
                term in normalized_key for term in _FORBIDDEN_METADATA_NAMES
            ):
                raise ValueError(f"safe_metadata field is not permitted: {key}")
            if not isinstance(value, (str, int, bool)):
                raise ValueError(
                    "safe_metadata values must be scalar strings, integers, or booleans"
                )
            if isinstance(value, str) and len(value) > 256:
                raise ValueError("safe_metadata string values must not exceed 256 characters")
        object.__setattr__(self, "safe_metadata", MappingProxyType(safe_metadata))


class SecurityEventFactory:
    """Creates event evidence from server-generated IDs and detector output only."""

    def from_detection(
        self,
        detection: AttackDetectionResult,
        decision: SecurityPolicyDecision,
        *,
        request_id: str | None = None,
        canonical_subject_id: str | None = None,
        canonical_tenant_id: str | None = None,
        route: str,
        outcome: str,
        safe_metadata: Mapping[str, _SafeMetadataValue] | None = None,
    ) -> SecurityEvent:
        """Create evidence without accepting raw prompts, tokens, or client authority fields."""
        if decision.detection_id != detection.detection_id:
            raise ValueError("policy decision must belong to the detection result")
        event_request_id = request_id or detection.request_id
        if event_request_id is None:
            raise ValueError("request_id is required for security event correlation")
        return SecurityEvent(
            event_id=f"sec_{uuid4().hex}",
            occurred_at=datetime.now(UTC),
            request_id=event_request_id,
            detection_id=detection.detection_id,
            subject_id=canonical_subject_id,
            tenant_id=canonical_tenant_id,
            categories=tuple(sorted(category.value for category in detection.attack_categories)),
            severity=detection.severity,
            risk_score=detection.risk_score,
            policy_action=decision.action,
            detector_version=detection.detector_version,
            policy_version=decision.policy_version,
            route=route,
            outcome=outcome,
            indicator_codes=tuple(
                sorted(
                    {
                        indicator
                        for indicator in detection.indicators
                        if _SAFE_INDICATOR_CODE.fullmatch(indicator)
                    }
                )
            ),
            safe_metadata=safe_metadata or {},
        )
