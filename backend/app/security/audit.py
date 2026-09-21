"""Swappable audit sink contracts and minimized SQL persistence."""

import json
from threading import Lock
from typing import Protocol, runtime_checkable

from backend.app.documents.persistence import SecurityEventRecord
from backend.app.security.events import SecurityEvent
from backend.app.security.failures import SecurityEventPersistenceUnavailableError


@runtime_checkable
class SecurityEventSink(Protocol):
    """Internal interface for recording already-sanitized security events."""

    def record(self, event: SecurityEvent) -> None:
        """Record one event or raise a sink-specific failure."""


class NoOpSecurityEventSink:
    """Safe default while event persistence is not configured.

    It accepts only a constructed :class:`SecurityEvent`, so it cannot become a
    raw-input logging path.  Route policy decides whether an audit failure must
    affect the request; this no-op sink does not silently alter authorization.
    """

    def record(self, event: SecurityEvent) -> None:
        del event


class InMemorySecurityEventSink:
    """Thread-safe test/development sink; never use it as durable audit storage."""

    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []
        self._lock = Lock()

    def record(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[SecurityEvent, ...]:
        with self._lock:
            return tuple(self._events)


class SqlAlchemySecurityEventSink:
    """Persist only already-minimized events in the dedicated Phase 5 table."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def record(self, event: SecurityEvent) -> None:
        try:
            with self._session_factory.begin() as session:
                session.add(
                    SecurityEventRecord(
                        event_id=event.event_id,
                        occurred_at=event.occurred_at.replace(tzinfo=None),
                        request_id=event.request_id,
                        detection_id=event.detection_id,
                        subject_id=event.subject_id,
                        tenant_id=event.tenant_id,
                        categories_json=json.dumps(event.categories),
                        severity=event.severity.value,
                        risk_score=event.risk_score,
                        policy_action=event.policy_action.value,
                        detector_version=event.detector_version,
                        policy_version=event.policy_version,
                        route=event.route,
                        outcome=event.outcome,
                        indicator_codes_json=json.dumps(event.indicator_codes),
                        safe_metadata_json=json.dumps(dict(event.safe_metadata), sort_keys=True),
                    )
                )
        except Exception as error:
            raise SecurityEventPersistenceUnavailableError(
                "Security evidence could not be recorded."
            ) from error
