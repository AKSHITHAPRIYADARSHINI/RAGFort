"""Inspect Phase 4-authorized retrieval candidates as untrusted reference data.

This guard is deliberately downstream of retrieval authorization.  It cannot
make a chunk authorized and must only be called with candidates that have
already passed the Phase 4 Qdrant and PostgreSQL checks.
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace

from backend.app.rag.models import RetrievalResult
from backend.app.security.detector import DeterministicAttackDetector
from backend.app.security.failures import SecurityContextInspectionUnavailableError
from backend.app.security.models import (
    AttackCategory,
    AttackDetectionResult,
    ContextDecision,
    ContextInspectionResult,
    ContextProvenance,
)
from backend.app.security.policy import DeterministicSecurityPolicy


@dataclass(frozen=True)
class ContextGuardResult:
    """The safe subset plus non-client-facing evidence for every candidate."""

    safe_results: tuple[RetrievalResult, ...]
    inspections: tuple[ContextInspectionResult, ...]

    @property
    def dropped_count(self) -> int:
        return sum(
            inspection.decision is ContextDecision.DROP_CHUNK for inspection in self.inspections
        )


class ContextSecurityGuard:
    """Drop retrieved instructions without treating authorized data as trusted.

    Detection is deterministic and bounded by the shared normalization layer.
    Any malformed candidate or detector failure raises a typed error so the
    secured query path can fail closed rather than send uninspected context to
    a model.
    """

    def __init__(
        self,
        detector: DeterministicAttackDetector | None = None,
        policy: DeterministicSecurityPolicy | None = None,
    ) -> None:
        self._detector = detector or DeterministicAttackDetector()
        self._policy = policy or DeterministicSecurityPolicy()

    def inspect(
        self,
        results: Iterable[RetrievalResult],
        *,
        request_id: str | None = None,
    ) -> ContextGuardResult:
        """Return only chunks safe to include as untrusted reference material."""
        try:
            candidates = tuple(results)
            safe_results: list[RetrievalResult] = []
            inspections: list[ContextInspectionResult] = []
            for result in candidates:
                provenance = self._provenance(result)
                detection = self._context_detection(result.text, request_id=request_id)
                decision = self._decision(detection)
                inspections.append(
                    ContextInspectionResult(
                        provenance=ContextProvenance(
                            **{
                                **provenance,
                                "context_decision": decision,
                                "context_detection_id": detection.detection_id
                                if detection.detected
                                else None,
                            }
                        ),
                        detection=detection,
                        decision=decision,
                    )
                )
                if decision is not ContextDecision.DROP_CHUNK:
                    # Server-owned inspection evidence follows the admitted chunk
                    # through ContextBuilder. Never trust a vector payload's copy.
                    safe_results.append(
                        replace(
                            result,
                            metadata={
                                **result.metadata,
                                "phase5_provenance": asdict(inspections[-1].provenance),
                            },
                        )
                    )
            return ContextGuardResult(tuple(safe_results), tuple(inspections))
        except SecurityContextInspectionUnavailableError:
            raise
        except Exception as error:
            raise SecurityContextInspectionUnavailableError(
                "Retrieved context could not be inspected safely."
            ) from error

    @staticmethod
    def _provenance(result: RetrievalResult) -> dict[str, object]:
        if not isinstance(result, RetrievalResult) or not isinstance(result.text, str):
            raise ValueError("retrieval candidate is malformed")
        metadata = result.metadata
        if not isinstance(metadata, dict):
            raise ValueError("retrieval candidate metadata is malformed")
        version_id = metadata.get("version_id")
        tenant_id = metadata.get("tenant_id")
        classification = metadata.get("classification")
        values = (result.document_id, result.chunk_id, version_id, tenant_id, classification)
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("retrieval candidate lacks required security provenance")
        # This component is intentionally unable to grant authorization.  Its
        # public contract requires the caller to supply Phase 4-authorized
        # candidates; the provenance records that established pipeline state.
        return {
            "document_id": result.document_id,
            "version_id": version_id,
            "chunk_id": result.chunk_id,
            "tenant_id": tenant_id,
            "classification": classification,
            "authorization_validated": True,
        }

    def _context_detection(self, text: str, *, request_id: str | None) -> AttackDetectionResult:
        detection = self._detector.analyze(text, request_id=request_id)
        if not isinstance(detection, AttackDetectionResult):
            raise ValueError("detector returned a malformed result")
        if not detection.detected:
            return detection

        # A signal observed in a retrieved document is indirect injection or
        # context manipulation in addition to its original semantic category.
        categories = detection.attack_categories | frozenset(
            {AttackCategory.INDIRECT_PROMPT_INJECTION, AttackCategory.CONTEXT_MANIPULATION}
        )
        indicators = tuple(dict.fromkeys((*detection.indicators, "untrusted_retrieved_context")))
        return AttackDetectionResult(
            detection_id=detection.detection_id,
            detected=True,
            request_id=detection.request_id,
            attack_categories=categories,
            indicators=indicators,
            risk_score=detection.risk_score,
            severity=detection.severity,
            confidence=detection.confidence,
            detector_version=detection.detector_version,
            policy_version=detection.policy_version,
        )

    def _decision(self, detection: AttackDetectionResult) -> ContextDecision:
        policy = self._policy.decide(detection)
        # Context that an input policy would block cannot enter a model prompt.
        if policy.action.value == "block":
            return ContextDecision.DROP_CHUNK
        if detection.detected:
            return ContextDecision.ALLOW_WITH_SECURITY_EVENT
        return ContextDecision.ALLOW
