"""Stable input-analysis entry point for protected request integration."""

from backend.app.security.detector import DeterministicAttackDetector
from backend.app.security.failures import SecurityAnalysisError, SecurityDetectionUnavailableError
from backend.app.security.models import AttackDetectionResult


class InputSecurityAnalyzer:
    """Analyze untrusted user input without making authorization decisions."""

    def __init__(self, detector: DeterministicAttackDetector | None = None) -> None:
        self._detector = detector or DeterministicAttackDetector()

    def analyze(self, value: str, request_id: str | None = None) -> AttackDetectionResult:
        try:
            result = self._detector.analyze(value, request_id=request_id)
            if not isinstance(result, AttackDetectionResult):
                raise ValueError("detector returned a malformed result")
            return result
        except SecurityAnalysisError:
            raise
        except Exception as error:
            raise SecurityDetectionUnavailableError("Security detection is unavailable.") from error
