"""Deterministic policy mapping; callers own safe response and event persistence."""

from backend.app.security.models import AttackDetectionResult, PolicyAction, SecurityPolicyDecision


class DeterministicSecurityPolicy:
    version = "phase-5-v1"

    def decide(self, result: AttackDetectionResult) -> SecurityPolicyDecision:
        if result.risk_score >= 70:
            return SecurityPolicyDecision(
                PolicyAction.BLOCK, result.detection_id, self.version, "high_risk"
            )
        if result.detected:
            return SecurityPolicyDecision(
                PolicyAction.ALLOW_AND_LOG, result.detection_id, self.version, "suspicious_input"
            )
        return SecurityPolicyDecision(
            PolicyAction.ALLOW, result.detection_id, self.version, "no_signal"
        )
