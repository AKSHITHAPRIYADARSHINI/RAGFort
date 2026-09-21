"""Local deterministic multi-signal detector; it is never an authorization control."""

import base64
import binascii
import re
from uuid import uuid4

from backend.app.security.models import AttackCategory, AttackDetectionResult, Severity
from backend.app.security.normalization import normalize_for_security_analysis

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|bypass|override)\b.{0,80}\b(?:previous|prior|system|policy|instruction)s?\b",
    re.I,
)
_EXTRACTION = re.compile(
    r"\b(?:reveal|show|print|dump|extract)\b.{0,80}\b(?:system prompt|hidden instructions?"
    r"|developer message|internal prompt)\b",
    re.I,
)
_CROSS_TENANT = re.compile(
    r"\b(?:other|another|all|global)\b.{0,40}\btenant|\btenant[_ -]?(?:acme|globex)\b", re.I
)
_ROLE = re.compile(
    r"\b(?:i am|act as|make me|grant me)\b.{0,50}\b(?:admin(?:istrator)?|owner|superuser"
    r"|finance reader)\b",
    re.I,
)
_TOOL = re.compile(r"\b(?:run|execute|call)\b.{0,50}\b(?:tool|shell|command|api)\b", re.I)
_CONTROL = re.compile(
    r"\b(?:new system message|highest priority|do not follow|forget (?:your|all))\b", re.I
)
_BASE64ISH = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")


def _severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFORMATIONAL


class DeterministicAttackDetector:
    """Explainable signal combiner intentionally conservative about security terminology."""

    detector_version = "phase-5-v1"
    policy_version = "phase-5-v1"

    def analyze(self, value: str, *, request_id: str | None = None) -> AttackDetectionResult:
        normalized = normalize_for_security_analysis(value).normalized_text
        categories: set[AttackCategory] = set()
        indicators: list[str] = []
        score = 0

        def add(category: AttackCategory, indicator: str, weight: int) -> None:
            nonlocal score
            categories.add(category)
            indicators.append(indicator)
            score += weight

        if _OVERRIDE.search(normalized):
            add(AttackCategory.INSTRUCTION_OVERRIDE, "instruction_override", 45)
            add(AttackCategory.PROMPT_INJECTION, "control_language", 15)
        if _EXTRACTION.search(normalized):
            add(AttackCategory.SYSTEM_PROMPT_EXTRACTION, "prompt_extraction_intent", 55)
        if _CROSS_TENANT.search(normalized) and re.search(
            r"\b(?:show|search|retrieve|find|give)\b", normalized, re.I
        ):
            add(AttackCategory.CROSS_TENANT_EXFILTRATION, "cross_tenant_retrieval_intent", 65)
            add(AttackCategory.DATA_EXFILTRATION, "data_exfiltration_intent", 15)
        if _ROLE.search(normalized):
            add(AttackCategory.ROLE_MANIPULATION, "privilege_claim", 45)
            add(AttackCategory.IDENTITY_MANIPULATION, "identity_claim", 15)
        if _TOOL.search(normalized) and _OVERRIDE.search(normalized):
            add(AttackCategory.TOOL_ABUSE, "tool_control_combination", 35)
        if _CONTROL.search(normalized):
            add(AttackCategory.SUSPICIOUS_CONTROL_LANGUAGE, "suspicious_control_language", 25)
        if self._contains_encoded_payload(normalized):
            add(AttackCategory.ENCODED_PAYLOAD, "encoded_payload", 20)

        score = min(score, 100)
        return AttackDetectionResult(
            detection_id=str(uuid4()),
            detected=bool(categories),
            request_id=request_id,
            attack_categories=frozenset(categories),
            indicators=tuple(indicators),
            risk_score=score,
            severity=_severity(score),
            confidence=min(1.0, 0.35 + 0.15 * len(categories)) if categories else 0.0,
            detector_version=self.detector_version,
            policy_version=self.policy_version,
        )

    @staticmethod
    def _contains_encoded_payload(value: str) -> bool:
        for token in _BASE64ISH.findall(value):
            try:
                decoded = base64.b64decode(token, validate=True)
            except (ValueError, binascii.Error):
                continue
            if decoded and sum(byte in range(32, 127) for byte in decoded) / len(decoded) > 0.8:
                return True
        return False
