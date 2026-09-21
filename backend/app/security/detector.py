"""Local deterministic multi-signal detector; it is never an authorization control."""

import base64
import binascii
import re
from uuid import uuid4

from backend.app.security.models import AttackCategory, AttackDetectionResult, Severity
from backend.app.security.normalization import normalize_for_security_analysis

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|bypass)\b.{0,80}\b(?:previous|prior|system|policy|instruction)s?\b",
    re.I,
)
_EXTRACTION = re.compile(
    r"\b(?:reveal|show|print|dump|extract)\b.{0,80}\b(?:system (?:message|prompt)"
    r"|hidden (?:application )?policy|hidden instructions?|developer message|internal prompt"
    r"|internal security (?:configuration|policy))\b",
    re.I,
)
_CROSS_TENANT = re.compile(
    r"\b(?:other|another|all|global)\b.{0,40}\btenant|\btenant[_ -]?(?:acme|globex)\b"
    r"|\bglobex[-_a-z0-9]*\b",
    re.I,
)
_ROLE = re.compile(
    r"\b(?:i am|act as|make me|grant me)\b.{0,50}\b(?:admin(?:istrator)?|owner|superuser"
    r"|finance reader)\b",
    re.I,
)
_TENANT_CLAIM = re.compile(r"\b(?:my|your|current) tenant is\b", re.I)
_TENANT_BYPASS = re.compile(r"\bignore tenant restrictions\b", re.I)
_RETRIEVAL = re.compile(
    r"\b(?:replace.{0,40}tenant scope|search globally|unrestricted filter|skip postgresql"
    r" validation|regardless of access policy|retrieve all matching)\b",
    re.I,
)
_EXFILTRATION = re.compile(
    r"\b(?:return|show|give|disclose|send)\b.{0,60}\b(?:every|all|unrelated).{0,60}"
    r"\b(?:confidential|restricted|tenant|record|document)s?\b",
    re.I,
)
_CONTEXT = re.compile(
    r"\bdiscard\b.{0,60}\b(?:retrieved references|context)\b.{0,80}"
    r"\b(?:only authoritative context|authoritative)\b",
    re.I,
)
_PRIVILEGED_TOOL = re.compile(
    r"\b(?:call.{0,50}(?:export )?tool.{0,80}(?:send|external)|execute privileged actions)\b",
    re.I,
)
_CONTROL = re.compile(
    r"\b(?:new system message|highest priority|do not follow|forget (?:your|all)"
    r"|system\s*:|assistant\s*:|policy reset|priority override)\b",
    re.I,
)
_FRAGMENTED_OVERRIDE = re.compile(
    r"\b(?:i\s+g\s+n\s+o\s+r\s+e)\b(?=.{0,80}\b(?:prior|previous|application|system)"
    r"\s+instructions?\b)",
    re.I,
)
_BASE64ISH = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,4096}={0,2}(?![A-Za-z0-9+/=])")


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

        override = _OVERRIDE.search(normalized) or _FRAGMENTED_OVERRIDE.search(normalized)
        if override:
            add(AttackCategory.INSTRUCTION_OVERRIDE, "instruction_override", 45)
            add(AttackCategory.PROMPT_INJECTION, "control_language", 15)
        if _EXTRACTION.search(normalized):
            add(AttackCategory.SYSTEM_PROMPT_EXTRACTION, "prompt_extraction_intent", 70)
        if _CROSS_TENANT.search(normalized) and re.search(
            r"\b(?:show|search|retrieve|find|give)\b", normalized, re.I
        ):
            add(AttackCategory.CROSS_TENANT_EXFILTRATION, "cross_tenant_retrieval_intent", 65)
            add(AttackCategory.DATA_EXFILTRATION, "cross_tenant_data_intent", 15)
        if _TENANT_CLAIM.search(normalized):
            add(AttackCategory.IDENTITY_MANIPULATION, "tenant_identity_claim", 20)
        if _TENANT_BYPASS.search(normalized):
            add(AttackCategory.CROSS_TENANT_EXFILTRATION, "tenant_bypass_intent", 65)
            add(AttackCategory.RETRIEVAL_MANIPULATION, "tenant_bypass_retrieval", 40)
            add(AttackCategory.INSTRUCTION_OVERRIDE, "tenant_bypass_override", 45)
        if _RETRIEVAL.search(normalized):
            add(AttackCategory.RETRIEVAL_MANIPULATION, "retrieval_control_intent", 40)
            if "skip postgresql validation" in normalized.casefold():
                add(AttackCategory.INSTRUCTION_OVERRIDE, "validation_bypass", 35)
        if _EXFILTRATION.search(normalized):
            add(AttackCategory.DATA_EXFILTRATION, "data_exfiltration_intent", 45)
        if _ROLE.search(normalized):
            add(AttackCategory.ROLE_MANIPULATION, "privilege_claim", 45)
            add(AttackCategory.IDENTITY_MANIPULATION, "identity_claim", 15)
        if _CONTEXT.search(normalized):
            add(AttackCategory.CONTEXT_MANIPULATION, "context_authority_claim", 40)
            add(AttackCategory.INSTRUCTION_OVERRIDE, "context_override", 35)
        if _PRIVILEGED_TOOL.search(normalized):
            add(AttackCategory.TOOL_ABUSE, "tool_control_combination", 35)
        if _CONTROL.search(normalized):
            add(AttackCategory.SUSPICIOUS_CONTROL_LANGUAGE, "suspicious_control_language", 25)
            if (
                "policy reset" in normalized.casefold()
                or "priority override" in normalized.casefold()
            ):
                add(AttackCategory.INSTRUCTION_OVERRIDE, "control_authority_claim", 35)
        encoded_control = self._contains_encoded_payload(normalized)
        if encoded_control is not None or _FRAGMENTED_OVERRIDE.search(normalized):
            add(AttackCategory.ENCODED_PAYLOAD, "encoded_payload", 20)
        if encoded_control:
            add(AttackCategory.SUSPICIOUS_CONTROL_LANGUAGE, "encoded_control_language", 25)

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
    def _contains_encoded_payload(value: str) -> bool | None:
        for token in _BASE64ISH.findall(value):
            try:
                decoded = base64.b64decode(token, validate=True)
            except (ValueError, binascii.Error):
                continue
            if decoded and sum(byte in range(32, 127) for byte in decoded) / len(decoded) > 0.8:
                decoded_text = decoded.decode("ascii", errors="ignore").casefold()
                return any(
                    cue in decoded_text for cue in ("ignore", "reveal", "policy", "instruction")
                )
        return None
