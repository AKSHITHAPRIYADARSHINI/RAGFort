"""Immutable contracts shared by Phase 5 detection and enforcement layers."""

from dataclasses import dataclass, field
from enum import StrEnum


class AttackCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    DATA_EXFILTRATION = "data_exfiltration"
    CROSS_TENANT_EXFILTRATION = "cross_tenant_exfiltration"
    ROLE_MANIPULATION = "role_manipulation"
    IDENTITY_MANIPULATION = "identity_manipulation"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CONTEXT_MANIPULATION = "context_manipulation"
    RETRIEVAL_MANIPULATION = "retrieval_manipulation"
    ENCODED_PAYLOAD = "encoded_payload"
    TOOL_ABUSE = "tool_abuse"
    SUSPICIOUS_CONTROL_LANGUAGE = "suspicious_control_language"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    ALLOW_AND_LOG = "allow_and_log"
    BLOCK = "block"


class ContextDecision(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_SECURITY_EVENT = "allow_with_security_event"
    DROP_CHUNK = "drop_chunk"
    BLOCK_REQUEST = "block_request"


@dataclass(frozen=True)
class NormalizedSecurityInput:
    """Security-analysis view of input; original user input remains untouched."""

    original_length: int
    normalized_text: str
    truncated: bool = False
    control_characters_removed: int = 0


@dataclass(frozen=True)
class AttackDetectionResult:
    detection_id: str
    detected: bool
    request_id: str | None = None
    attack_categories: frozenset[AttackCategory] = field(default_factory=frozenset)
    indicators: tuple[str, ...] = ()
    risk_score: int = 0
    severity: Severity = Severity.INFORMATIONAL
    confidence: float = 0.0
    detector_version: str = "phase-5-v1"
    policy_version: str = "phase-5-v1"

    def __post_init__(self) -> None:
        if not self.detection_id.strip():
            raise ValueError("detection_id is required")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be in the range 0..100")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in the range 0..1")
        if self.detected != bool(self.attack_categories):
            raise ValueError("detected must match whether attack_categories are present")
        if not self.detector_version.strip() or not self.policy_version.strip():
            raise ValueError("detector and policy versions are required")


@dataclass(frozen=True)
class SecurityPolicyDecision:
    action: PolicyAction
    detection_id: str
    policy_version: str
    reason_code: str

    def __post_init__(self) -> None:
        if (
            not self.detection_id.strip()
            or not self.policy_version.strip()
            or not self.reason_code.strip()
        ):
            raise ValueError("policy decision requires IDs, version, and reason code")


@dataclass(frozen=True)
class ContextProvenance:
    """Non-client-facing evidence retained with a chunk entering model context."""

    document_id: str
    version_id: str
    chunk_id: str
    tenant_id: str
    classification: str
    authorization_validated: bool
    context_decision: ContextDecision
    context_detection_id: str | None = None

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.document_id,
                self.version_id,
                self.chunk_id,
                self.tenant_id,
                self.classification,
            )
        ):
            raise ValueError(
                "context provenance requires document, version, chunk, tenant, and classification"
            )
        if not self.authorization_validated:
            raise ValueError("context provenance cannot represent an unauthorized chunk")


@dataclass(frozen=True)
class ContextInspectionResult:
    provenance: ContextProvenance
    detection: AttackDetectionResult
    decision: ContextDecision
