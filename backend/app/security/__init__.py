"""Deterministic, defense-in-depth security analysis for Phase 5.

This package does not make authorization decisions.  Phase 4 remains the
authority for tenant, ACL, classification, and document lifecycle access.
"""

from backend.app.security.detector import DeterministicAttackDetector
from backend.app.security.models import AttackDetectionResult, PolicyAction
from backend.app.security.normalization import normalize_for_security_analysis
from backend.app.security.policy import DeterministicSecurityPolicy

__all__ = [
    "AttackDetectionResult",
    "InputSecurityAnalyzer",
    "DeterministicAttackDetector",
    "DeterministicSecurityPolicy",
    "PolicyAction",
    "normalize_for_security_analysis",
]
from backend.app.security.analyzer import InputSecurityAnalyzer
