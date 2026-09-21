"""Typed failures for callers to implement documented fail-safe behavior."""


class SecurityAnalysisError(RuntimeError):
    """Base class for security analysis failures."""


class SecurityInputTooLargeError(SecurityAnalysisError):
    """The bounded analysis input limit was exceeded."""


class SecurityDetectionUnavailableError(SecurityAnalysisError):
    """Detection could not establish a trustworthy result."""


class SecurityContextInspectionUnavailableError(SecurityAnalysisError):
    """Retrieved context could not be inspected safely."""
