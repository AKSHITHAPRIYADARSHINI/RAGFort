"""Bounded normalization used only for security analysis, never user-text mutation."""

import re
import unicodedata

from backend.app.security.failures import SecurityInputTooLargeError
from backend.app.security.models import NormalizedSecurityInput

MAX_SECURITY_INPUT_CHARS = 16_384
_WHITESPACE = re.compile(r"\s+")


def normalize_for_security_analysis(
    value: str, *, max_chars: int = MAX_SECURITY_INPUT_CHARS
) -> NormalizedSecurityInput:
    """Normalize a bounded string without recursively decoding attacker input."""
    if not isinstance(value, str):
        raise TypeError("security analysis input must be a string")
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if len(value) > max_chars:
        raise SecurityInputTooLargeError("security analysis input exceeds configured limit")

    normalized = unicodedata.normalize("NFKC", value)
    cleaned: list[str] = []
    removed = 0
    for character in normalized:
        if unicodedata.category(character) in {"Cc", "Cf"} and character not in "\t\n\r":
            removed += 1
            continue
        cleaned.append(character)
    collapsed = _WHITESPACE.sub(" ", "".join(cleaned)).strip()
    return NormalizedSecurityInput(
        original_length=len(value),
        normalized_text=collapsed,
        control_characters_removed=removed,
    )
