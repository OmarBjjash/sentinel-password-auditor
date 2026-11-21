"""
Interactive password strength checking and dictionary lookup.

Evaluates passwords against multiple criteria including length, character
diversity, common patterns, predictable substitutions, repeated characters,
and sequential characters. Never logs or stores the actual password.
"""

import logging
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from core.config import (
    STRENGTH_MODERATE_MAX,
    STRENGTH_STRONG_MAX,
    STRENGTH_VERY_WEAK_MAX,
    STRENGTH_WEAK_MAX,
)
from core.dictionary_manager import DictionaryManager

logger = logging.getLogger(__name__)


class StrengthLevel(str, Enum):
    """Password strength classification levels."""

    VERY_WEAK = "VERY_WEAK"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"


@dataclass(frozen=True)
class PasswordStrength:
    """Result of a password strength evaluation."""

    score: int
    level: StrengthLevel
    feedback: List[str]


# ── Common Patterns and Sequences ─────────────────────────────────────────────

_KEYBOARD_SEQUENCES = [
    "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn",
    "qweasd", "1qaz2wsx", "1q2w3e", "zaq1xsw2",
    "!qaz@wsx", "qazwsx", "asdzxc",
]

_COMMON_PATTERNS = [
    "123456", "12345678", "123456789", "1234567890", "12345",
    "111111", "000000", "121212", "123123", "654321",
    "abcdef", "abcabc", "aaaaaa", "password", "passwd",
    "pass1234", "admin", "login", "welcome", "letmein",
    "iloveyou", "monkey", "master", "dragon", "trustno1",
    "baseball", "football", "shadow", "sunshine", "princess",
    "superman", "michael", "charlie", "jordan", "access",
]

# Leetspeak / predictable substitution map
_LEET_MAP: dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "+": "t",
    "8": "b",
}

_SEQUENTIAL_ALPHA = string.ascii_lowercase
_SEQUENTIAL_DIGITS = string.digits


def _desubstitute(password: str) -> str:
    """Reverse common leetspeak substitutions to reveal the base word."""
    result: list[str] = []
    for ch in password.lower():
        result.append(_LEET_MAP.get(ch, ch))
    return "".join(result)


def _has_sequential_chars(password: str, min_run: int = 3) -> bool:
    """Check if the password contains sequential characters (abc, 123, etc.)."""
    lower = password.lower()
    if len(lower) < min_run:
        return False

    for seq in (_SEQUENTIAL_ALPHA, _SEQUENTIAL_DIGITS):
        for i in range(len(lower) - min_run + 1):
            fragment = lower[i : i + min_run]
            if fragment in seq or fragment[::-1] in seq:
                return True
    return False


def _has_repeated_chars(password: str, max_repeat: int = 3) -> bool:
    """Check if any character repeats more than max_repeat times consecutively."""
    if not password:
        return False
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            count += 1
            if count > max_repeat:
                return True
        else:
            count = 1
    return False


def _matches_common_pattern(password: str) -> bool:
    """Check if the password matches a common pattern or keyboard walk."""
    lower = password.lower()
    desubbed = _desubstitute(password)

    for pattern in _COMMON_PATTERNS:
        if lower == pattern or desubbed == pattern:
            return True

    for seq in _KEYBOARD_SEQUENCES:
        if seq in lower or seq in desubbed:
            return True

    return False


def _has_predictable_substitutions(
    password: str, dictionary: Optional[DictionaryManager] = None
) -> bool:
    """Check if the password is just a dictionary word with leetspeak."""
    desubbed = _desubstitute(password)
    if desubbed == password.lower():
        return False  # No substitutions detected

    dm = dictionary or DictionaryManager()
    if dm.is_loaded or dm.load():
        if dm.contains(desubbed):
            return True

    return desubbed in _COMMON_PATTERNS


def check_dictionary(
    password: str, dictionary: Optional[DictionaryManager] = None
) -> bool:
    """
    Check if a password exists in the dictionary wordlist (case-insensitive).

    Args:
        password: The password to check. Never logged or stored.
        dictionary: Optional DictionaryManager instance.

    Returns:
        True if the password is found in the dictionary.
    """
    dm = dictionary or DictionaryManager()
    if not dm.is_loaded:
        if not dm.load():
            logger.warning("Dictionary not available for lookup")
            return False
    return dm.contains(password)


def evaluate_strength(
    password: str, dictionary: Optional[DictionaryManager] = None
) -> PasswordStrength:
    """
    Evaluate the strength of a password on a 0-100 scale.

    Scoring criteria:
    - Base length score (up to 30 points)
    - Character diversity (up to 40 points: uppercase, lowercase, digits, special)
    - Penalties for weaknesses (common patterns, repetition, sequences, dictionary)

    The password is never logged or stored.

    Args:
        password: The password to evaluate.
        dictionary: Optional DictionaryManager instance.

    Returns:
        A PasswordStrength object with score, level, and feedback.
    """
    if not password:
        return PasswordStrength(
            score=0,
            level=StrengthLevel.VERY_WEAK,
            feedback=["Password is empty."],
        )

    score = 0
    feedback: list[str] = []
    length = len(password)

    # ── Length scoring (up to 30 points) ─────────────────────────────────
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 10:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        score += 3
        feedback.append("Password is too short. Use at least 8 characters.")

    if length < 8:
        feedback.append("Consider using at least 8 characters for better security.")

    # ── Character diversity (up to 40 points, 10 each) ───────────────────
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    diversity_count = sum([has_upper, has_lower, has_digit, has_special])

    if has_upper:
        score += 10
    else:
        feedback.append("Add uppercase letters for stronger security.")

    if has_lower:
        score += 10
    else:
        feedback.append("Add lowercase letters for stronger security.")

    if has_digit:
        score += 10
    else:
        feedback.append("Add digits for stronger security.")

    if has_special:
        score += 10
    else:
        feedback.append("Add special characters (!@#$%^&*) for stronger security.")

    # ── Diversity bonus (up to 10 points) ────────────────────────────────
    if diversity_count == 4:
        score += 10
    elif diversity_count == 3:
        score += 5

    # ── Length bonus for long passwords (up to 10 points) ────────────────
    if length >= 20:
        score += 10
    elif length >= 16:
        score += 5

    # ── Penalties ────────────────────────────────────────────────────────

    # Repeated characters
    if _has_repeated_chars(password):
        score -= 10
        feedback.append("Avoid repeating the same character more than 3 times in a row.")

    # Sequential characters
    if _has_sequential_chars(password):
        score -= 10
        feedback.append("Avoid sequential characters like 'abc' or '123'.")

    # Common patterns
    if _matches_common_pattern(password):
        score -= 20
        feedback.append("This password matches a commonly used pattern.")

    # Dictionary word check
    if check_dictionary(password, dictionary=dictionary):
        score -= 20
        feedback.append("This password is found in the dictionary of common passwords.")

    # Predictable substitutions
    if _has_predictable_substitutions(password, dictionary=dictionary):
        score -= 10
        feedback.append(
            "Simple character substitutions (e.g., @ for 'a', 3 for 'e') "
            "are easily guessed."
        )

    # ── Clamp score ──────────────────────────────────────────────────────
    score = max(0, min(100, score))

    # ── Determine level ──────────────────────────────────────────────────
    if score <= STRENGTH_VERY_WEAK_MAX:
        level = StrengthLevel.VERY_WEAK
    elif score <= STRENGTH_WEAK_MAX:
        level = StrengthLevel.WEAK
    elif score <= STRENGTH_MODERATE_MAX:
        level = StrengthLevel.MODERATE
    elif score <= STRENGTH_STRONG_MAX:
        level = StrengthLevel.STRONG
    else:
        level = StrengthLevel.VERY_STRONG

    if not feedback:
        feedback.append("Great password! It meets all security criteria.")

    return PasswordStrength(score=score, level=level, feedback=feedback)
