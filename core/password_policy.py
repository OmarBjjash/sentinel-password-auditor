"""
Password policy evaluator.

Provides a configurable password policy with rules for length, character
requirements, repetition, sequential characters, and dictionary checks.
Evaluates passwords against the policy and returns detailed per-rule results
with actionable recommendations.
"""

import re
import string
from dataclasses import dataclass, field
from typing import List, Optional

from core.config import (
    DEFAULT_CHECK_DICTIONARY,
    DEFAULT_CHECK_SEQUENTIAL,
    DEFAULT_MAX_LENGTH,
    DEFAULT_MAX_REPEATED_CHARS,
    DEFAULT_MIN_LENGTH,
    DEFAULT_REQUIRE_DIGITS,
    DEFAULT_REQUIRE_LOWERCASE,
    DEFAULT_REQUIRE_SPECIAL,
    DEFAULT_REQUIRE_UPPERCASE,
)
from core.dictionary_manager import DictionaryManager


@dataclass
class PolicyRule:
    """Result of evaluating a single policy rule."""

    name: str
    description: str
    passed: bool
    recommendation: str = ""


@dataclass
class PolicyResult:
    """Complete result of evaluating a password against a policy."""

    passed: bool
    rules: List[PolicyRule]
    failed_count: int
    passed_count: int
    total_rules: int
    recommendations: List[str]

    @property
    def compliance_percentage(self) -> float:
        """Percentage of rules that passed."""
        if self.total_rules == 0:
            return 100.0
        return (self.passed_count / self.total_rules) * 100.0


@dataclass
class PasswordPolicy:
    """
    Configurable password policy with industry-standard defaults.

    Each attribute controls a specific password requirement. The evaluate()
    method checks a password against all enabled rules and returns a
    detailed PolicyResult.
    """

    min_length: int = DEFAULT_MIN_LENGTH
    max_length: int = DEFAULT_MAX_LENGTH
    require_uppercase: bool = DEFAULT_REQUIRE_UPPERCASE
    require_lowercase: bool = DEFAULT_REQUIRE_LOWERCASE
    require_digits: bool = DEFAULT_REQUIRE_DIGITS
    require_special: bool = DEFAULT_REQUIRE_SPECIAL
    max_repeated_chars: int = DEFAULT_MAX_REPEATED_CHARS
    check_sequential: bool = DEFAULT_CHECK_SEQUENTIAL
    check_dictionary: bool = DEFAULT_CHECK_DICTIONARY

    def evaluate(self, password: str) -> PolicyResult:
        """
        Evaluate a password against all policy rules.

        The password is never logged or stored.

        Args:
            password: The password to evaluate.

        Returns:
            A PolicyResult with pass/fail per rule and recommendations.
        """
        rules: list[PolicyRule] = []

        # ── Minimum length ───────────────────────────────────────────────
        rules.append(self._check_min_length(password))

        # ── Maximum length ───────────────────────────────────────────────
        rules.append(self._check_max_length(password))

        # ── Uppercase requirement ────────────────────────────────────────
        if self.require_uppercase:
            rules.append(self._check_uppercase(password))

        # ── Lowercase requirement ────────────────────────────────────────
        if self.require_lowercase:
            rules.append(self._check_lowercase(password))

        # ── Digit requirement ────────────────────────────────────────────
        if self.require_digits:
            rules.append(self._check_digits(password))

        # ── Special character requirement ────────────────────────────────
        if self.require_special:
            rules.append(self._check_special(password))

        # ── Repeated characters ──────────────────────────────────────────
        rules.append(self._check_repeated(password))

        # ── Sequential characters ────────────────────────────────────────
        if self.check_sequential:
            rules.append(self._check_sequential_chars(password))

        # ── Dictionary check ─────────────────────────────────────────────
        if self.check_dictionary:
            rules.append(self._check_dictionary_word(password))

        # ── Compile results ──────────────────────────────────────────────
        passed_rules = [r for r in rules if r.passed]
        failed_rules = [r for r in rules if not r.passed]
        recommendations = [r.recommendation for r in failed_rules if r.recommendation]

        return PolicyResult(
            passed=len(failed_rules) == 0,
            rules=rules,
            failed_count=len(failed_rules),
            passed_count=len(passed_rules),
            total_rules=len(rules),
            recommendations=recommendations,
        )

    def _check_min_length(self, password: str) -> PolicyRule:
        length = len(password)
        passed = length >= self.min_length
        return PolicyRule(
            name="Minimum Length",
            description=f"Password must be at least {self.min_length} characters",
            passed=passed,
            recommendation=(
                ""
                if passed
                else f"Increase password length to at least {self.min_length} characters. "
                f"Current length: {length}."
            ),
        )

    def _check_max_length(self, password: str) -> PolicyRule:
        length = len(password)
        passed = length <= self.max_length
        return PolicyRule(
            name="Maximum Length",
            description=f"Password must not exceed {self.max_length} characters",
            passed=passed,
            recommendation=(
                ""
                if passed
                else f"Reduce password length to at most {self.max_length} characters. "
                f"Current length: {length}."
            ),
        )

    def _check_uppercase(self, password: str) -> PolicyRule:
        passed = bool(re.search(r"[A-Z]", password))
        return PolicyRule(
            name="Uppercase Letters",
            description="Password must contain at least one uppercase letter (A-Z)",
            passed=passed,
            recommendation=(
                "" if passed else "Add at least one uppercase letter (A-Z)."
            ),
        )

    def _check_lowercase(self, password: str) -> PolicyRule:
        passed = bool(re.search(r"[a-z]", password))
        return PolicyRule(
            name="Lowercase Letters",
            description="Password must contain at least one lowercase letter (a-z)",
            passed=passed,
            recommendation=(
                "" if passed else "Add at least one lowercase letter (a-z)."
            ),
        )

    def _check_digits(self, password: str) -> PolicyRule:
        passed = bool(re.search(r"\d", password))
        return PolicyRule(
            name="Digits",
            description="Password must contain at least one digit (0-9)",
            passed=passed,
            recommendation=(
                "" if passed else "Add at least one digit (0-9)."
            ),
        )

    def _check_special(self, password: str) -> PolicyRule:
        passed = bool(re.search(r"[^A-Za-z0-9]", password))
        return PolicyRule(
            name="Special Characters",
            description="Password must contain at least one special character",
            passed=passed,
            recommendation=(
                ""
                if passed
                else "Add at least one special character (e.g., !@#$%^&*)."
            ),
        )

    def _check_repeated(self, password: str) -> PolicyRule:
        max_run = 0
        if password:
            current_run = 1
            for i in range(1, len(password)):
                if password[i] == password[i - 1]:
                    current_run += 1
                    max_run = max(max_run, current_run)
                else:
                    current_run = 1
            max_run = max(max_run, current_run) if password else 0

        passed = max_run <= self.max_repeated_chars
        return PolicyRule(
            name="Repeated Characters",
            description=(
                f"No character should repeat more than {self.max_repeated_chars} "
                f"times consecutively"
            ),
            passed=passed,
            recommendation=(
                ""
                if passed
                else f"Avoid repeating the same character more than "
                f"{self.max_repeated_chars} times in a row."
            ),
        )

    def _check_sequential_chars(self, password: str) -> PolicyRule:
        has_sequential = False
        lower = password.lower()
        min_run = 3
        sequences = (string.ascii_lowercase, string.digits)

        for seq in sequences:
            for i in range(len(lower) - min_run + 1):
                fragment = lower[i : i + min_run]
                if fragment in seq or fragment[::-1] in seq:
                    has_sequential = True
                    break
            if has_sequential:
                break

        passed = not has_sequential
        return PolicyRule(
            name="Sequential Characters",
            description="Password should not contain sequential characters (abc, 123)",
            passed=passed,
            recommendation=(
                ""
                if passed
                else "Avoid sequential characters like 'abc', '123', or 'cba'."
            ),
        )

    def _check_dictionary_word(self, password: str) -> PolicyRule:
        dm = DictionaryManager()
        if not dm.is_loaded:
            if not dm.load():
                return PolicyRule(
                    name="Dictionary Check",
                    description="Password should not be a common dictionary word",
                    passed=True,
                    recommendation="Dictionary not available for checking.",
                )

        is_dictionary_word = dm.contains(password)
        passed = not is_dictionary_word
        return PolicyRule(
            name="Dictionary Check",
            description="Password should not be a common dictionary word",
            passed=passed,
            recommendation=(
                ""
                if passed
                else "This password is a known common password. Choose a unique password."
            ),
        )
