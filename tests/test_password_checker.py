"""
Tests for interactive password checker and policy evaluation.
"""

from pathlib import Path
import pytest

from core.dictionary_manager import DictionaryManager
from core.password_checker import (
    StrengthLevel,
    check_dictionary,
    evaluate_strength,
)
from core.password_policy import PasswordPolicy


class TestPasswordChecker:
    """Tests for core.password_checker module."""

    def test_common_password_detected(self) -> None:
        """Verify common passwords from wordlist are detected."""
        assert check_dictionary("password") is True
        assert check_dictionary("123456") is True
        assert check_dictionary("qwerty") is True

    def test_uncommon_password_not_detected(self) -> None:
        """Verify complex random passwords are not flagged as common."""
        assert check_dictionary("Xk9#mZp!2026StrongPass") is False
        assert check_dictionary("uncommon_pass_77491_xyz") is False

    def test_case_insensitive_comparison(self) -> None:
        """Verify dictionary lookup is case-insensitive."""
        assert check_dictionary("PASSWORD") is True
        assert check_dictionary("Password") is True
        assert check_dictionary("pAsSwOrD") is True
        assert check_dictionary("QWERTY") is True

    def test_whitespace_handling(self) -> None:
        """Verify leading/trailing whitespace handling."""
        # Stripped dictionary check should detect common words
        assert check_dictionary("  password  ".strip()) is True

    def test_empty_input(self) -> None:
        """Verify empty password produces score 0 and VERY_WEAK."""
        res = evaluate_strength("")
        assert res.score == 0
        assert res.level == StrengthLevel.VERY_WEAK
        assert "empty" in res.feedback[0].lower()

    def test_strength_very_weak(self) -> None:
        """Verify short or common passwords score very weak."""
        res = evaluate_strength("123")
        assert res.level == StrengthLevel.VERY_WEAK
        assert res.score <= 20

    def test_strength_weak(self) -> None:
        """Verify simple passwords score weak."""
        res = evaluate_strength("simplepass")
        assert res.level in (StrengthLevel.VERY_WEAK, StrengthLevel.WEAK)

    def test_strength_moderate(self) -> None:
        """Verify medium complexity passwords score moderate."""
        res = evaluate_strength("Password123")
        # Has upper, lower, digits, but contains common word 'password'
        assert res.score <= 60

    def test_strength_strong(self) -> None:
        """Verify good diversity passwords score strong."""
        res = evaluate_strength("BlueSky#2026!Winter")
        assert res.level in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)
        assert res.score >= 60

    def test_strength_very_strong(self) -> None:
        """Verify long, diverse, non-dictionary passwords score very strong."""
        res = evaluate_strength("Xk9#mZp!2026StrongPass#Winter")
        assert res.level == StrengthLevel.VERY_STRONG
        assert res.score >= 80

    def test_repeated_chars_penalty(self) -> None:
        """Verify character repetition penalty."""
        base_res = evaluate_strength("AbcDefGh123!")
        repeat_res = evaluate_strength("AbcDefGh123!aaaa")
        # Repetition penalty should be applied
        assert any("repeating" in f.lower() for f in repeat_res.feedback)

    def test_sequential_chars_penalty(self) -> None:
        """Verify sequential characters penalty (e.g. 123, abc)."""
        res = evaluate_strength("P@ss123456Abc")
        assert any("sequential" in f.lower() for f in res.feedback)

    def test_custom_dictionary(self, temp_wordlist: Path) -> None:
        """Verify checker functions properly with a custom wordlist."""
        dm = DictionaryManager(temp_wordlist)
        dm.load()
        assert check_dictionary("baseball", dictionary=dm) is True
        assert check_dictionary("not_in_custom_list", dictionary=dm) is False


class TestPasswordPolicy:
    """Tests for core.password_policy module."""

    def test_policy_defaults_pass_on_strong_password(self) -> None:
        policy = PasswordPolicy()
        res = policy.evaluate("Str0ng!Pass#2026")
        assert res.passed is True
        assert res.failed_count == 0
        assert res.compliance_percentage == 100.0

    def test_policy_fails_on_short_password(self) -> None:
        policy = PasswordPolicy(min_length=8)
        res = policy.evaluate("Ab1!")
        assert res.passed is False
        assert any("length" in r.name.lower() and not r.passed for r in res.rules)

    def test_policy_fails_on_missing_special(self) -> None:
        policy = PasswordPolicy(require_special=True)
        res = policy.evaluate("ValidPassword123")
        assert res.passed is False
        assert any("special" in r.name.lower() and not r.passed for r in res.rules)
