"""
Shared pytest fixtures and test configuration for Sentinel Password Auditor.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List

import pytest

from auditors.audit_result import AuditResult, AuditStatus, AuditSummary
from core.dictionary_manager import DictionaryManager


@pytest.fixture(autouse=True)
def reset_dictionary_manager() -> Generator[None, None, None]:
    """Ensure DictionaryManager singleton is reset before each test."""
    DictionaryManager.reset()
    yield
    DictionaryManager.reset()


@pytest.fixture
def temp_wordlist(tmp_path: Path) -> Path:
    """Create a temporary wordlist file for testing."""
    wordlist_file = tmp_path / "test_wordlist.txt"
    content = (
        "password\n"
        "123456\n"
        "12345678\n"
        "qwerty\n"
        "admin\n"
        "letmein\n"
        "welcome\n"
        "shadow\n"
        "dragon\n"
        "baseball\n"
        "\n"
        "PASSWORD\n"  # duplicate testing
    )
    wordlist_file.write_text(content, encoding="utf-8")
    return wordlist_file


@pytest.fixture
def temp_hash_file(tmp_path: Path) -> Path:
    """Create a temporary NTLM hash file for testing."""
    hash_file = tmp_path / "test_hashes.txt"
    content = (
        "alice:8846F7EAEE8FB117AD06BDD830B7586C\n"  # password (weak)
        "bob:E19CCF750465A06B4D603A684D4511A8\n"    # 123456 (weak)
        "charlie:125bb5b52406ff09ee0c43655c9ae051\n" # unmatched (strong)
        "# This is a comment\n"
        "\n"
    )
    hash_file.write_text(content, encoding="utf-8")
    return hash_file


@pytest.fixture
def sample_audit_results() -> List[AuditResult]:
    """Sample list of AuditResult instances for report tests."""
    return [
        AuditResult.weak("alice", "NTLM", "windows", "password"),
        AuditResult.strong("bob", "NTLM", "windows"),
        AuditResult.locked("daemon", "linux"),
        AuditResult.error("malformed", "windows", "Invalid record format"),
        AuditResult.unsupported("guest", "DES", "linux"),
    ]


@pytest.fixture
def sample_audit_summary(sample_audit_results: List[AuditResult]) -> AuditSummary:
    """Sample AuditSummary for testing."""
    return AuditSummary.from_results(sample_audit_results, audit_type="windows", duration_seconds=0.15)
