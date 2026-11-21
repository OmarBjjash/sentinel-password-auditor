"""
Audit result models.

Provides dataclasses for representing individual audit results and aggregate
audit summaries. Used by all auditor implementations to report findings.
"""

import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AuditStatus(str, Enum):
    """Status codes for audit results."""

    WEAK_PASSWORD = "WEAK_PASSWORD"
    STRONG_PASSWORD = "STRONG_PASSWORD"
    LOCKED = "LOCKED"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class AuditResult:
    """
    Result of auditing a single user account.

    Attributes:
        username: The account username.
        algorithm: The hashing algorithm used (e.g., SHA-512, NTLM).
        status: The audit status (WEAK_PASSWORD, STRONG_PASSWORD, etc.).
        is_weak: Whether the password was found to be weak.
        recommendation: Actionable recommendation for the account.
        audit_type: The audit type ('linux' or 'windows').
        timestamp: When the audit result was generated.
        matched_word: The dictionary word that matched (only for weak passwords).
    """

    username: str
    algorithm: str
    status: str
    is_weak: bool
    recommendation: str
    audit_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    matched_word: Optional[str] = None

    @classmethod
    def weak(
        cls,
        username: str,
        algorithm: str,
        audit_type: str,
        matched_word: Optional[str] = None,
    ) -> "AuditResult":
        """Create a result for a weak password."""
        return cls(
            username=username,
            algorithm=algorithm,
            status=AuditStatus.WEAK_PASSWORD.value,
            is_weak=True,
            recommendation=(
                f"Password for '{username}' was found in the dictionary. "
                "Change it immediately to a strong, unique password."
            ),
            audit_type=audit_type,
            matched_word=matched_word,
        )

    @classmethod
    def strong(
        cls, username: str, algorithm: str, audit_type: str
    ) -> "AuditResult":
        """Create a result for a strong password."""
        return cls(
            username=username,
            algorithm=algorithm,
            status=AuditStatus.STRONG_PASSWORD.value,
            is_weak=False,
            recommendation=(
                f"Password for '{username}' was not found in the dictionary. "
                "Continue using strong password practices."
            ),
            audit_type=audit_type,
        )

    @classmethod
    def locked(
        cls, username: str, audit_type: str, algorithm: str = "N/A"
    ) -> "AuditResult":
        """Create a result for a locked account."""
        return cls(
            username=username,
            algorithm=algorithm,
            status=AuditStatus.LOCKED.value,
            is_weak=False,
            recommendation=f"Account '{username}' is locked or disabled.",
            audit_type=audit_type,
        )

    @classmethod
    def error(
        cls,
        username: str,
        audit_type: str,
        error_message: str,
        algorithm: str = "N/A",
    ) -> "AuditResult":
        """Create a result for an error during auditing."""
        return cls(
            username=username,
            algorithm=algorithm,
            status=AuditStatus.ERROR.value,
            is_weak=False,
            recommendation=f"Error auditing '{username}': {error_message}",
            audit_type=audit_type,
        )

    @classmethod
    def unsupported(
        cls, username: str, algorithm: str, audit_type: str
    ) -> "AuditResult":
        """Create a result for an unsupported hash algorithm."""
        return cls(
            username=username,
            algorithm=algorithm,
            status=AuditStatus.UNSUPPORTED.value,
            is_weak=False,
            recommendation=(
                f"Hash algorithm '{algorithm}' for '{username}' is not supported "
                "on this platform."
            ),
            audit_type=audit_type,
        )

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert result to dictionary, stripping sensitive information by default."""
        data: Dict[str, Any] = {
            "username": self.username,
            "algorithm": self.algorithm,
            "status": self.status,
            "is_weak": self.is_weak,
            "recommendation": self.recommendation,
            "audit_type": self.audit_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
        if include_sensitive and self.matched_word:
            data["matched_word"] = self.matched_word
        return data


@dataclass
class AuditSummary:
    """
    Aggregate summary of an audit run.

    Attributes:
        total_accounts: Total number of accounts audited.
        weak_accounts: Number of accounts with weak passwords.
        strong_accounts: Number of accounts with strong passwords.
        locked_accounts: Number of locked/disabled accounts.
        error_accounts: Number of accounts with audit errors.
        unsupported_accounts: Number of accounts with unsupported algorithms.
        results: List of individual audit results.
        audit_type: The audit type ('linux' or 'windows').
        timestamp: When the audit summary was generated.
        os_info: Operating system information.
        error_message: Optional error message if the audit failed entirely.
        duration_seconds: Time taken for the audit in seconds.
    """

    total_accounts: int
    weak_accounts: int
    strong_accounts: int
    locked_accounts: int
    error_accounts: int
    unsupported_accounts: int
    results: List[AuditResult]
    audit_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    os_info: Dict[str, str] = field(default_factory=dict)
    error_message: Optional[str] = None
    duration_seconds: float = 0.0

    @classmethod
    def from_results(
        cls,
        results: List[AuditResult],
        audit_type: str,
        duration_seconds: float = 0.0,
    ) -> "AuditSummary":
        """
        Create an AuditSummary from a list of AuditResult objects.

        Args:
            results: List of individual audit results.
            audit_type: The type of audit ('linux' or 'windows').
            duration_seconds: Time taken for the audit.

        Returns:
            An AuditSummary aggregating the results.
        """
        weak = sum(1 for r in results if r.status == AuditStatus.WEAK_PASSWORD.value)
        strong = sum(
            1 for r in results if r.status == AuditStatus.STRONG_PASSWORD.value
        )
        locked = sum(1 for r in results if r.status == AuditStatus.LOCKED.value)
        errors = sum(1 for r in results if r.status == AuditStatus.ERROR.value)
        unsupported = sum(
            1 for r in results if r.status == AuditStatus.UNSUPPORTED.value
        )

        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": platform.node(),
        }

        return cls(
            total_accounts=len(results),
            weak_accounts=weak,
            strong_accounts=strong,
            locked_accounts=locked,
            error_accounts=errors,
            unsupported_accounts=unsupported,
            results=results,
            audit_type=audit_type,
            os_info=os_info,
            duration_seconds=duration_seconds,
        )

    @classmethod
    def create_empty(
        cls, audit_type: str, error_message: Optional[str] = None
    ) -> "AuditSummary":
        """
        Create an empty AuditSummary, typically used when an audit cannot proceed.

        Args:
            audit_type: The type of audit.
            error_message: Optional error message explaining why the audit failed.

        Returns:
            An empty AuditSummary.
        """
        return cls(
            total_accounts=0,
            weak_accounts=0,
            strong_accounts=0,
            locked_accounts=0,
            error_accounts=0,
            unsupported_accounts=0,
            results=[],
            audit_type=audit_type,
            error_message=error_message,
        )

    @property
    def has_weak_passwords(self) -> bool:
        """Whether any weak passwords were found."""
        return self.weak_accounts > 0

    @property
    def weakness_percentage(self) -> float:
        """Percentage of audited accounts with weak passwords."""
        if self.total_accounts == 0:
            return 0.0
        return (self.weak_accounts / self.total_accounts) * 100.0

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert summary to dictionary, stripping sensitive information by default."""
        return {
            "total_accounts": self.total_accounts,
            "weak_accounts": self.weak_accounts,
            "strong_accounts": self.strong_accounts,
            "locked_accounts": self.locked_accounts,
            "error_accounts": self.error_accounts,
            "unsupported_accounts": self.unsupported_accounts,
            "audit_type": self.audit_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "os_info": self.os_info,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "weakness_percentage": self.weakness_percentage,
            "results": [
                r.to_dict(include_sensitive=include_sensitive) for r in self.results
            ],
        }
