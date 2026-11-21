"""
Audit orchestration engine.

Coordinates password auditing across Linux and Windows systems by delegating
to platform-specific auditors. Provides a unified interface for running audits
with progress callbacks suitable for GUI integration and threading.
"""

import logging
import platform
from pathlib import Path
from typing import Callable, List, Optional

from auditors.audit_result import AuditResult, AuditSummary
from core.dictionary_manager import DictionaryManager

logger = logging.getLogger(__name__)

# Type alias for progress callbacks: (current_step, total_steps, message)
ProgressCallback = Optional[Callable[[int, int, str], None]]


class AuditEngine:
    """
    Central audit orchestration engine.

    Coordinates dictionary loading, platform detection, and delegates to
    the appropriate auditor. Designed to be called from a background thread
    to avoid blocking the GUI.
    """

    def __init__(self, wordlist_path: Optional[Path] = None) -> None:
        """
        Initialize the audit engine.

        Args:
            wordlist_path: Optional path to a custom wordlist file.
                           Uses the default if not specified.
        """
        self._dictionary = DictionaryManager(wordlist_path)
        self._is_running: bool = False
        self._cancel_requested: bool = False

    @property
    def is_running(self) -> bool:
        """Whether an audit is currently in progress."""
        return self._is_running

    def request_cancel(self) -> None:
        """Request cancellation of the current audit."""
        self._cancel_requested = True
        logger.info("Audit cancellation requested")

    def _ensure_dictionary_loaded(self) -> bool:
        """Load the dictionary if not already loaded, or reload if modified on disk."""
        if not self._dictionary.is_loaded:
            success = self._dictionary.load()
            if not success:
                logger.error(
                    "Failed to load dictionary: %s", self._dictionary.load_error
                )
            return success

        # Auto-check if wordlist file changed on disk
        try:
            wpath = self._dictionary.wordlist_path
            if wpath.exists():
                mtime = wpath.stat().st_mtime
                if mtime != getattr(self._dictionary, "_last_mtime", None):
                    logger.info("Detected change in wordlist file '%s'; reloading...", wpath)
                    self._dictionary.load(force_reload=True)
        except Exception as exc:
            logger.debug("Error checking wordlist timestamp: %s", exc)

        return True

    def run_linux_audit(
        self, progress_callback: ProgressCallback = None
    ) -> AuditSummary:
        """
        Run a password audit against Linux /etc/shadow.

        Requires root/sudo access on Linux systems. Reads shadow entries and
        compares each password hash against the wordlist.

        Args:
            progress_callback: Optional callback for progress updates.
                               Signature: (current, total, message) -> None

        Returns:
            An AuditSummary containing all audit results.
        """
        self._is_running = True
        self._cancel_requested = False

        try:
            if not self._ensure_dictionary_loaded():
                return AuditSummary.create_empty(
                    audit_type="linux",
                    error_message="Failed to load wordlist dictionary.",
                )

            if progress_callback:
                progress_callback(0, 0, "Initializing Linux audit...")

            from auditors.linux_auditor import LinuxAuditor

            auditor = LinuxAuditor(self._dictionary)
            results = auditor.audit(
                progress_callback=progress_callback,
                cancel_check=lambda: self._cancel_requested,
            )

            return AuditSummary.from_results(results, audit_type="linux")

        except ImportError as exc:
            logger.error("Linux auditor import failed: %s", exc)
            return AuditSummary.create_empty(
                audit_type="linux",
                error_message=f"Linux auditor not available: {exc}",
            )
        except Exception as exc:
            logger.exception("Linux audit failed with unexpected error")
            return AuditSummary.create_empty(
                audit_type="linux",
                error_message=f"Audit failed: {exc}",
            )
        finally:
            self._is_running = False
            self._cancel_requested = False

    def run_linux_shadow_file_audit(
        self,
        shadow_file_path: str,
        progress_callback: ProgressCallback = None,
    ) -> AuditSummary:
        """
        Run a password audit against Linux shadow hashes from an imported file (Mode B).

        Reads shadow-format entries from a file and compares each password
        hash against the wordlist.

        Args:
            shadow_file_path: Path to the shadow hash file.
            progress_callback: Optional callback for progress updates.

        Returns:
            An AuditSummary containing all audit results.
        """
        self._is_running = True
        self._cancel_requested = False

        try:
            if not self._ensure_dictionary_loaded():
                return AuditSummary.create_empty(
                    audit_type="linux",
                    error_message="Failed to load wordlist dictionary.",
                )

            shadow_path = Path(shadow_file_path)
            if not shadow_path.exists():
                return AuditSummary.create_empty(
                    audit_type="linux",
                    error_message=f"Shadow hash file not found: {shadow_file_path}",
                )

            if progress_callback:
                progress_callback(0, 0, "Initializing Linux shadow file audit...")

            from auditors.linux_auditor import LinuxAuditor

            auditor = LinuxAuditor(self._dictionary)
            results = auditor.audit_from_file(
                shadow_file_path=str(shadow_path),
                progress_callback=progress_callback,
                cancel_check=lambda: self._cancel_requested,
            )

            return AuditSummary.from_results(results, audit_type="linux")

        except ImportError as exc:
            logger.error("Linux auditor import failed: %s", exc)
            return AuditSummary.create_empty(
                audit_type="linux",
                error_message=f"Linux auditor not available: {exc}",
            )
        except Exception as exc:
            logger.exception("Linux shadow file audit failed with unexpected error")
            return AuditSummary.create_empty(
                audit_type="linux",
                error_message=f"Audit failed: {exc}",
            )
        finally:
            self._is_running = False
            self._cancel_requested = False

    def run_windows_audit(
        self,
        hash_file_path: str,
        progress_callback: ProgressCallback = None,
    ) -> AuditSummary:
        """
        Run a password audit against Windows NTLM hashes from an authorized file (Mode B).

        Reads NTLM hashes from an authorized file and compares them against
        the wordlist by pre-computing NTLM hashes for all dictionary words.

        Args:
            hash_file_path: Path to the file containing username:NTLM_HASH entries.
            progress_callback: Optional callback for progress updates.

        Returns:
            An AuditSummary containing all audit results.
        """
        self._is_running = True
        self._cancel_requested = False

        try:
            if not self._ensure_dictionary_loaded():
                return AuditSummary.create_empty(
                    audit_type="windows",
                    error_message="Failed to load wordlist dictionary.",
                )

            hash_path = Path(hash_file_path)
            if not hash_path.exists():
                return AuditSummary.create_empty(
                    audit_type="windows",
                    error_message=f"Hash file not found: {hash_file_path}",
                )

            if progress_callback:
                progress_callback(0, 0, "Initializing Windows audit...")

            from auditors.windows_auditor import WindowsAuditor

            auditor = WindowsAuditor(self._dictionary)
            results = auditor.audit(
                hash_file_path=str(hash_path),
                progress_callback=progress_callback,
                cancel_check=lambda: self._cancel_requested,
            )

            return AuditSummary.from_results(results, audit_type="windows")

        except ImportError as exc:
            logger.error("Windows auditor import failed: %s", exc)
            return AuditSummary.create_empty(
                audit_type="windows",
                error_message=f"Windows auditor not available: {exc}",
            )
        except Exception as exc:
            logger.exception("Windows audit failed with unexpected error")
            return AuditSummary.create_empty(
                audit_type="windows",
                error_message=f"Audit failed: {exc}",
            )
        finally:
            self._is_running = False
            self._cancel_requested = False

    def run_windows_local_sam_audit(
        self,
        progress_callback: ProgressCallback = None,
    ) -> AuditSummary:
        """
        Run a live audit against the local Windows SAM database (Mode A).

        Requires Administrator privileges. Acquires local SAM/SYSTEM registry hives,
        decrypts local account NTLM hashes in-memory, and evaluates them against the wordlist.
        Does not retain credential secrets or registry files.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            An AuditSummary containing all audit results.
        """
        self._is_running = True
        self._cancel_requested = False

        try:
            if not self._ensure_dictionary_loaded():
                return AuditSummary.create_empty(
                    audit_type="windows",
                    error_message="Failed to load wordlist dictionary.",
                )

            if progress_callback:
                progress_callback(0, 0, "Initializing Local Windows SAM audit...")

            from auditors.windows_auditor import WindowsAuditor

            auditor = WindowsAuditor(self._dictionary)
            results = auditor.audit_local_sam(
                progress_callback=progress_callback,
                cancel_check=lambda: self._cancel_requested,
            )

            return AuditSummary.from_results(results, audit_type="windows")

        except ImportError as exc:
            logger.error("Windows auditor import failed: %s", exc)
            return AuditSummary.create_empty(
                audit_type="windows",
                error_message=f"Windows auditor not available: {exc}",
            )
        except Exception as exc:
            logger.exception("Windows local SAM audit failed with unexpected error")
            return AuditSummary.create_empty(
                audit_type="windows",
                error_message=f"Local SAM audit failed: {exc}",
            )
        finally:
            self._is_running = False
            self._cancel_requested = False

    def run_windows_offline_sam_audit(
        self,
        sam_path: str,
        system_path: str,
        progress_callback: ProgressCallback = None,
    ) -> AuditSummary:
        """
        Run an audit against offline SAM and SYSTEM hive files.

        Args:
            sam_path: Path to SAM hive.
            system_path: Path to SYSTEM hive.
            progress_callback: Progress callback.

        Returns:
            An AuditSummary containing results.
        """
        self._is_running = True
        self._cancel_requested = False

        try:
            if not self._ensure_dictionary_loaded():
                return AuditSummary.create_empty(
                    audit_type="windows",
                    error_message="Failed to load wordlist dictionary.",
                )

            from auditors.windows_auditor import WindowsAuditor

            auditor = WindowsAuditor(self._dictionary)
            results = auditor.audit_offline_sam(
                sam_path=sam_path,
                system_path=system_path,
                progress_callback=progress_callback,
                cancel_check=lambda: self._cancel_requested,
            )

            return AuditSummary.from_results(results, audit_type="windows")

        except Exception as exc:
            logger.exception("Offline SAM audit failed: %s", exc)
            return AuditSummary.create_empty(
                audit_type="windows",
                error_message=f"Offline SAM audit failed: {exc}",
            )
        finally:
            self._is_running = False
            self._cancel_requested = False

    def get_dictionary_stats(self) -> dict:
        """
        Get statistics about the loaded dictionary.

        Returns:
            Dictionary with word count, file size, load time, etc.
        """
        if not self._dictionary.is_loaded:
            self._ensure_dictionary_loaded()

        stats = self._dictionary.stats
        if stats is None:
            return {
                "loaded": False,
                "error": self._dictionary.load_error or "Dictionary not loaded",
            }

        return {
            "loaded": True,
            "word_count": stats.word_count,
            "file_size": stats.file_size_human,
            "file_size_bytes": stats.file_size_bytes,
            "load_time_seconds": round(stats.load_time_seconds, 3),
            "file_path": stats.file_path,
        }

    @staticmethod
    def detect_platform() -> str:
        """Detect the current operating system platform."""
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        return system
