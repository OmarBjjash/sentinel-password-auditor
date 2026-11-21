"""
Linux system password auditor.

Audits Linux user accounts by reading /etc/shadow entries and comparing
password hashes against a dictionary wordlist. Supports SHA-512, SHA-256,
MD5, DES, bcrypt, and yescrypt hash algorithms.
"""

import logging
import time
from typing import Callable, List, Optional

from auditors.audit_result import AuditResult
from collectors.linux_shadow_collector import ShadowEntry, read_shadow
from collectors.linux_shadow_importer import parse_shadow_file
from core.dictionary_manager import DictionaryManager
from core.password_hasher import (
    HashAlgorithm,
    identify_algorithm,
    is_algorithm_supported,
    verify_linux_hash,
)

logger = logging.getLogger(__name__)

# Type alias for progress callback: (current, total, message)
ProgressCallback = Optional[Callable[[int, int, str], None]]
CancelCheck = Optional[Callable[[], bool]]


class LinuxAuditor:
    """
    Audits Linux user accounts against a dictionary wordlist.

    Reads shadow entries, identifies hash algorithms, and tests each
    account's password against every word in the wordlist.
    """

    def __init__(self, dictionary: DictionaryManager) -> None:
        """
        Initialize the Linux auditor.

        Args:
            dictionary: A loaded DictionaryManager instance.
        """
        self._dictionary = dictionary

    def audit(
        self,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Run the Linux password audit.

        Reads /etc/shadow, identifies hash algorithms for each entry,
        and tests each password against the wordlist.

        Args:
            progress_callback: Optional callback for progress updates.
                               Signature: (current, total, message) -> None
            cancel_check: Optional callable that returns True to cancel.

        Returns:
            List of AuditResult objects, one per audited account.
        """
        results: list[AuditResult] = []

        # Read shadow entries
        try:
            if progress_callback:
                progress_callback(0, 0, "Reading /etc/shadow...")
            entries = read_shadow()
        except PermissionError as exc:
            logger.error("Permission denied: %s", exc)
            results.append(
                AuditResult.error(
                    username="<system>",
                    audit_type="linux",
                    error_message=str(exc),
                )
            )
            return results
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            logger.error("Cannot read shadow: %s", exc)
            results.append(
                AuditResult.error(
                    username="<system>",
                    audit_type="linux",
                    error_message=str(exc),
                )
            )
            return results

        if not entries:
            logger.info("No auditable entries found in /etc/shadow")
            return results

        total_entries = len(entries)
        wordlist = list(self._dictionary.get_words())
        total_words = len(wordlist)

        if progress_callback:
            progress_callback(
                0,
                total_entries,
                f"Auditing {total_entries} accounts against {total_words} words...",
            )

        for entry_idx, entry in enumerate(entries):
            if cancel_check and cancel_check():
                logger.info("Audit cancelled by user")
                break

            result = self._audit_entry(
                entry=entry,
                wordlist=wordlist,
                entry_idx=entry_idx,
                total_entries=total_entries,
                total_words=total_words,
                progress_callback=progress_callback,
                cancel_check=cancel_check,
            )
            results.append(result)

        return results

    def audit_from_file(
        self,
        shadow_file_path: str,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Run the Linux password audit against an imported shadow hash file (Mode B).

        Reads shadow-format entries from a file and tests each password
        against the wordlist.

        Args:
            shadow_file_path: Path to the shadow hash file.
            progress_callback: Optional callback for progress updates.
            cancel_check: Optional callable that returns True to cancel.

        Returns:
            List of AuditResult objects, one per audited account.
        """
        results: list[AuditResult] = []

        try:
            if progress_callback:
                progress_callback(0, 0, f"Importing shadow hashes from file...")
            import_result = parse_shadow_file(shadow_file_path)
        except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
            logger.error("Cannot read shadow file: %s", exc)
            results.append(
                AuditResult.error(
                    username="<file>",
                    audit_type="linux",
                    error_message=str(exc),
                )
            )
            return results

        # Report import errors as individual results
        if import_result.has_errors:
            for err in import_result.errors:
                logger.warning(
                    "Import error at line %d: %s", err.line_number, err.error_message
                )

        entries = [e for e in import_result.entries if not e.is_locked]
        locked_entries = [e for e in import_result.entries if e.is_locked]

        # Add locked entries as results
        for entry in locked_entries:
            results.append(
                AuditResult.locked(
                    username=entry.username,
                    audit_type="linux",
                )
            )

        if not entries:
            logger.info("No auditable entries found in shadow file")
            if import_result.has_errors:
                results.append(
                    AuditResult.error(
                        username="<file>",
                        audit_type="linux",
                        error_message=(
                            f"No valid entries imported. "
                            f"{import_result.error_count} error(s) in file."
                        ),
                    )
                )
            return results

        total_entries = len(entries)
        wordlist = list(self._dictionary.get_words())
        total_words = len(wordlist)

        if progress_callback:
            progress_callback(
                0,
                total_entries,
                f"Auditing {total_entries} accounts against {total_words} words...",
            )

        for entry_idx, entry in enumerate(entries):
            if cancel_check and cancel_check():
                logger.info("Audit cancelled by user")
                break

            result = self._audit_entry(
                entry=entry,
                wordlist=wordlist,
                entry_idx=entry_idx,
                total_entries=total_entries,
                total_words=total_words,
                progress_callback=progress_callback,
                cancel_check=cancel_check,
            )
            results.append(result)

        return results

    def _audit_entry(
        self,
        entry: ShadowEntry,
        wordlist: list[str],
        entry_idx: int,
        total_entries: int,
        total_words: int,
        progress_callback: ProgressCallback,
        cancel_check: CancelCheck,
    ) -> AuditResult:
        """Audit a single shadow entry against the wordlist."""
        username = entry.username
        hash_string = entry.hash_string

        # Identify the hash algorithm
        algorithm = identify_algorithm(hash_string)

        if algorithm == HashAlgorithm.UNKNOWN:
            logger.warning(
                "Unknown hash algorithm for user '%s'", username
            )
            return AuditResult.error(
                username=username,
                audit_type="linux",
                error_message="Unknown hash algorithm",
                algorithm=algorithm.value,
            )

        # Check if the algorithm is supported on this platform
        if not is_algorithm_supported(algorithm):
            logger.info(
                "Unsupported algorithm %s for user '%s'",
                algorithm.value,
                username,
            )
            return AuditResult.unsupported(
                username=username,
                algorithm=algorithm.value,
                audit_type="linux",
            )

        if progress_callback:
            progress_callback(
                entry_idx,
                total_entries,
                f"Testing '{username}' ({algorithm.value})...",
            )

        last_progress_time = 0.0
        num_digits = len(str(total_words))

        # Test each word in the wordlist against the hash (exact + case variants)
        for word_idx, base_word in enumerate(wordlist):
            if cancel_check and cancel_check():
                return AuditResult.error(
                    username=username,
                    audit_type="linux",
                    error_message="Audit cancelled",
                    algorithm=algorithm.value,
                )

            current_num = word_idx + 1
            pct = int((current_num / total_words) * 100)
            now = time.time()
            if progress_callback and (
                now - last_progress_time >= 0.08
                or current_num == total_words
                or word_idx == 0
            ):
                last_progress_time = now
                if total_entries > 1:
                    status_msg = (
                        f'[{username}] {pct:>3}% ({current_num:>{num_digits}}/{total_words}) '
                        f'| current status: "{base_word}"'
                    )
                else:
                    status_msg = (
                        f'{pct:>3}% ({current_num:>{num_digits}}/{total_words}) '
                        f'| current status: "{base_word}"'
                    )
                progress_callback(current_num, total_words, status_msg)

            candidates = [base_word]
            w_lower = base_word.lower()
            if w_lower != base_word:
                candidates.append(w_lower)
            w_cap = base_word.capitalize()
            if w_cap not in candidates:
                candidates.append(w_cap)

            for cand in candidates:
                try:
                    if verify_linux_hash(cand, hash_string):
                        logger.info(
                            "WEAK password found for user '%s' (algorithm: %s)",
                            username,
                            algorithm.value,
                        )
                        return AuditResult.weak(
                            username=username,
                            algorithm=algorithm.value,
                            audit_type="linux",
                            matched_word=cand,
                        )
                except (ValueError, ImportError) as exc:
                    logger.debug(
                        "Verification error for '%s' with word #%d: %s",
                        username,
                        word_idx,
                        exc,
                    )
                    return AuditResult.error(
                        username=username,
                        audit_type="linux",
                        error_message=str(exc),
                        algorithm=algorithm.value,
                    )

        # No match found — password is not in the wordlist
        return AuditResult.strong(
            username=username,
            algorithm=algorithm.value,
            audit_type="linux",
        )
