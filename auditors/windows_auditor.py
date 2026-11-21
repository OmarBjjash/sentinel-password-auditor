"""
Windows NTLM and LM password auditor.

Audits Windows user accounts by comparing acquired or imported NTLM and LM hashes
against a dictionary wordlist. Supports multiple acquisition workflows:
1. Live Local SAM Audit: Extracts local SAM hashes using Windows administrative
   APIs (similar to Ophcrack Local SAM).
2. Authorized Hash Import: Reads administrator-provided hash files in formats:
   - <LM Hash>
   - <LM Hash>:<NT Hash>
   - <UserName>:<UserID>:<LM Hash>:<NT Hash>:::
   - <UserName>:<NT Hash>

Pre-computes NTLM and LM hashes for the entire wordlist once for efficient O(1) matching.
"""

import logging
import time
from typing import Callable, Dict, List, Optional, Tuple

from auditors.audit_result import AuditResult
from collectors.windows_hash_importer import (
    ImportedHash,
    parse_hash_file,
    _EMPTY_LM_HASH,
    _EMPTY_NT_HASH,
)
from collectors.windows_sam_collector import (
    SAMAcquisitionResult,
    WindowsSAMAcquisitionService,
)
from core.dictionary_manager import DictionaryManager
from core.password_hasher import compute_lm_hash, compute_ntlm_hash

logger = logging.getLogger(__name__)

# Type aliases
ProgressCallback = Optional[Callable[[int, int, str], None]]
CancelCheck = Optional[Callable[[], bool]]


class WindowsAuditor:
    """
    Audits Windows user accounts against a dictionary wordlist using NTLM and LM hashes.

    Pre-computes NTLM and LM hashes for every word in the dictionary, then performs
    O(1) lookups for each acquired or imported user hash.
    """

    def __init__(self, dictionary: DictionaryManager) -> None:
        """
        Initialize the Windows auditor.

        Args:
            dictionary: A loaded DictionaryManager instance.
        """
        self._dictionary = dictionary
        self._sam_service = WindowsSAMAcquisitionService()

    def audit(
        self,
        hash_file_path: str,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Run the Windows NTLM/LM audit using an authorized hash file (Mode B).

        Args:
            hash_file_path: Path to the file containing hash entries.
            progress_callback: Optional callback for progress updates.
            cancel_check: Optional callable that returns True to cancel.

        Returns:
            List of AuditResult objects, one per audited account.
        """
        if progress_callback:
            progress_callback(0, 0, "Importing authorized hash file...")

        try:
            import_result = parse_hash_file(hash_file_path)
        except FileNotFoundError as exc:
            logger.error("Hash file not found: %s", exc)
            return [
                AuditResult.error(
                    username="<system>",
                    audit_type="windows",
                    error_message=f"Hash file not found: {hash_file_path}",
                    algorithm="NTLM",
                )
            ]
        except (PermissionError, ValueError, OSError) as exc:
            logger.error("Error reading hash file: %s", exc)
            return [
                AuditResult.error(
                    username="<system>",
                    audit_type="windows",
                    error_message=str(exc),
                    algorithm="NTLM",
                )
            ]

        if not import_result.hashes:
            msg = "No valid hashes found in the import file."
            if import_result.has_errors:
                msg += f" {import_result.error_count} malformed records were skipped."
            logger.warning(msg)
            return [
                AuditResult.error(
                    username="<system>",
                    audit_type="windows",
                    error_message=msg,
                    algorithm="NTLM",
                )
            ]

        for err in import_result.errors:
            logger.warning(
                "Import error on line %d: %s", err.line_number, err.error_message
            )

        return self._audit_hashes(
            hashes=import_result.hashes,
            progress_callback=progress_callback,
            cancel_check=cancel_check,
        )

    def audit_local_sam(
        self,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Run a live audit against the local Windows SAM database (Mode A).

        Requires Administrator privileges. Acquires local SAM and SYSTEM hives,
        decrypts local account NTLM/LM hashes in-memory, and matches against the wordlist.

        Args:
            progress_callback: Optional callback for progress updates.
            cancel_check: Optional callable that returns True to cancel.

        Returns:
            List of AuditResult objects.
        """
        if progress_callback:
            progress_callback(0, 0, "Initiating local Windows SAM acquisition...")

        acq_result: SAMAcquisitionResult = self._sam_service.acquire_live_sam(
            progress_callback=progress_callback
        )

        if not acq_result.success:
            logger.warning("Local SAM acquisition failed: %s", acq_result.error_message)
            return [
                AuditResult.error(
                    username="<system>",
                    audit_type="windows",
                    error_message=acq_result.error_message or "SAM acquisition failed.",
                    algorithm="NTLM",
                )
            ]

        return self._audit_hashes(
            hashes=acq_result.hashes,
            progress_callback=progress_callback,
            cancel_check=cancel_check,
        )

    def audit_offline_sam(
        self,
        sam_path: str,
        system_path: str,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Run an audit against offline SAM and SYSTEM hive files.

        Args:
            sam_path: Path to SAM hive.
            system_path: Path to SYSTEM hive.
            progress_callback: Optional callback for progress updates.
            cancel_check: Optional callable that returns True to cancel.

        Returns:
            List of AuditResult objects.
        """
        if progress_callback:
            progress_callback(0, 0, "Parsing offline SAM and SYSTEM hives...")

        acq_result: SAMAcquisitionResult = self._sam_service.acquire_offline_sam(
            sam_path=sam_path,
            system_path=system_path,
            progress_callback=progress_callback,
        )

        if not acq_result.success:
            logger.warning("Offline SAM parsing failed: %s", acq_result.error_message)
            return [
                AuditResult.error(
                    username="<system>",
                    audit_type="windows",
                    error_message=acq_result.error_message or "Failed to parse hives.",
                    algorithm="NTLM",
                )
            ]

        return self._audit_hashes(
            hashes=acq_result.hashes,
            progress_callback=progress_callback,
            cancel_check=cancel_check,
        )

    def _audit_hashes(
        self,
        hashes: List[ImportedHash],
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> List[AuditResult]:
        """
        Core NTLM/LM dictionary matching engine shared by all acquisition modes.

        Args:
            hashes: List of account hashes to audit.
            progress_callback: Progress reporting callback.
            cancel_check: Cancellation check callback.

        Returns:
            List of AuditResult objects.
        """
        results: list[AuditResult] = []

        if not hashes:
            return results

        # Pre-compute NTLM and LM hashes for the wordlist
        if progress_callback:
            progress_callback(
                0,
                0,
                f"Pre-computing hash tables for {self._dictionary.word_count} words...",
            )

        ntlm_lookup, lm_lookup = self._build_hash_lookups(
            progress_callback=progress_callback,
            cancel_check=cancel_check,
        )

        if cancel_check and cancel_check():
            logger.info("Audit cancelled during hash pre-computation")
            return results

        # Compare acquired/imported hashes against the lookup tables
        total_users = len(hashes)
        if progress_callback:
            progress_callback(
                0,
                total_users,
                f"Comparing {total_users} accounts against wordlist...",
            )

        for idx, imported in enumerate(hashes):
            if cancel_check and cancel_check():
                logger.info("Audit cancelled by user")
                break

            result = self._check_hash(imported, ntlm_lookup, lm_lookup)
            results.append(result)

            if progress_callback:
                progress_callback(
                    idx + 1,
                    total_users,
                    f"Audited '{imported.username}' ({idx + 1}/{total_users})",
                )

        return results

    def _build_hash_lookups(
        self,
        progress_callback: ProgressCallback = None,
        cancel_check: CancelCheck = None,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Build lookup dictionaries mapping NTLM and LM hashes to plaintext words.

        Returns:
            Tuple of (ntlm_lookup, lm_lookup) dicts mapping lowercase hash → plaintext word.
        """
        ntlm_lookup: dict[str, str] = {}
        lm_lookup: dict[str, str] = {}

        # Add empty password markers
        empty_ntlm = compute_ntlm_hash("")
        empty_lm = compute_lm_hash("")
        ntlm_lookup[empty_ntlm] = "<blank>"
        lm_lookup[empty_lm] = "<blank>"

        words = list(self._dictionary.get_words())
        total_words = len(words)
        num_digits = len(str(total_words))
        last_progress_time = 0.0

        for idx, base_word in enumerate(words):
            if cancel_check and cancel_check():
                break

            current_num = idx + 1
            pct = int((current_num / total_words) * 100)
            now = time.time()
            if progress_callback and (
                now - last_progress_time >= 0.08
                or current_num == total_words
                or idx == 0
            ):
                last_progress_time = now
                status_msg = (
                    f'Pre-computing {pct:>3}% ({current_num:>{num_digits}}/{total_words}) '
                    f'| current status: "{base_word}"'
                )
                progress_callback(current_num, total_words, status_msg)

            # Build candidates: exact casing as in wordlist, plus common case variants
            candidates = [base_word]
            w_lower = base_word.lower()
            if w_lower != base_word:
                candidates.append(w_lower)
            w_cap = base_word.capitalize()
            if w_cap not in candidates:
                candidates.append(w_cap)
            if len(base_word) <= 14:
                w_up = base_word.upper()
                if w_up not in candidates:
                    candidates.append(w_up)

            for cand in candidates:
                # Compute NTLM
                ntlm = compute_ntlm_hash(cand)
                if ntlm not in ntlm_lookup:
                    ntlm_lookup[ntlm] = cand

                # Compute LM for passwords <= 14 characters
                if len(cand) <= 14:
                    try:
                        lm = compute_lm_hash(cand)
                        if lm not in lm_lookup:
                            lm_lookup[lm] = cand
                    except Exception:
                        pass

            if progress_callback and (idx + 1) % 5000 == 0:
                progress_callback(
                    idx + 1,
                    total_words,
                    f"Pre-computing hashes... {idx + 1}/{total_words}",
                )

        logger.info(
            "Built hash lookups: %d NTLM entries, %d LM entries",
            len(ntlm_lookup),
            len(lm_lookup),
        )
        return ntlm_lookup, lm_lookup

    def _check_hash(
        self,
        imported: ImportedHash,
        ntlm_lookup: Dict[str, str],
        lm_lookup: Dict[str, str],
    ) -> AuditResult:
        """
        Check an individual hash against the NTLM and LM lookup tables.

        Args:
            imported: The imported/acquired hash entry.
            ntlm_lookup: Pre-computed NTLM hash → word mapping.
            lm_lookup: Pre-computed LM hash → word mapping.

        Returns:
            An AuditResult for this account.
        """
        nt_hash = imported.ntlm_hash.lower() if imported.ntlm_hash else ""
        lm_hash = imported.lm_hash.lower() if imported.lm_hash else ""

        # 1. Try matching NTLM hash
        if nt_hash:
            matched_word = ntlm_lookup.get(nt_hash)
            if matched_word is not None:
                logger.info(
                    "WEAK password found for Windows user '%s' via NTLM", imported.username
                )
                return AuditResult.weak(
                    username=imported.username,
                    algorithm="NTLM",
                    audit_type="windows",
                    matched_word=matched_word,
                )

        # 2. Try matching LM hash (ignore empty LM marker unless NT hash is also empty/missing)
        if lm_hash and lm_hash != _EMPTY_LM_HASH:
            matched_word = lm_lookup.get(lm_hash)
            if matched_word is not None:
                logger.info(
                    "WEAK password found for Windows user '%s' via LM", imported.username
                )
                return AuditResult.weak(
                    username=imported.username,
                    algorithm="LM",
                    audit_type="windows",
                    matched_word=matched_word,
                )

        # 3. For standalone / lm_only hashes, check if hash matches LM table
        if imported.source_format in ("standalone", "lm_only") and nt_hash:
            matched_word = lm_lookup.get(nt_hash)
            if matched_word is not None:
                logger.info(
                    "WEAK password found for Windows user '%s' via standalone LM",
                    imported.username,
                )
                return AuditResult.weak(
                    username=imported.username,
                    algorithm="LM",
                    audit_type="windows",
                    matched_word=matched_word,
                )

        # 4. Check for empty password hash
        if nt_hash == _EMPTY_NT_HASH or (lm_hash == _EMPTY_LM_HASH and not nt_hash):
            return AuditResult.weak(
                username=imported.username,
                algorithm="NTLM",
                audit_type="windows",
                matched_word="<blank>",
            )

        return AuditResult.strong(
            username=imported.username,
            algorithm="NTLM",
            audit_type="windows",
        )
