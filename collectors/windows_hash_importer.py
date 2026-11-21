"""
Windows NTLM hash importer from authorized hash files.

Supports multiple hash dump formats:
  1. <LM_Hash>                                       — Standalone 32-hex LM hash
  2. <LM_Hash>:<NT_Hash>                             — LM:NT pair
  3. <Username>:<NT_Hash>                             — Simple username:hash
  4. <Username>:<UserID>:<LM_Hash>:<NT_Hash>:::       — pwdump / secretsdump format

Provides strict validation and clear error reporting for malformed records.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Hashes are exactly 32 hexadecimal characters
_HEX32_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")

# Well-known sentinel hashes
_EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
_EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


@dataclass(frozen=True)
class ImportedHash:
    """An imported username and NTLM hash pair."""

    username: str
    ntlm_hash: str
    line_number: int
    lm_hash: Optional[str] = None      # Populated when available
    source_format: str = "unknown"      # e.g. "pwdump", "lm_nt", "user_nt", "lm_only"


@dataclass(frozen=True)
class ImportError_:
    """Details about a malformed record in the import file."""

    line_number: int
    line_content: str
    error_message: str


@dataclass(frozen=True)
class ImportResult:
    """Complete result of importing a hash file."""

    hashes: List[ImportedHash]
    errors: List[ImportError_]
    total_lines: int
    skipped_lines: int
    file_path: str

    @property
    def success_count(self) -> int:
        """Number of successfully imported hashes."""
        return len(self.hashes)

    @property
    def error_count(self) -> int:
        """Number of malformed records."""
        return len(self.errors)

    @property
    def is_successful(self) -> bool:
        """Whether at least one hash was imported without errors."""
        return len(self.hashes) > 0 and len(self.errors) == 0

    @property
    def has_errors(self) -> bool:
        """Whether any malformed records were found."""
        return len(self.errors) > 0


def validate_ntlm_hash(hash_str: str) -> bool:
    """
    Validate that a string is a valid NTLM hash (32 hex characters).

    Args:
        hash_str: The hash string to validate.

    Returns:
        True if the string is a valid NTLM hash format.
    """
    return bool(_HEX32_PATTERN.match(hash_str))


def _is_hex32(s: str) -> bool:
    """Check if a string is exactly 32 hex characters."""
    return bool(_HEX32_PATTERN.match(s))


def parse_hash_file(filepath: str) -> ImportResult:
    """
    Parse a hash file containing NTLM hashes in various formats.

    Supported formats (one per line):
      1. <LM_Hash>                                       — Standalone LM hash
      2. <LM_Hash>:<NT_Hash>                             — LM:NT pair
      3. <Username>:<NT_Hash>                             — Simple user:hash
      4. <Username>:<UserID>:<LM_Hash>:<NT_Hash>:::       — pwdump / secretsdump

    Lines that are blank or start with '#' are skipped. Invalid records
    are collected as errors with descriptive messages.

    Args:
        filepath: Path to the hash file.

    Returns:
        An ImportResult with successfully parsed hashes and any errors.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Hash file not found: {filepath}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {filepath}")

    hashes: list[ImportedHash] = []
    errors: list[ImportError_] = []
    total_lines = 0
    skipped_lines = 0
    seen_usernames: set[str] = set()
    unknown_counter = 0

    encodings = ("utf-8", "latin-1", "cp1252")
    lines: list[str] = []

    for encoding in encodings:
        try:
            with open(path, "r", encoding=encoding, errors="strict") as fh:
                lines = fh.readlines()
            break
        except UnicodeDecodeError:
            if encoding == encodings[-1]:
                raise ValueError(
                    f"Cannot decode hash file with any supported encoding: "
                    f"{', '.join(encodings)}"
                )
            continue
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {filepath}")
        except OSError as exc:
            raise OSError(f"Error reading hash file: {exc}") from exc

    for line_num, raw_line in enumerate(lines, start=1):
        total_lines += 1
        stripped = raw_line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            skipped_lines += 1
            continue

        # Detect format and parse
        result = _parse_line_multi_format(stripped, line_num)

        if result is None:
            errors.append(
                ImportError_(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=(
                        "Unrecognized format. Supported: "
                        "'username:NTLM', 'LM:NT', 'username:uid:LM:NT:::', "
                        "or standalone 32-hex hash."
                    ),
                )
            )
            continue

        username, ntlm_hash, lm_hash, source_format, error_msg = result

        if error_msg:
            errors.append(
                ImportError_(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=error_msg,
                )
            )
            continue

        # Generate username for formats that don't provide one
        if not username:
            unknown_counter += 1
            username = f"Unknown_{unknown_counter}"

        # Check for duplicate usernames
        username_lower = username.lower()
        if username_lower in seen_usernames:
            # Allow duplicates for auto-generated usernames
            if username.startswith("Unknown_"):
                unknown_counter += 1
                username = f"Unknown_{unknown_counter}"
                username_lower = username.lower()
            else:
                errors.append(
                    ImportError_(
                        line_number=line_num,
                        line_content=_sanitize_line(stripped),
                        error_message=f"Duplicate username: '{username}'.",
                    )
                )
                continue

        # Flag empty NT hash (password is blank)
        if ntlm_hash.lower() == _EMPTY_NT_HASH:
            logger.info(
                "Line %d: User '%s' has an empty-password NT hash.", line_num, username
            )

        seen_usernames.add(username_lower)
        hashes.append(
            ImportedHash(
                username=username,
                ntlm_hash=ntlm_hash.lower(),
                line_number=line_num,
                lm_hash=lm_hash.lower() if lm_hash else None,
                source_format=source_format,
            )
        )

    logger.info(
        "Imported %d hashes from %s (%d errors, %d skipped)",
        len(hashes),
        filepath,
        len(errors),
        skipped_lines,
    )

    return ImportResult(
        hashes=hashes,
        errors=errors,
        total_lines=total_lines,
        skipped_lines=skipped_lines,
        file_path=str(path),
    )


def _parse_line_multi_format(
    line: str, line_num: int
) -> Optional[Tuple[Optional[str], str, Optional[str], str, Optional[str]]]:
    """
    Parse a single line into (username, nt_hash, lm_hash, format, error_message).

    Returns None if the line cannot be parsed at all.
    Returns (username, nt_hash, lm_hash, format, None) on success.
    Returns (username, nt_hash, lm_hash, format, error_msg) on validation failure.

    Detection strategy (based on colon count and field content):
      - 0 colons: standalone hash (LM or NT)
      - 1 colon:  either username:NT_hash or LM_hash:NT_hash
      - 6+ colons: pwdump format (username:uid:LM:NT:::)
      - Other counts: try best-effort parsing
    """
    parts = line.split(":")
    num_parts = len(parts)

    # ── Format 4: pwdump / secretsdump ──────────────────────────────────
    # username:uid:LM_hash:NT_hash:::  (7 fields, last 3 empty)
    if num_parts >= 7:
        return _parse_pwdump(parts, line_num)

    # ── Format 1: Standalone hash (no colons) ───────────────────────────
    if num_parts == 1:
        return _parse_standalone(line, line_num)

    # ── 2 fields (1 colon): username:NT or LM:NT ───────────────────────
    if num_parts == 2:
        return _parse_two_fields(parts, line_num)

    # ── 4 fields (3 colons): might be incomplete pwdump ─────────────────
    if num_parts == 4:
        return _parse_four_fields(parts, line_num)

    # Unrecognized
    return None


def _parse_pwdump(
    parts: List[str], line_num: int
) -> Tuple[Optional[str], str, Optional[str], str, Optional[str]]:
    """
    Parse pwdump/secretsdump format: username:uid:LM_hash:NT_hash:::

    Fields: [0]=username, [1]=uid, [2]=LM_hash, [3]=NT_hash, [4:]=trailing colons
    """
    username = parts[0].strip()
    # uid = parts[1].strip()  # Not used for auditing
    lm_hash = parts[2].strip()
    nt_hash = parts[3].strip()

    if not username:
        return (None, "", None, "pwdump", "Username is empty in pwdump record.")

    if not nt_hash:
        return (username, "", None, "pwdump",
                f"NT hash field is empty for user '{username}' in pwdump record.")

    if not _is_hex32(nt_hash):
        if len(nt_hash) != 32:
            return (username, nt_hash, None, "pwdump",
                    f"Invalid NT hash for user '{username}': "
                    f"expected 32 hex characters, got {len(nt_hash)}.")
        return (username, nt_hash, None, "pwdump",
                f"Invalid NT hash for user '{username}': "
                f"contains non-hexadecimal characters.")

    # Validate LM hash if present (optional — may be empty or "NO PASSWORD" markers)
    valid_lm = None
    if lm_hash and _is_hex32(lm_hash):
        valid_lm = lm_hash

    return (username, nt_hash, valid_lm, "pwdump", None)


def _parse_standalone(
    line: str, line_num: int
) -> Optional[Tuple[Optional[str], str, Optional[str], str, Optional[str]]]:
    """
    Parse a standalone 32-hex hash on its own line.

    Could be an LM hash or NT hash. We treat it as an NT hash for auditing
    since we can only dictionary-attack NT hashes.
    """
    h = line.strip()
    if not _is_hex32(h):
        return None  # Not a valid standalone hash

    # If it's the empty LM hash, skip it (not useful for auditing)
    if h.lower() == _EMPTY_LM_HASH:
        return (None, "", None, "lm_only",
                "Standalone empty LM hash — no NT hash available, skipping.")

    return (None, h, None, "standalone", None)


def _parse_two_fields(
    parts: List[str], line_num: int
) -> Tuple[Optional[str], str, Optional[str], str, Optional[str]]:
    """
    Parse a two-field line: either username:NT_hash or LM_hash:NT_hash.

    Disambiguation:
      - If BOTH fields are 32-hex: treat as LM:NT (take second as NT hash)
      - If only second is 32-hex: treat as username:NT
      - Otherwise: error
    """
    field1 = parts[0].strip()
    field2 = parts[1].strip()

    f1_is_hex = _is_hex32(field1)
    f2_is_hex = _is_hex32(field2)

    if f1_is_hex and f2_is_hex:
        # Both are 32-hex: LM:NT format
        return (None, field2, field1, "lm_nt", None)

    if f2_is_hex:
        # username:NT format (original format)
        if not field1:
            return (None, field2, None, "user_nt", "Username is empty.")
        return (field1, field2, None, "user_nt", None)

    if f1_is_hex and not f2_is_hex:
        # First is a hash but second isn't — probably malformed
        if len(field2) != 32:
            return (None, field1, None, "standalone",
                    f"Second field is not a valid 32-hex hash "
                    f"(got {len(field2)} chars). "
                    f"Treating first field as NT hash.")

    # Neither field is a valid hash
    if not field1:
        return (field1, field2, None, "user_nt", "Username is empty.")

    if not field2:
        return (field1, field2, None, "user_nt",
                f"NTLM hash is empty for user '{field1}'.")

    if len(field2) != 32:
        return (field1, field2, None, "user_nt",
                f"Invalid NTLM hash for user '{field1}': "
                f"expected 32 hex characters, got {len(field2)}.")

    return (field1, field2, None, "user_nt",
            f"Invalid NTLM hash for user '{field1}': "
            f"contains non-hexadecimal characters.")


def _parse_four_fields(
    parts: List[str], line_num: int
) -> Optional[Tuple[Optional[str], str, Optional[str], str, Optional[str]]]:
    """
    Parse a four-field line: username:uid:LM:NT (pwdump without trailing colons).
    """
    username = parts[0].strip()
    nt_hash = parts[3].strip()
    lm_hash = parts[2].strip()

    if not username:
        return (None, "", None, "pwdump", "Username is empty in pwdump record.")

    if not nt_hash:
        return (username, "", None, "pwdump",
                f"NT hash field is empty for user '{username}'.")

    if not _is_hex32(nt_hash):
        if len(nt_hash) != 32:
            return (username, nt_hash, None, "pwdump",
                    f"Invalid NT hash for user '{username}': "
                    f"expected 32 hex characters, got {len(nt_hash)}.")
        return (username, nt_hash, None, "pwdump",
                f"Invalid NT hash for user '{username}': "
                f"contains non-hexadecimal characters.")

    valid_lm = None
    if lm_hash and _is_hex32(lm_hash):
        valid_lm = lm_hash

    return (username, nt_hash, valid_lm, "pwdump", None)


def _sanitize_line(line: str, max_length: int = 100) -> str:
    """Sanitize a line for safe display in error messages."""
    if len(line) > max_length:
        return line[:max_length] + "..."
    return line
