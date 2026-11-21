"""
Linux shadow hash file importer.

Supports importing password hashes from files in /etc/shadow format or
simplified formats:
  1. username:hash_string                           — Simple username:hash
  2. username:hash_string:last_changed:min:max:warn:inactive:expire:reserved
                                                     — Full /etc/shadow line

Provides strict validation and clear error reporting for malformed records.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from collectors.linux_shadow_collector import ShadowEntry, _parse_shadow_line

logger = logging.getLogger(__name__)

# Valid crypt-hash prefixes
_KNOWN_HASH_PREFIXES = ("$6$", "$5$", "$y$", "$2b$", "$2a$", "$2y$", "$1$")


@dataclass(frozen=True)
class ShadowImportError:
    """Details about a malformed record in the import file."""

    line_number: int
    line_content: str
    error_message: str


@dataclass(frozen=True)
class ShadowImportResult:
    """Complete result of importing a shadow hash file."""

    entries: List[ShadowEntry]
    errors: List[ShadowImportError]
    total_lines: int
    skipped_lines: int
    file_path: str

    @property
    def success_count(self) -> int:
        """Number of successfully imported entries."""
        return len(self.entries)

    @property
    def error_count(self) -> int:
        """Number of malformed records."""
        return len(self.errors)

    @property
    def is_successful(self) -> bool:
        """Whether at least one entry was imported without errors."""
        return len(self.entries) > 0 and len(self.errors) == 0

    @property
    def has_errors(self) -> bool:
        """Whether any malformed records were found."""
        return len(self.errors) > 0


def _is_valid_crypt_hash(hash_string: str) -> bool:
    """Check if a string looks like a valid crypt-style password hash."""
    if not hash_string:
        return False
    # Must start with a known prefix
    for prefix in _KNOWN_HASH_PREFIXES:
        if hash_string.startswith(prefix):
            return True
    # DES crypt: exactly 13 chars, no $ prefix
    if len(hash_string) == 13 and not hash_string.startswith("$"):
        return True
    return False


def _sanitize_line(line: str, max_length: int = 100) -> str:
    """Sanitize a line for safe display in error messages (mask hash content)."""
    if len(line) > max_length:
        return line[:max_length] + "..."
    return line


def parse_shadow_file(filepath: str) -> ShadowImportResult:
    """
    Parse a file containing Linux shadow-format password hashes.

    Supported formats (one per line):
      1. username:hash_string                           — Simple username:hash
      2. username:hash:last_changed:min:max:warn:inactive:expire:reserved
                                                         — Full shadow line

    Lines that are blank or start with '#' are skipped. Invalid records
    are collected as errors with descriptive messages.

    Args:
        filepath: Path to the shadow hash file.

    Returns:
        A ShadowImportResult with successfully parsed entries and any errors.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"Shadow hash file not found: {filepath}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {filepath}")

    entries: list[ShadowEntry] = []
    errors: list[ShadowImportError] = []
    total_lines = 0
    skipped_lines = 0
    seen_usernames: set[str] = set()

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
                    f"Cannot decode shadow file with any supported encoding: "
                    f"{', '.join(encodings)}"
                )
            continue
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {filepath}")
        except OSError as exc:
            raise OSError(f"Error reading shadow file: {exc}") from exc

    for line_num, raw_line in enumerate(lines, start=1):
        total_lines += 1
        stripped = raw_line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            skipped_lines += 1
            continue

        parts = stripped.split(":")
        num_parts = len(parts)

        # Need at least 2 fields: username:hash
        if num_parts < 2:
            errors.append(
                ShadowImportError(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=(
                        "Unrecognized format. Expected at least 'username:hash'. "
                        "Supported: 'username:hash' or full /etc/shadow line."
                    ),
                )
            )
            continue

        username = parts[0].strip()
        hash_field = parts[1].strip()

        if not username:
            errors.append(
                ShadowImportError(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message="Username field is empty.",
                )
            )
            continue

        if not hash_field:
            errors.append(
                ShadowImportError(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=f"Hash field is empty for user '{username}'.",
                )
            )
            continue

        # Check for locked / disabled accounts
        is_locked = False
        if hash_field in ("!", "*", "!!", "!!*"):
            is_locked = True
        elif hash_field.startswith(("!", "*")):
            is_locked = True

        # Validate the hash looks like a valid crypt hash (unless locked)
        if not is_locked and not _is_valid_crypt_hash(hash_field):
            errors.append(
                ShadowImportError(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=(
                        f"Invalid hash format for user '{username}'. "
                        "Expected a crypt-style hash starting with $6$, $5$, $y$, "
                        "$2b$, $2a$, $2y$, $1$, or a 13-char DES hash."
                    ),
                )
            )
            continue

        # Check for duplicate usernames
        username_lower = username.lower()
        if username_lower in seen_usernames:
            errors.append(
                ShadowImportError(
                    line_number=line_num,
                    line_content=_sanitize_line(stripped),
                    error_message=f"Duplicate username: '{username}'.",
                )
            )
            continue

        seen_usernames.add(username_lower)

        # Parse optional numeric fields from full shadow format
        def _parse_opt_int(idx: int) -> Optional[int]:
            if idx < num_parts:
                val = parts[idx].strip()
                if val:
                    try:
                        return int(val)
                    except ValueError:
                        return None
            return None

        entry = ShadowEntry(
            username=username,
            hash_string=hash_field,
            last_changed=_parse_opt_int(2),
            min_days=_parse_opt_int(3),
            max_days=_parse_opt_int(4),
            warn_days=_parse_opt_int(5),
            inactive_days=_parse_opt_int(6),
            expire_date=_parse_opt_int(7),
            is_locked=is_locked,
            is_empty_password=False,
            raw_line=stripped,
        )

        entries.append(entry)

    logger.info(
        "Imported %d shadow entries from %s (%d errors, %d skipped)",
        len(entries),
        filepath,
        len(errors),
        skipped_lines,
    )

    return ShadowImportResult(
        entries=entries,
        errors=errors,
        total_lines=total_lines,
        skipped_lines=skipped_lines,
        file_path=str(path),
    )
