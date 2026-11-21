"""
Linux /etc/shadow collector.

Safely reads and parses the /etc/shadow file to extract password hash entries
for auditing. Handles permission errors, locked accounts, and malformed entries.
This module NEVER modifies /etc/shadow.
"""

import logging
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

SHADOW_PATH = "/etc/shadow"

# Prefixes indicating a locked or disabled account
_LOCKED_PREFIXES = ("!", "*")

# Fields in /etc/shadow (colon-delimited)
_FIELD_USERNAME = 0
_FIELD_HASH = 1
_FIELD_LAST_CHANGED = 2
_FIELD_MIN_DAYS = 3
_FIELD_MAX_DAYS = 4
_FIELD_WARN_DAYS = 5
_FIELD_INACTIVE_DAYS = 6
_FIELD_EXPIRE_DATE = 7


@dataclass(frozen=True)
class ShadowEntry:
    """Parsed entry from /etc/shadow."""

    username: str
    hash_string: str
    last_changed: Optional[int]
    min_days: Optional[int]
    max_days: Optional[int]
    warn_days: Optional[int]
    inactive_days: Optional[int]
    expire_date: Optional[int]
    is_locked: bool
    is_empty_password: bool
    raw_line: str


def detect_linux() -> bool:
    """
    Detect if the current system is running Linux.

    Returns:
        True if the platform is Linux.
    """
    return platform.system().lower() == "linux"


def check_shadow_access() -> bool:
    """
    Check if the current process has read access to /etc/shadow.

    Returns:
        True if /etc/shadow exists and is readable.
    """
    if not detect_linux():
        logger.info("Not a Linux system; /etc/shadow access check skipped")
        return False

    shadow = Path(SHADOW_PATH)
    if not shadow.exists():
        logger.warning("%s does not exist", SHADOW_PATH)
        return False

    if not os.access(SHADOW_PATH, os.R_OK):
        logger.warning(
            "%s exists but is not readable. Run with sudo or as root.",
            SHADOW_PATH,
        )
        return False

    return True


def _parse_optional_int(value: str) -> Optional[int]:
    """Parse an optional integer field from shadow, returning None for empty."""
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_shadow_line(line: str) -> Optional[ShadowEntry]:
    """
    Parse a single line from /etc/shadow into a ShadowEntry.

    Args:
        line: A raw line from /etc/shadow.

    Returns:
        A ShadowEntry if the line is valid, None otherwise.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split(":")
    if len(parts) < 2:
        logger.debug("Malformed shadow line (too few fields): skipping")
        return None

    username = parts[_FIELD_USERNAME].strip()
    hash_field = parts[_FIELD_HASH].strip() if len(parts) > _FIELD_HASH else ""

    if not username:
        return None

    # Determine if account is locked
    is_locked = False
    if not hash_field or hash_field in ("!", "*", "!!", "!!*"):
        is_locked = True
    elif hash_field.startswith(_LOCKED_PREFIXES):
        is_locked = True

    # Determine if password is empty (no hash set)
    is_empty_password = hash_field == "" or hash_field == "*"

    # Pad parts to ensure we have enough fields
    while len(parts) < 9:
        parts.append("")

    return ShadowEntry(
        username=username,
        hash_string=hash_field,
        last_changed=_parse_optional_int(parts[_FIELD_LAST_CHANGED]),
        min_days=_parse_optional_int(parts[_FIELD_MIN_DAYS]),
        max_days=_parse_optional_int(parts[_FIELD_MAX_DAYS]),
        warn_days=_parse_optional_int(parts[_FIELD_WARN_DAYS]),
        inactive_days=_parse_optional_int(parts[_FIELD_INACTIVE_DAYS]),
        expire_date=_parse_optional_int(parts[_FIELD_EXPIRE_DATE]),
        is_locked=is_locked,
        is_empty_password=is_empty_password,
        raw_line=stripped,
    )


def read_shadow() -> List[ShadowEntry]:
    """
    Read and parse /etc/shadow into a list of ShadowEntry objects.

    Skips locked accounts (hash starts with ! or *) and accounts with
    empty passwords. Handles permission errors gracefully.

    Returns:
        A list of parsed ShadowEntry objects for auditable accounts.

    Raises:
        PermissionError: If the process does not have read access.
        FileNotFoundError: If /etc/shadow does not exist.
        RuntimeError: If not running on Linux.
    """
    if not detect_linux():
        raise RuntimeError(
            "Cannot read /etc/shadow: not running on a Linux system."
        )

    shadow_path = Path(SHADOW_PATH)

    if not shadow_path.exists():
        raise FileNotFoundError(f"{SHADOW_PATH} does not exist.")

    raw_lines: list[str] = []

    if os.access(SHADOW_PATH, os.R_OK):
        try:
            with open(SHADOW_PATH, "r", encoding="utf-8", errors="replace") as fh:
                raw_lines = fh.readlines()
        except PermissionError:
            raise PermissionError(
                f"Permission denied reading {SHADOW_PATH}. Run with sudo or as root."
            )
        except OSError as exc:
            raise OSError(f"Error reading {SHADOW_PATH}: {exc}") from exc
    else:
        # Fallback: attempt to read via sudo -n or pkexec (without running entire GUI as root)
        import subprocess

        read_success = False
        for cmd in [
            ["sudo", "-n", "cat", SHADOW_PATH],
            ["pkexec", "cat", SHADOW_PATH],
        ]:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0 and proc.stdout:
                    raw_lines = proc.stdout.splitlines(keepends=True)
                    read_success = True
                    break
            except Exception:
                continue

        if not read_success:
            raise PermissionError(
                f"Cannot read {SHADOW_PATH}. Run with sudo, execute in CLI mode "
                f"('--audit-linux'), or use Mode B to import an exported shadow file."
            )

    entries: list[ShadowEntry] = []

    for line_num, line in enumerate(raw_lines, start=1):
        try:
            entry = _parse_shadow_line(line)
            if entry is None:
                continue

            # Skip locked and empty-password accounts
            if entry.is_locked:
                logger.debug(
                    "Skipping locked account: %s", entry.username
                )
                continue

            if entry.is_empty_password:
                logger.debug(
                    "Skipping empty-password account: %s", entry.username
                )
                continue

            entries.append(entry)

        except Exception as exc:
            logger.warning(
                "Error parsing shadow line %d: %s", line_num, exc
            )
            continue

    logger.info("Read %d auditable entries from %s", len(entries), SHADOW_PATH)
    return entries
