"""
Windows environment detection and local account enumeration.

Provides utilities to detect Windows systems, retrieve OS information,
and enumerate local user accounts using ctypes (net user equivalent).
Handles non-Windows platforms gracefully.
"""

import ctypes
import logging
import platform
import struct
import subprocess
import sys
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def detect_windows() -> bool:
    """
    Detect if the current system is running Windows.

    Returns:
        True if the platform is Windows.
    """
    return platform.system().lower() == "windows"


def get_windows_info() -> Dict[str, str]:
    """
    Get Windows system information.

    Returns:
        Dictionary with OS details including version, hostname, architecture,
        and edition. Returns minimal info on non-Windows systems.
    """
    info: dict[str, str] = {
        "platform": platform.system(),
        "hostname": platform.node(),
        "architecture": platform.machine(),
    }

    if not detect_windows():
        info["note"] = "Not running on Windows"
        return info

    try:
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
        info["platform_detail"] = platform.platform()

        # Get Windows edition via ver command
        try:
            result = subprocess.run(
                ["cmd", "/c", "ver"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0,
            )
            if result.returncode == 0:
                ver_output = result.stdout.strip()
                if ver_output:
                    info["windows_ver"] = ver_output
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Check if running with elevated privileges
        try:
            info["is_admin"] = str(bool(ctypes.windll.shell32.IsUserAnAdmin()))
        except (AttributeError, OSError):
            info["is_admin"] = "unknown"

    except Exception as exc:
        logger.warning("Error gathering Windows info: %s", exc)

    return info


def enumerate_local_accounts() -> List[str]:
    """
    Enumerate local user accounts on a Windows system.

    Uses the NetUserEnum Win32 API via ctypes to list all local user accounts,
    equivalent to the 'net user' command.

    Returns:
        List of local usernames. Returns an empty list on non-Windows systems
        or if enumeration fails.
    """
    if not detect_windows():
        logger.info("Not running on Windows; account enumeration skipped")
        return []

    # Try ctypes approach first (more reliable)
    users = _enumerate_via_ctypes()
    if users is not None:
        return users

    # Fallback to net user command
    logger.info("Falling back to 'net user' command for enumeration")
    return _enumerate_via_net_user()


def _enumerate_via_ctypes() -> Optional[List[str]]:
    """
    Enumerate local accounts using the Win32 NetUserEnum API via ctypes.

    Returns:
        List of usernames, or None if the API call fails.
    """
    try:
        netapi32 = ctypes.windll.Netapi32

        # Constants for NetUserEnum
        FILTER_NORMAL_ACCOUNT = 0x0002
        MAX_PREFERRED_LENGTH = 0xFFFFFFFF
        NERR_Success = 0
        ERROR_MORE_DATA = 234
        LEVEL = 0  # USER_INFO_0 — just usernames

        # Output parameters
        buf = ctypes.c_void_p()
        entries_read = ctypes.c_ulong(0)
        total_entries = ctypes.c_ulong(0)
        resume_handle = ctypes.c_ulong(0)

        users: list[str] = []

        while True:
            result = netapi32.NetUserEnum(
                None,  # servername (None = local)
                LEVEL,  # level
                FILTER_NORMAL_ACCOUNT,  # filter
                ctypes.byref(buf),  # bufptr
                MAX_PREFERRED_LENGTH,  # prefmaxlen
                ctypes.byref(entries_read),  # entriesread
                ctypes.byref(total_entries),  # totalentries
                ctypes.byref(resume_handle),  # resume_handle
            )

            if result not in (NERR_Success, ERROR_MORE_DATA):
                logger.warning("NetUserEnum failed with error code: %d", result)
                if buf.value:
                    netapi32.NetApiBufferFree(buf)
                return None

            if buf.value is None:
                break

            # USER_INFO_0 structure contains a single LPWSTR pointer
            pointer_size = ctypes.sizeof(ctypes.c_void_p)
            for i in range(entries_read.value):
                # Read pointer to username string
                ptr_addr = buf.value + (i * pointer_size)
                name_ptr = ctypes.c_void_p.from_address(ptr_addr).value
                if name_ptr:
                    username = ctypes.wstring_at(name_ptr)
                    users.append(username)

            netapi32.NetApiBufferFree(buf)
            buf = ctypes.c_void_p()

            if result == NERR_Success:
                break

        logger.info("Enumerated %d local accounts via NetUserEnum", len(users))
        return users

    except Exception as exc:
        logger.warning("ctypes NetUserEnum failed: %s", exc)
        return None


def _enumerate_via_net_user() -> List[str]:
    """
    Enumerate local accounts by parsing the output of 'net user'.

    Returns:
        List of usernames parsed from net user output.
    """
    try:
        creation_flags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )
        result = subprocess.run(
            ["net", "user"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creation_flags,
        )

        if result.returncode != 0:
            logger.warning("'net user' command failed: %s", result.stderr.strip())
            return []

        users: list[str] = []
        lines = result.stdout.strip().split("\n")

        # Skip header lines (before the dashes line) and footer
        in_users_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("---"):
                in_users_section = True
                continue
            if not in_users_section:
                continue
            if stripped.startswith("The command completed"):
                break
            if not stripped:
                continue

            # net user output has usernames in columns
            parts = stripped.split()
            users.extend(parts)

        logger.info("Enumerated %d local accounts via 'net user'", len(users))
        return users

    except subprocess.TimeoutExpired:
        logger.warning("'net user' command timed out")
        return []
    except FileNotFoundError:
        logger.warning("'net' command not found")
        return []
    except OSError as exc:
        logger.warning("Error running 'net user': %s", exc)
        return []
