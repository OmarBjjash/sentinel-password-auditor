"""
Application configuration constants for Sentinel Password Auditor.

Provides centralized configuration for the application including GUI theming,
password strength thresholds, file paths, and application metadata.
"""

import sys
import tempfile
from pathlib import Path
from typing import Final

# ── Application Metadata ─────────────────────────────────────────────────────
APP_NAME: Final[str] = "Sentinel Password Auditor"
APP_VERSION: Final[str] = "1.0.0"
APP_AUTHOR: Final[str] = "Sentinel Security"
APP_DESCRIPTION: Final[str] = (
    "A comprehensive password auditing tool for evaluating password strength "
    "and identifying weak credentials across Linux and Windows systems."
)

# ── File Paths ────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    BASE_DIR: Final[Path] = Path(sys._MEIPASS)
else:
    BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent

DEFAULT_WORDLIST: Final[str] = "wordlist.txt"
WORDLIST_PATH: Final[Path] = BASE_DIR / DEFAULT_WORDLIST


def get_report_output_dir() -> Path:
    """
    Determine a safe, writable directory for generated audit reports.

    Priority:
    1. If running from source in development (not frozen) and project root/reports is writable:
       Use <project_root>/reports
    2. Try current working directory: ./reports
    3. Try user's Documents or Home directory: ~/Documents/SentinelReports or ~/SentinelReports
    4. Safe fallback: temporary directory: <tempdir>/sentinel_reports
    """
    # 1. Source / dev environment
    if not getattr(sys, "frozen", False):
        try:
            dev_reports = Path(__file__).resolve().parent.parent / "reports"
            dev_reports.mkdir(parents=True, exist_ok=True)
            return dev_reports
        except (OSError, PermissionError):
            pass

    # 2. Packaged execution (AppImage or .exe) or read-only dev directory
    # Primary destination: current working directory / reports
    try:
        cwd_reports = Path.cwd() / "reports"
        cwd_reports.mkdir(parents=True, exist_ok=True)
        return cwd_reports
    except (OSError, PermissionError):
        pass

    # 3. User document / home directory
    for home_candidate in [
        Path.home() / "Documents" / "SentinelReports",
        Path.home() / "SentinelReports",
    ]:
        try:
            home_candidate.mkdir(parents=True, exist_ok=True)
            return home_candidate
        except (OSError, PermissionError):
            pass

    # 4. Safe fallback: temporary directory
    temp_reports = Path(tempfile.gettempdir()) / "sentinel_reports"
    temp_reports.mkdir(parents=True, exist_ok=True)
    return temp_reports


REPORT_OUTPUT_DIR: Final[Path] = get_report_output_dir()

# ── GUI Color Scheme (Modern Dual-Theme Palette) ──────────────────────────────
# Two-tuple format for CustomTkinter: (Light Mode, Dark Mode)
BG_MAIN: Final[tuple[str, str]] = ("#F8FAFC", "#0B1120")
BG_DARK: Final[tuple[str, str]] = BG_MAIN  # Compatibility alias
BG_SIDEBAR: Final[tuple[str, str]] = ("#F1F5F9", "#080D1A")
BG_CARD: Final[tuple[str, str]] = ("#FFFFFF", "#131C31")
BG_INPUT: Final[tuple[str, str]] = ("#F8FAFC", "#0D1527")
BG_HOVER: Final[tuple[str, str]] = ("#E2E8F0", "#1E2B48")
BORDER_COLOR: Final[tuple[str, str]] = ("#E2E8F0", "#1E2B48")

PRIMARY: Final[tuple[str, str]] = ("#1D4ED8", "#3B82F6")
PRIMARY_HOVER: Final[tuple[str, str]] = ("#1E40AF", "#2563EB")
SUCCESS: Final[tuple[str, str]] = ("#15803D", "#22C55E")
DANGER: Final[tuple[str, str]] = ("#B91C1C", "#EF4444")
WARNING: Final[tuple[str, str]] = ("#B45309", "#F59E0B")
TEXT_PRIMARY: Final[tuple[str, str]] = ("#0F172A", "#F8FAFC")
TEXT_SECONDARY: Final[tuple[str, str]] = ("#475569", "#94A3B8")
TEXT_MUTED: Final[tuple[str, str]] = ("#64748B", "#64748B")

# Secondary action / outline buttons styling (high-contrast in both light & dark)
BTN_SECONDARY_FG: Final[tuple[str, str]] = ("#E2E8F0", "#1E2B48")
BTN_SECONDARY_HOVER: Final[tuple[str, str]] = ("#CBD5E1", "#2D3F66")
BTN_SECONDARY_BORDER: Final[tuple[str, str]] = ("#94A3B8", "#3B4D73")


def get_treeview_colors(is_dark: bool) -> dict[str, str]:
    """Return single-color hex mapping for Tkinter ttk widgets."""
    if is_dark:
        return {
            "bg": "#131C31",
            "fg": "#F8FAFC",
            "heading_bg": "#0B1120",
            "heading_fg": "#94A3B8",
            "selected_bg": "#1E2B48",
            "weak": "#EF4444",
            "strong": "#22C55E",
            "locked": "#F59E0B",
            "error": "#94A3B8",
        }
    return {
        "bg": "#FFFFFF",
        "fg": "#0F172A",
        "heading_bg": "#F1F5F9",
        "heading_fg": "#475569",
        "selected_bg": "#E2E8F0",
        "weak": "#B91C1C",
        "strong": "#15803D",
        "locked": "#B45309",
        "error": "#64748B",
    }

# ── Password Strength Thresholds ──────────────────────────────────────────────
# Score ranges that map to strength levels (inclusive bounds)
STRENGTH_VERY_WEAK_MAX: Final[int] = 20
STRENGTH_WEAK_MAX: Final[int] = 40
STRENGTH_MODERATE_MAX: Final[int] = 60
STRENGTH_STRONG_MAX: Final[int] = 80
# Scores above STRONG_MAX are VERY_STRONG

# Minimum acceptable score for a password to be considered non-weak
MIN_ACCEPTABLE_SCORE: Final[int] = 41

# ── Password Requirement Defaults ─────────────────────────────────────────────
DEFAULT_MIN_LENGTH: Final[int] = 8
DEFAULT_MAX_LENGTH: Final[int] = 128
DEFAULT_MAX_REPEATED_CHARS: Final[int] = 3
DEFAULT_REQUIRE_UPPERCASE: Final[bool] = True
DEFAULT_REQUIRE_LOWERCASE: Final[bool] = True
DEFAULT_REQUIRE_DIGITS: Final[bool] = True
DEFAULT_REQUIRE_SPECIAL: Final[bool] = True
DEFAULT_CHECK_SEQUENTIAL: Final[bool] = True
DEFAULT_CHECK_DICTIONARY: Final[bool] = True

# ── Audit Settings ────────────────────────────────────────────────────────────
# Maximum number of words to load from a wordlist
MAX_WORDLIST_SIZE: Final[int] = 10_000_000
# Chunk size for progress reporting during audits
AUDIT_PROGRESS_CHUNK: Final[int] = 1000
