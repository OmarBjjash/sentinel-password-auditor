"""
Sentinel Password Auditor — Main Entry Point.

Supports both interactive GUI mode (CustomTkinter) and headless CLI execution:
- GUI mode: python main.py
- Linux audit CLI: sudo python main.py --audit-linux
- Windows audit CLI: python main.py --audit-windows <hash_file>
- Interactive checker CLI: python main.py --check <password>
"""

import argparse
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Any

from auditors.audit_result import AuditStatus
from core.audit_engine import AuditEngine
from core.config import APP_DESCRIPTION, APP_NAME, APP_VERSION
from core.dictionary_manager import DictionaryManager
from core.password_checker import evaluate_strength
from core.password_policy import PasswordPolicy
from reports.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel")


def _make_cli_progress():
    """Create a progress reporter function that dynamically updates current status inline."""
    last_was_status = False

    def cli_progress(current: int, total: int, msg: str) -> None:
        nonlocal last_was_status
        if "current status:" in msg:
            sys.stdout.write(f"\r[*] {msg:<80}")
            sys.stdout.flush()
            last_was_status = True
        else:
            if last_was_status:
                sys.stdout.write("\n")
                last_was_status = False
            if total > 0 and current > 0:
                print(f"[*] [{current}/{total}] {msg}")
            else:
                print(f"[*] {msg}")

    return cli_progress


def run_cli_linux_audit(args: argparse.Namespace) -> int:
    """Execute Linux system auditing in CLI mode."""
    print("=" * 65)
    print(f"  {APP_NAME} — Linux Account Auditor (Mode A: /etc/shadow)")
    print("=" * 65)

    if platform.system().lower() != "linux":
        print("[!] Warning: Linux audit requires a Linux environment to access /etc/shadow.")
        print(f"    Current operating system: {platform.system()}")

    wordlist = Path(args.wordlist) if args.wordlist else None
    engine = AuditEngine(wordlist_path=wordlist)
    cli_progress = _make_cli_progress()

    print("[*] Initiating /etc/shadow audit...")
    summary = engine.run_linux_audit(progress_callback=cli_progress)

    sys.stdout.write("\n")
    sys.stdout.flush()
    print("-" * 65)
    print(f"  Audit Results Summary ({summary.audit_type.upper()})")
    print("-" * 65)
    print(f"  Total Accounts Audited:  {summary.total_accounts}")
    print(f"  Weak Passwords Detected: {summary.weak_accounts}")
    print(f"  Strong Passwords:        {summary.strong_accounts}")
    print(f"  Locked/Disabled:         {summary.locked_accounts}")
    print(f"  Errors/Unsupported:      {summary.error_accounts + summary.unsupported_accounts}")
    print("-" * 65)

    print("\nAccount Findings:")
    for res in summary.results:
        status_tag = f"[{res.status}]"
        pwd_info = f" (password: {res.matched_word})" if res.matched_word else ""
        print(f"  {res.username:<20} {res.algorithm:<15} {status_tag:<18}{pwd_info}")
        print(f"    Recommendation: {res.recommendation}")

    _handle_exports(args, summary)
    return 0 if summary.weak_accounts == 0 else 1


def run_cli_linux_file_audit(args: argparse.Namespace) -> int:
    """Execute Linux shadow hash file auditing in CLI mode (Mode B)."""
    print("=" * 65)
    print(f"  {APP_NAME} — Linux Shadow File Auditor (Mode B)")
    print("=" * 65)

    shadow_path = args.audit_linux_file
    if not shadow_path:
        print("[!] Error: --audit-linux-file requires a valid shadow hash file path.")
        return 1

    wordlist = Path(args.wordlist) if args.wordlist else None
    engine = AuditEngine(wordlist_path=wordlist)
    cli_progress = _make_cli_progress()

    print(f"[*] Importing shadow hash file: {shadow_path}")
    summary = engine.run_linux_shadow_file_audit(shadow_path, progress_callback=cli_progress)

    sys.stdout.write("\n")
    sys.stdout.flush()
    print("-" * 65)
    print(f"  Audit Results Summary ({summary.audit_type.upper()})")
    print("-" * 65)
    print(f"  Total Accounts Audited:  {summary.total_accounts}")
    print(f"  Weak Passwords Detected: {summary.weak_accounts}")
    print(f"  Strong Passwords:        {summary.strong_accounts}")
    print(f"  Locked/Disabled:         {summary.locked_accounts}")
    print(f"  Errors/Unsupported:      {summary.error_accounts + summary.unsupported_accounts}")
    print("-" * 65)

    print("\nAccount Findings:")
    for res in summary.results:
        status_tag = f"[{res.status}]"
        pwd_info = f" (password: {res.matched_word})" if res.matched_word else ""
        print(f"  {res.username:<20} {res.algorithm:<15} {status_tag:<18}{pwd_info}")
        print(f"    Recommendation: {res.recommendation}")

    _handle_exports(args, summary)
    return 0 if summary.weak_accounts == 0 else 1


def run_cli_windows_sam_audit(args: argparse.Namespace) -> int:
    """Execute live local Windows SAM auditing in CLI mode (requires Administrator rights)."""
    print("=" * 65)
    print(f"  {APP_NAME} — Windows Local SAM Auditor (Mode A)")
    print("=" * 65)

    if platform.system().lower() != "windows":
        print("[!] Error: Local SAM audit requires a Windows operating system.")
        return 1

    wordlist = Path(args.wordlist) if args.wordlist else None
    engine = AuditEngine(wordlist_path=wordlist)
    cli_progress = _make_cli_progress()

    print("[*] Initiating live local SAM acquisition...")
    summary = engine.run_windows_local_sam_audit(progress_callback=cli_progress)

    sys.stdout.write("\n")
    sys.stdout.flush()
    print("-" * 65)
    print(f"  Audit Results Summary ({summary.audit_type.upper()})")
    print("-" * 65)
    print(f"  Total Accounts Audited:  {summary.total_accounts}")
    print(f"  Weak Passwords Detected: {summary.weak_accounts}")
    print(f"  Strong Passwords:        {summary.strong_accounts}")
    print(f"  Errors/Unsupported:      {summary.error_accounts}")
    if summary.error_message:
        print(f"  Status / Notice:         {summary.error_message}")
    print("-" * 65)

    if summary.results:
        print("\nAccount Findings:")
        for res in summary.results:
            status_tag = f"[{res.status}]"
            pwd_info = f" (password: {res.matched_word})" if res.matched_word else ""
            print(f"  {res.username:<20} {res.algorithm:<15} {status_tag:<18}{pwd_info}")
            print(f"    Recommendation: {res.recommendation}")

    _handle_exports(args, summary)
    return 0 if summary.weak_accounts == 0 else 1


def run_cli_windows_audit(args: argparse.Namespace) -> int:
    """Execute Windows NTLM hash file auditing in CLI mode."""
    print("=" * 65)
    print(f"  {APP_NAME} — Windows NTLM Hash Auditor")
    print("=" * 65)

    hash_path = args.audit_windows
    if not hash_path:
        print("[!] Error: --audit-windows requires a valid hash file path.")
        return 1

    wordlist = Path(args.wordlist) if args.wordlist else None
    engine = AuditEngine(wordlist_path=wordlist)
    cli_progress = _make_cli_progress()

    print(f"[*] Importing authorized NTLM hash file: {hash_path}")
    summary = engine.run_windows_audit(hash_path, progress_callback=cli_progress)

    sys.stdout.write("\n")
    sys.stdout.flush()
    print("-" * 65)
    print(f"  Audit Results Summary ({summary.audit_type.upper()})")
    print("-" * 65)
    print(f"  Total Accounts Audited:  {summary.total_accounts}")
    print(f"  Weak Passwords Detected: {summary.weak_accounts}")
    print(f"  Strong Passwords:        {summary.strong_accounts}")
    print(f"  Errors/Unsupported:      {summary.error_accounts}")
    print("-" * 65)

    print("\nAccount Findings:")
    for res in summary.results:
        status_tag = f"[{res.status}]"
        pwd_info = f" (password: {res.matched_word})" if res.matched_word else ""
        print(f"  {res.username:<20} {res.algorithm:<15} {status_tag:<18}{pwd_info}")
        print(f"    Recommendation: {res.recommendation}")

    _handle_exports(args, summary)
    return 0 if summary.weak_accounts == 0 else 1


def run_cli_check_password(password: str) -> int:
    """Check a single password in CLI mode without storing/logging it."""
    print("=" * 60)
    print(f"  {APP_NAME} — Password Evaluation")
    print("=" * 60)

    dm = DictionaryManager()
    dm.load()

    strength = evaluate_strength(password, dm)
    policy = PasswordPolicy().evaluate(password)

    in_dict = dm.contains(password)

    print(f"Password Length:         {len(password)} characters")
    print(f"Dictionary Exposure:     {'FOUND IN DICTIONARY (UNSAFE)' if in_dict else 'NOT FOUND (SAFE)'}")
    print(f"Strength Score:          {strength.score} / 100")
    print(f"Classification:          {strength.level.value}")
    print(f"Policy Compliance:       {policy.passed_count}/{policy.total_rules} rules passed ({policy.compliance_percentage:.0f}%)")

    if strength.feedback:
        print("\nObservations:")
        for fb in strength.feedback:
            print(f"  • {fb}")

    print("=" * 60)
    return 0


def _handle_exports(args: argparse.Namespace, summary: Any) -> None:
    """Handle PDF or JSON export requested via CLI flags."""
    rep_gen = ReportGenerator()
    if args.export_pdf:
        out = rep_gen.generate_pdf(summary, filename=args.export_pdf)
        print(f"\n[+] PDF audit report generated at: {out}")
    if args.export_json:
        out = rep_gen.generate_json(summary, filename=args.export_json)
        print(f"\n[+] JSON audit report generated at: {out}")


def main() -> int:
    """Application CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{APP_NAME} v{APP_VERSION} — {APP_DESCRIPTION}",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        default=False,
        help="Launch the graphical interface (default when no audit options provided)",
    )
    parser.add_argument(
        "--audit-linux",
        action="store_true",
        help="Run Linux /etc/shadow audit in CLI mode (requires root privileges)",
    )
    parser.add_argument(
        "--audit-linux-file",
        metavar="SHADOW_FILE",
        help="Run Linux audit using an imported shadow hash file (Mode B, no root needed)",
    )
    parser.add_argument(
        "--audit-windows-sam",
        action="store_true",
        help="Run live local Windows SAM audit in CLI mode (requires Administrator rights)",
    )
    parser.add_argument(
        "--audit-windows",
        metavar="HASH_FILE",
        help="Run Windows NTLM audit using an authorized hash file (username:hash)",
    )
    parser.add_argument(
        "--check",
        metavar="PASSWORD",
        help="Evaluate proposed password strength and dictionary exposure in CLI",
    )
    parser.add_argument(
        "--wordlist",
        metavar="PATH",
        help="Path to custom wordlist dictionary file",
    )
    parser.add_argument(
        "--export-pdf",
        metavar="PATH",
        help="Export audit report to PDF file",
    )
    parser.add_argument(
        "--export-json",
        metavar="PATH",
        help="Export audit report to JSON file",
    )

    args = parser.parse_args()

    # Route based on CLI arguments
    if args.audit_linux:
        return run_cli_linux_audit(args)
    elif args.audit_linux_file:
        return run_cli_linux_file_audit(args)
    elif args.audit_windows_sam:
        return run_cli_windows_sam_audit(args)
    elif args.audit_windows:
        return run_cli_windows_audit(args)
    elif args.check:
        return run_cli_check_password(args.check)
    else:
        # Default: Launch CustomTkinter GUI
        # Handle Linux environment when launched under sudo
        if platform.system().lower() == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                # Fix missing XAUTHORITY when invoked via sudo
                if "XAUTHORITY" not in os.environ:
                    user_xauth = Path(f"/home/{sudo_user}/.Xauthority")
                    if user_xauth.exists():
                        os.environ["XAUTHORITY"] = str(user_xauth)
                # Ensure Wayland / X11 compatibility
                if "GDK_BACKEND" not in os.environ:
                    os.environ["GDK_BACKEND"] = "x11"

            display = os.environ.get("DISPLAY")
            wayland = os.environ.get("WAYLAND_DISPLAY")
            if not display and not wayland:
                print("[!] Error: Cannot launch graphical interface as root without an active display.")
                print("    Recommendation:")
                print("    - Launch GUI as normal user (WITHOUT sudo):")
                print("        python3 main.py")
                print("    - Or run in CLI mode:")
                print("        sudo python3 main.py --audit-linux")
                print("        python3 main.py --audit-linux-file sample_linux_hashes.txt")
                return 1

        try:
            from gui.app import SentinelApp

            app = SentinelApp()
            app.mainloop()
            return 0
        except Exception as exc:
            logger.error("GUI failed to start: %s", exc)
            print(f"[!] GUI error: {exc}")
            print("    You can run in CLI mode using --help.")
            return 1


if __name__ == "__main__":
    sys.exit(main())
