"""
Tests for Windows NTLM and LM hash importer and auditor.

Covers:
  1. <LM Hash> (standalone LM)
  2. <LM Hash>:<NT Hash>
  3. <UserName>:<UserID>:<LM Hash>:<NT Hash>::: (pwdump / secretsdump)
  4. <UserName>:<NT Hash>
  5. Real account audit matching (e.g. sample_hashes.txt with shadow:anonymous)
"""

from pathlib import Path
import pytest

from auditors.audit_result import AuditStatus
from auditors.windows_auditor import WindowsAuditor
from collectors.windows_hash_importer import (
    parse_hash_file,
    validate_ntlm_hash,
)
from core.dictionary_manager import DictionaryManager
from core.password_hasher import compute_lm_hash, compute_ntlm_hash


class TestWindowsImporter:
    """Tests for collectors.windows_hash_importer module."""

    def test_validate_valid_ntlm_hash(self) -> None:
        assert validate_ntlm_hash("8846F7EAEE8FB117AD06BDD830B7586C") is True
        assert validate_ntlm_hash("8846f7eaee8fb117ad06bdd830b7586c") is True
        assert validate_ntlm_hash("0123456789abcdef0123456789abcdef") is True

    def test_validate_invalid_ntlm_hash(self) -> None:
        assert validate_ntlm_hash("too_short") is False
        assert validate_ntlm_hash("8846F7EAEE8FB117AD06BDD830B7586CEXTRA") is False
        assert validate_ntlm_hash("8846F7EAEE8FB117AD06BDD830B7586Z") is False  # 'Z' is non-hex
        assert validate_ntlm_hash("") is False

    def test_parse_valid_hash_file(self, temp_hash_file: Path) -> None:
        result = parse_hash_file(str(temp_hash_file))
        assert result.success_count == 3
        assert result.error_count == 0
        usernames = [h.username for h in result.hashes]
        assert "alice" in usernames
        assert "bob" in usernames
        assert "charlie" in usernames

    def test_parse_pwdump_format(self, tmp_path: Path) -> None:
        """Test parsing pwdump / secretsdump format: user:uid:LM:NT:::"""
        f = tmp_path / "pwdump.txt"
        content = (
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "shadow:1001:aad3b435b51404eeaad3b435b51404ee:4481b934fc9cad79cb0f5295fa8cfc98:::\n"
        )
        f.write_text(content, encoding="utf-8")

        result = parse_hash_file(str(f))
        assert result.success_count == 2
        assert result.error_count == 0
        assert result.hashes[0].username == "Administrator"
        assert result.hashes[0].ntlm_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
        assert result.hashes[0].source_format == "pwdump"
        assert result.hashes[1].username == "shadow"
        assert result.hashes[1].ntlm_hash == "4481b934fc9cad79cb0f5295fa8cfc98"

    def test_parse_lm_nt_pair_format(self, tmp_path: Path) -> None:
        """Test parsing <LM Hash>:<NT Hash> format."""
        f = tmp_path / "lm_nt.txt"
        content = (
            "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c\n"
            "e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c\n"
        )
        f.write_text(content, encoding="utf-8")

        result = parse_hash_file(str(f))
        assert result.success_count == 2
        assert result.error_count == 0
        assert result.hashes[0].source_format == "lm_nt"
        assert result.hashes[0].ntlm_hash == "8846f7eaee8fb117ad06bdd830b7586c"
        assert result.hashes[0].lm_hash == "aad3b435b51404eeaad3b435b51404ee"
        # Usernames are auto-generated
        assert result.hashes[0].username == "Unknown_1"
        assert result.hashes[1].username == "Unknown_2"

    def test_parse_standalone_lm_hash(self, tmp_path: Path) -> None:
        """Test parsing standalone <LM Hash> format."""
        f = tmp_path / "standalone_lm.txt"
        # LM hash of "password"
        content = "e52cac67419a9a224a3b108f3fa6cb6d\n"
        f.write_text(content, encoding="utf-8")

        result = parse_hash_file(str(f))
        assert result.success_count == 1
        assert result.error_count == 0
        assert result.hashes[0].ntlm_hash == "e52cac67419a9a224a3b108f3fa6cb6d"
        assert result.hashes[0].source_format == "standalone"

    def test_parse_malformed_hash_file(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad_hashes.txt"
        content = (
            "validuser:8846F7EAEE8FB117AD06BDD830B7586C\n"
            "no_colon_and_not_hex\n"
            "badhash:NOT_A_VALID_HEX_HASH_12345\n"
        )
        bad_file.write_text(content, encoding="utf-8")

        result = parse_hash_file(str(bad_file))
        assert result.success_count == 1
        assert result.error_count == 2
        assert result.has_errors is True

    def test_parse_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_hash_file("non_existent_file_xyz_123.txt")


class TestWindowsAuditor:
    """Tests for auditors.windows_auditor module."""

    def test_common_password_detection(self, temp_hash_file: Path) -> None:
        dm = DictionaryManager()
        dm.load()

        auditor = WindowsAuditor(dm)
        results = auditor.audit(str(temp_hash_file))

        # alice has NTLM of 'password', which is in wordlist.txt
        alice_res = next((r for r in results if r.username == "alice"), None)
        assert alice_res is not None
        assert alice_res.status == AuditStatus.WEAK_PASSWORD.value
        assert alice_res.is_weak is True

    def test_unmatched_account_is_strong(self, temp_hash_file: Path) -> None:
        dm = DictionaryManager()
        dm.load()

        auditor = WindowsAuditor(dm)
        results = auditor.audit(str(temp_hash_file))

        # charlie has unique hash not in wordlist.txt
        charlie_res = next((r for r in results if r.username == "charlie"), None)
        assert charlie_res is not None
        assert charlie_res.status == AuditStatus.STRONG_PASSWORD.value
        assert charlie_res.is_weak is False

    def test_audit_pwdump_sample_hashes(self, tmp_path: Path) -> None:
        """
        Audit pwdump format record containing:
        shadow:1001:aad3b435b51404eeaad3b435b51404ee:4481b934fc9cad79cb0f5295fa8cfc98:::
        Verify user 'shadow' with password 'anonymous' is correctly detected!
        """
        test_file = tmp_path / "test_pwdump.txt"
        content = (
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "shadow:1001:aad3b435b51404eeaad3b435b51404ee:4481b934fc9cad79cb0f5295fa8cfc98:::\n"
        )
        test_file.write_text(content, encoding="utf-8")

        dict_file = tmp_path / "test_wordlist.txt"
        dict_file.write_text("password\nanonymous\n123456\n", encoding="utf-8")

        dm = DictionaryManager()
        dm.load_wordlist(dict_file)

        auditor = WindowsAuditor(dm)
        results = auditor.audit(str(test_file))

        # Check shadow account
        shadow_res = next((r for r in results if r.username.lower() == "shadow"), None)
        assert shadow_res is not None, "User 'shadow' was not parsed from pwdump format"
        assert shadow_res.status == AuditStatus.WEAK_PASSWORD.value
        assert shadow_res.matched_word == "anonymous"

        # Check Administrator (blank password)
        admin_res = next((r for r in results if r.username.lower() == "administrator"), None)
        assert admin_res is not None
        assert admin_res.status == AuditStatus.WEAK_PASSWORD.value

    def test_audit_changed_password_strong(self, tmp_path: Path) -> None:
        """
        Verify that when a user changes their password to one not in wordlist,
        the audit accurately identifies it as STRONG_PASSWORD.
        """
        test_file = tmp_path / "changed_pwdump.txt"
        # 8c0813fc1773466efdfaff25d3fb55cb is not in wordlist.txt
        content = "shadow:1001:aad3b435b51404eeaad3b435b51404ee:8c0813fc1773466efdfaff25d3fb55cb:::\n"
        test_file.write_text(content, encoding="utf-8")

        dm = DictionaryManager()
        dm.load()

        auditor = WindowsAuditor(dm)
        results = auditor.audit(str(test_file))

        shadow_res = next((r for r in results if r.username.lower() == "shadow"), None)
        assert shadow_res is not None
        assert shadow_res.status == AuditStatus.STRONG_PASSWORD.value
        assert shadow_res.is_weak is False

    def test_audit_standalone_lm_hash(self, tmp_path: Path) -> None:
        """Verify auditing a standalone <LM Hash> detects the password."""
        dm = DictionaryManager()
        dm.load()

        lm_file = tmp_path / "standalone.txt"
        # LM hash of "password"
        lm_file.write_text(compute_lm_hash("password") + "\n", encoding="utf-8")

        auditor = WindowsAuditor(dm)
        results = auditor.audit(str(lm_file))

        assert len(results) == 1
        assert results[0].status == AuditStatus.WEAK_PASSWORD.value
        assert results[0].algorithm == "LM"

    def test_missing_hash_file_returns_error_result(self) -> None:
        dm = DictionaryManager()
        dm.load()

        auditor = WindowsAuditor(dm)
        results = auditor.audit("missing_file_path_123.txt")

        assert len(results) == 1
        assert results[0].status == AuditStatus.ERROR.value

    def test_system_audit_view_password_column_and_switch(self) -> None:
        """Verify the results table displays discovered passwords and toggles with the switch."""
        from gui.app import SentinelApp
        from auditors.audit_result import AuditResult, AuditSummary

        app = SentinelApp()
        try:
            app.update()
            view = app.system_audit_view

            # Verify columns include 'password'
            assert "password" in view.windows_tree["columns"]

            # Prepare weak and strong findings
            res_weak = AuditResult.weak("target_user", "NTLM", "windows", matched_word="WeakPass123")
            res_strong = AuditResult.strong("admin_user", "NTLM", "windows")
            summary = AuditSummary.from_results([res_weak, res_strong], audit_type="windows")

            # Deliver audit results with show_passwords enabled (default True)
            view.var_show_passwords.set(True)
            view._on_audit_done(summary, "windows")
            app.update()

            items = view.windows_tree.get_children()
            assert len(items) == 2
            weak_row = view.windows_tree.item(items[0])["values"]
            assert weak_row[0] == "target_user"
            assert weak_row[2] == "WEAK_PASSWORD"
            assert weak_row[3] == "WeakPass123"

            # Toggle switch to OFF (Masked)
            view.var_show_passwords.set(False)
            view._on_toggle_show_passwords()
            app.update()

            items_masked = view.windows_tree.get_children()
            masked_row = view.windows_tree.item(items_masked[0])["values"]
            assert "Masked" in str(masked_row[3])

            # Toggle switch back to ON (Revealed)
            view.var_show_passwords.set(True)
            view._on_toggle_show_passwords()
            app.update()

            items_unmasked = view.windows_tree.get_children()
            unmasked_row = view.windows_tree.item(items_unmasked[0])["values"]
            assert unmasked_row[3] == "WeakPass123"
        finally:
            app.destroy()
