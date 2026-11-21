"""
Tests for Linux shadow collector and Linux auditor.
"""

import platform
import pytest

from auditors.audit_result import AuditStatus
from auditors.linux_auditor import LinuxAuditor
from collectors.linux_shadow_collector import (
    ShadowEntry,
    _parse_shadow_line,
    check_shadow_access,
    detect_linux,
)
from core.dictionary_manager import DictionaryManager


class TestLinuxCollector:
    """Tests for collectors.linux_shadow_collector module."""

    def test_parse_valid_shadow_entry(self) -> None:
        # Standard SHA-512 shadow line
        line = "testuser:$6$rounds=5000$saltsalt$hashedpassword:19000:0:99999:7:::"
        entry = _parse_shadow_line(line)
        assert entry is not None
        assert entry.username == "testuser"
        assert entry.hash_string.startswith("$6$")
        assert entry.is_locked is False
        assert entry.is_empty_password is False
        assert entry.last_changed == 19000

    def test_skip_locked_account_exclamation(self) -> None:
        line = "lockeduser:!$6$rounds=5000$salt$hash:19000:0:99999:7:::"
        entry = _parse_shadow_line(line)
        assert entry is not None
        assert entry.is_locked is True

    def test_skip_locked_account_asterisk(self) -> None:
        line = "sysuser:*:19000:0:99999:7:::"
        entry = _parse_shadow_line(line)
        assert entry is not None
        assert entry.is_locked is True

    def test_empty_password_entry(self) -> None:
        line = "nopass::19000:0:99999:7:::"
        entry = _parse_shadow_line(line)
        assert entry is not None
        assert entry.is_empty_password is True

    def test_malformed_entry(self) -> None:
        line = "malformed_entry_without_colons"
        entry = _parse_shadow_line(line)
        assert entry is None

    def test_detect_linux(self) -> None:
        is_linux = detect_linux()
        assert is_linux == (platform.system().lower() == "linux")

    @pytest.mark.integration
    def test_real_shadow_access_on_linux(self) -> None:
        """Integration test: Requires running as root on Linux."""
        if not detect_linux():
            pytest.skip("Not running on Linux")
        access = check_shadow_access()
        # Should be True if running with sudo/root, False otherwise
        assert isinstance(access, bool)


class TestLinuxAuditor:
    """Tests for auditors.linux_auditor module."""

    def setup_method(self) -> None:
        """Reset singleton before each test to allow custom wordlist paths."""
        DictionaryManager.reset()

    def teardown_method(self) -> None:
        """Reset singleton after each test to avoid polluting other test modules."""
        DictionaryManager.reset()

    def test_linux_auditor_handles_unsupported_hash(self) -> None:
        dm = DictionaryManager()
        dm.load()
        auditor = LinuxAuditor(dm)

        # Create a mock ShadowEntry with unknown algorithm
        entry = ShadowEntry(
            username="alien_user",
            hash_string="non_standard_hash_format_xyz",
            last_changed=19000,
            min_days=0,
            max_days=99999,
            warn_days=7,
            inactive_days=None,
            expire_date=None,
            is_locked=False,
            is_empty_password=False,
            raw_line="alien_user:non_standard_hash_format_xyz:...",
        )
        res = auditor._audit_entry(
            entry=entry,
            wordlist=["password"],
            entry_idx=0,
            total_entries=1,
            total_words=1,
            progress_callback=None,
            cancel_check=None,
        )
        assert res.username == "alien_user"
        assert res.status == AuditStatus.ERROR.value

    def test_audit_yescrypt_weak_password(self, tmp_path) -> None:
        """Test that the Linux auditor detects a weak yescrypt-hashed password."""
        try:
            from pyescrypt import Yescrypt, Mode
            import secrets
        except ImportError:
            pytest.skip("pyescrypt not installed")

        # Generate a yescrypt hash for 'password'
        hasher = Yescrypt(n=2**16, r=8, p=1, mode=Mode.MCF)
        salt = secrets.token_bytes(16)
        yescrypt_hash = hasher.digest(
            password=b"password", salt=salt
        ).decode("utf-8")

        # Create a wordlist containing 'password'
        wl = tmp_path / "wordlist.txt"
        wl.write_text("password\nsecret\nadmin\n", encoding="utf-8")

        DictionaryManager.reset()
        dm = DictionaryManager(wordlist_path=wl)
        dm.load()
        auditor = LinuxAuditor(dm)

        entry = ShadowEntry(
            username="testuser",
            hash_string=yescrypt_hash,
            last_changed=19000,
            min_days=0,
            max_days=99999,
            warn_days=7,
            inactive_days=None,
            expire_date=None,
            is_locked=False,
            is_empty_password=False,
            raw_line=f"testuser:{yescrypt_hash}:19000:0:99999:7:::",
        )

        res = auditor._audit_entry(
            entry=entry,
            wordlist=list(dm.get_words()),
            entry_idx=0,
            total_entries=1,
            total_words=3,
            progress_callback=None,
            cancel_check=None,
        )

        assert res.username == "testuser"
        assert res.status == AuditStatus.WEAK_PASSWORD.value
        assert res.is_weak is True
        assert res.matched_word == "password"
        assert res.algorithm == "yescrypt"

    def test_audit_yescrypt_strong_password(self, tmp_path) -> None:
        """Test that the Linux auditor correctly reports strong yescrypt passwords."""
        try:
            from pyescrypt import Yescrypt, Mode
            import secrets
        except ImportError:
            pytest.skip("pyescrypt not installed")

        # Generate a yescrypt hash for a password NOT in the wordlist
        hasher = Yescrypt(n=2**16, r=8, p=1, mode=Mode.MCF)
        salt = secrets.token_bytes(16)
        yescrypt_hash = hasher.digest(
            password=b"MyStr0ng!P@ssW0rd#2026", salt=salt
        ).decode("utf-8")

        wl = tmp_path / "wordlist.txt"
        wl.write_text("password\nsecret\nadmin\n", encoding="utf-8")

        DictionaryManager.reset()
        dm = DictionaryManager(wordlist_path=wl)
        dm.load()
        auditor = LinuxAuditor(dm)

        entry = ShadowEntry(
            username="secureuser",
            hash_string=yescrypt_hash,
            last_changed=19000,
            min_days=0,
            max_days=99999,
            warn_days=7,
            inactive_days=None,
            expire_date=None,
            is_locked=False,
            is_empty_password=False,
            raw_line=f"secureuser:{yescrypt_hash}:19000:0:99999:7:::",
        )

        res = auditor._audit_entry(
            entry=entry,
            wordlist=list(dm.get_words()),
            entry_idx=0,
            total_entries=1,
            total_words=3,
            progress_callback=None,
            cancel_check=None,
        )

        assert res.username == "secureuser"
        assert res.status == AuditStatus.STRONG_PASSWORD.value
        assert res.is_weak is False

    def test_audit_from_file_yescrypt(self, tmp_path) -> None:
        """Test Linux Mode B: audit imported shadow file with yescrypt hashes."""
        try:
            from pyescrypt import Yescrypt, Mode
            import secrets
        except ImportError:
            pytest.skip("pyescrypt not installed")

        hasher = Yescrypt(n=2**16, r=8, p=1, mode=Mode.MCF)
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        weak_hash = hasher.digest(password=b"password", salt=salt1).decode("utf-8")
        strong_hash = hasher.digest(password=b"UnCr@ck4bleStr0ng!", salt=salt2).decode("utf-8")

        # Create shadow hash file
        shadow_file = tmp_path / "shadow_hashes.txt"
        shadow_file.write_text(
            f"weakuser:{weak_hash}:19000:0:99999:7:::\n"
            f"stronguser:{strong_hash}:19000:0:99999:7:::\n"
            f"lockeduser:!:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        # Create a wordlist
        wl = tmp_path / "wordlist.txt"
        wl.write_text("password\nsecret\nadmin\n", encoding="utf-8")

        DictionaryManager.reset()
        dm = DictionaryManager(wordlist_path=wl)
        dm.load()
        auditor = LinuxAuditor(dm)

        results = auditor.audit_from_file(shadow_file_path=str(shadow_file))

        # Should have 3 results: weak, strong, locked
        assert len(results) == 3

        result_map = {r.username: r for r in results}

        assert result_map["weakuser"].status == AuditStatus.WEAK_PASSWORD.value
        assert result_map["weakuser"].matched_word == "password"
        assert result_map["stronguser"].status == AuditStatus.STRONG_PASSWORD.value
        assert result_map["lockeduser"].status == AuditStatus.LOCKED.value


class TestLinuxShadowImporter:
    """Tests for collectors.linux_shadow_importer module."""

    def test_parse_simple_username_hash(self, tmp_path) -> None:
        """Test parsing simple username:hash format."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "hashes.txt"
        f.write_text(
            "root:$6$rounds=5000$saltsalt$hashedpassword\n"
            "user1:$y$j9T$salt$hashvalue\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 2
        assert result.error_count == 0
        assert result.entries[0].username == "root"
        assert result.entries[0].hash_string.startswith("$6$")
        assert result.entries[1].username == "user1"
        assert result.entries[1].hash_string.startswith("$y$")

    def test_parse_full_shadow_line(self, tmp_path) -> None:
        """Test parsing full /etc/shadow format lines."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "testuser:$6$rounds=5000$salt$hash:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 1
        entry = result.entries[0]
        assert entry.username == "testuser"
        assert entry.last_changed == 19000
        assert entry.max_days == 99999

    def test_skip_comments_and_blanks(self, tmp_path) -> None:
        """Test that comments and blank lines are skipped."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "# This is a comment\n"
            "\n"
            "user1:$6$salt$hash\n"
            "   \n"
            "# Another comment\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 1
        assert result.skipped_lines == 4

    def test_locked_accounts_detected(self, tmp_path) -> None:
        """Test that locked accounts are properly flagged."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "locked1:!$6$salt$hash:19000:0:99999:7:::\n"
            "locked2:*:19000:0:99999:7:::\n"
            "locked3:!!:19000:0:99999:7:::\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 3
        assert all(e.is_locked for e in result.entries)

    def test_invalid_hash_format_reported(self, tmp_path) -> None:
        """Test that invalid hash formats are reported as errors."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "baduser:not_a_valid_hash\n"
            "gooduser:$6$salt$hash\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 1
        assert result.error_count == 1
        assert result.entries[0].username == "gooduser"
        assert "Invalid hash format" in result.errors[0].error_message

    def test_duplicate_username_reported(self, tmp_path) -> None:
        """Test that duplicate usernames are reported as errors."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "user1:$6$salt1$hash1\n"
            "user1:$6$salt2$hash2\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 1
        assert result.error_count == 1
        assert "Duplicate" in result.errors[0].error_message

    def test_file_not_found(self) -> None:
        """Test FileNotFoundError for missing file."""
        from collectors.linux_shadow_importer import parse_shadow_file

        with pytest.raises(FileNotFoundError):
            parse_shadow_file("/nonexistent/path/shadow.txt")

    def test_yescrypt_hash_import(self, tmp_path) -> None:
        """Test importing yescrypt ($y$) hashes."""
        from collectors.linux_shadow_importer import parse_shadow_file

        f = tmp_path / "shadow.txt"
        f.write_text(
            "user1:$y$jD5$salt$hashvalue:19000:0:99999:7:::\n"
            "user2:$y$j9T$salt2$hashvalue2\n",
            encoding="utf-8",
        )

        result = parse_shadow_file(str(f))
        assert result.success_count == 2
        assert result.error_count == 0
        assert all(e.hash_string.startswith("$y$") for e in result.entries)
