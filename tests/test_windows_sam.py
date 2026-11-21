"""
Tests for Windows SAM acquisition and local account auditing.

Covers:
- Administrator privilege detection
- Windows environment detection
- Acquisition service error handling and validation
- BootKey and HBootKey cryptographic transforms
- DES / AES / RC4 decryption routines
- Clean error reporting when not elevated (zero false positives)
- Zero disk retention of temporary acquisition hives
- Integration with WindowsAuditor and AuditEngine
"""

import os
import platform
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from auditors.audit_result import AuditStatus
from auditors.windows_auditor import WindowsAuditor
from collectors.windows_sam_collector import (
    SAMAcquisitionResult,
    WindowsSAMAcquisitionService,
    detect_windows,
    is_admin,
)
from core.audit_engine import AuditEngine
from core.dictionary_manager import DictionaryManager


class TestWindowsSAMCollector:
    """Unit tests for collectors.windows_sam_collector module."""

    def test_detect_windows(self) -> None:
        """Verify Windows platform detection matches the OS."""
        expected = platform.system().lower() == "windows"
        assert detect_windows() == expected

    def test_is_admin_detection(self) -> None:
        """Verify is_admin() returns a boolean without throwing exceptions."""
        admin_status = is_admin()
        assert isinstance(admin_status, bool)

    def test_check_environment_admin_check(self) -> None:
        """Verify check_environment() reports elevation requirements accurately."""
        service = WindowsSAMAcquisitionService()
        is_ok, msg = service.check_environment()

        if not detect_windows():
            assert is_ok is False
            assert "Windows" in msg
        elif not is_admin():
            assert is_ok is False
            assert "Administrator" in msg
        else:
            assert is_ok is True

    def test_check_environment_mocked_non_windows(self) -> None:
        """Verify environment check cleanly rejects non-Windows platforms."""
        service = WindowsSAMAcquisitionService()
        with patch("collectors.windows_sam_collector.detect_windows", return_value=False):
            is_ok, msg = service.check_environment()
            assert is_ok is False
            assert "only supported on Windows" in msg

    def test_check_environment_mocked_non_admin(self) -> None:
        """Verify environment check cleanly rejects unprivileged executions."""
        service = WindowsSAMAcquisitionService()
        with patch("collectors.windows_sam_collector.detect_windows", return_value=True), \
             patch("collectors.windows_sam_collector.is_admin", return_value=False):
            is_ok, msg = service.check_environment()
            assert is_ok is False
            assert "Administrator privileges required" in msg

    def test_live_sam_acquisition_non_admin_fails_safely(self) -> None:
        """
        Verify acquire_live_sam() safely returns failure when not elevated
        and NEVER reports false success.
        """
        service = WindowsSAMAcquisitionService()
        with patch("collectors.windows_sam_collector.is_admin", return_value=False):
            res: SAMAcquisitionResult = service.acquire_live_sam()
            assert res.success is False
            assert res.accounts_found == 0
            assert res.error_message is not None
            assert "Administrator" in res.error_message

    def test_offline_sam_missing_files(self) -> None:
        """Verify acquire_offline_sam() handles missing hive files gracefully."""
        service = WindowsSAMAcquisitionService()
        res = service.acquire_offline_sam("non_existent_sam.hive", "non_existent_sys.hive")
        assert res.success is False
        assert "not found" in res.error_message.lower()

    def test_offline_sam_corrupted_hives(self, tmp_path: Path) -> None:
        """Verify hive parser rejects invalid/corrupted files gracefully."""
        bad_sam = tmp_path / "bad_sam"
        bad_sys = tmp_path / "bad_sys"
        bad_sam.write_bytes(b"NOT_A_REGISTRY_HIVE_FILE_DATA_1234567890")
        bad_sys.write_bytes(b"NOT_A_REGISTRY_HIVE_FILE_DATA_1234567890")

        service = WindowsSAMAcquisitionService()
        res = service.acquire_offline_sam(str(bad_sam), str(bad_sys))
        assert res.success is False
        assert "invalid" in res.error_message.lower() or "failed" in res.error_message.lower()

    def test_derive_des_keys(self) -> None:
        """Test RID-based DES key derivation against known RID 500 vectors."""
        service = WindowsSAMAcquisitionService()
        k1, k2 = service._derive_des_keys(500)
        assert len(k1) == 8
        assert len(k2) == 8
        assert k1.hex() == "f40040000ea00400"
        assert k2.hex() == "007a00200006d002"

    def test_des_decryption_routine(self) -> None:
        """Verify single DES decryption routine."""
        service = WindowsSAMAcquisitionService()
        key = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        # Test vector: encrypt 8 bytes with TripleDES (key*3), then decrypt
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            cipher = Cipher(TripleDES(key * 3), modes.ECB())
        except (ImportError, Exception):
            cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())
        enc = cipher.encryptor()
        ciphertext = enc.update(b"ABCDEFGH") + enc.finalize()

        plaintext = service._des_decrypt(key, ciphertext)
        assert plaintext == b"ABCDEFGH"

    def test_aes_cbc_decryption_routine(self) -> None:
        """Verify AES-128-CBC decryption helper."""
        service = WindowsSAMAcquisitionService()
        key = b"\x00" * 16
        iv = b"\x00" * 16
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(b"16_BYTE_TEST_MSG") + enc.finalize()

        pt = service._decrypt_aes_cbc(key, iv, ct)
        assert pt == b"16_BYTE_TEST_MSG"

    def test_rc4_decryption_routine(self) -> None:
        """Verify RC4 decryption helper."""
        service = WindowsSAMAcquisitionService()
        key = b"SECRET_RC4_KEY_1"
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
            cipher = Cipher(ARC4(key), mode=None)
        except (ImportError, Exception):
            cipher = Cipher(algorithms.ARC4(key), mode=None)
        enc = cipher.encryptor()
        ct = enc.update(b"HELLO_RC4_WORLD!") + enc.finalize()

        pt = service._decrypt_rc4(key, ct)
        assert pt == b"HELLO_RC4_WORLD!"

    def test_v_value_aes_ntlm_decryption_end_to_end(self) -> None:
        """
        End-to-end verification of V-value table parsing and AES-128 NTLM decryption.
        """
        service = WindowsSAMAcquisitionService()
        rid = 1001
        hbootkey = b"16_BYTE_HBOOOTKEY!"[:16]
        salt = b"16_BYTE_SALT_123"[:16]

        # Target NTLM hash of 'password'
        target_ntlm_hex = "8846f7eaee8fb117ad06bdd830b7586c"
        raw_ntlm = bytes.fromhex(target_ntlm_hex)

        # 1. Derive DES keys for RID 1001
        k1, k2 = service._derive_des_keys(rid)

        # 2. DES encrypt target hash
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

        c1 = Cipher(TripleDES(k1 * 3), modes.ECB()).encryptor()
        c2 = Cipher(TripleDES(k2 * 3), modes.ECB()).encryptor()
        des_crypted = c1.update(raw_ntlm[:8]) + c1.finalize() + c2.update(raw_ntlm[8:]) + c2.finalize()

        # 3. AES-128-CBC encrypt with hbootkey and salt
        from cryptography.hazmat.primitives.ciphers import algorithms
        aes_cipher = Cipher(algorithms.AES(hbootkey), modes.CBC(salt)).encryptor()
        aes_crypted = aes_cipher.update(des_crypted) + aes_cipher.finalize()

        # 4. Construct SAM_HASH_AES block:
        # PekID (2B), Revision (2B), DataOffset (4B), Salt (16B), Hash (16B)
        crypted_nt = struct.pack("<HHL", 1, 2, 0) + salt + aes_crypted
        assert len(crypted_nt) == 40

        # 5. Build synthetic V-value:
        # Header size 0xCC (204 bytes)
        # NTHashOffset at 0xA8, NTHashLength at 0xAC
        v_header = bytearray(0xCC)
        struct.pack_into("<I", v_header, 0xA8, 0)       # Relative offset 0 in Data section
        struct.pack_into("<I", v_header, 0xAC, len(crypted_nt))  # Length 40

        v_data = bytes(v_header) + crypted_nt

        # 6. Decrypt and verify
        decrypted_ntlm = service._decrypt_user_ntlm(v_data, rid, hbootkey, is_aes=True)
        assert decrypted_ntlm == target_ntlm_hex

    def test_extract_hbootkey_aes_offsets(self) -> None:
        """Verify _extract_hbootkey correctly parses Revision 2 AES-128 SAM F-value."""
        from unittest.mock import MagicMock
        service = WindowsSAMAcquisitionService()
        bootkey = b"0123456789ABCDEF"
        salt = b"ABCDEF0123456789"
        expected_hbootkey = b"EXPECTED_HBOOT_K"

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(bootkey), modes.CBC(salt)).encryptor()
        enc_data = cipher.update(expected_hbootkey) + cipher.finalize()

        # Build F-value (Key0 at offset 0x68)
        # 0x68: Revision=2, Length=len(enc_data)+32, CheckSumLen=16, DataLen=len(enc_data)
        f_data = bytearray(0x68)
        f_data += struct.pack("<LLLL", 2, len(enc_data) + 32, 16, len(enc_data))
        f_data += salt
        f_data += enc_data

        mock_reg = MagicMock()
        mock_f_val = MagicMock()
        mock_f_val.raw_data.return_value = bytes(f_data)

        mock_account_key = MagicMock()
        mock_account_key.value.return_value = mock_f_val

        with patch.object(service, "_find_key_path", return_value=mock_account_key):
            hbootkey, is_aes = service._extract_hbootkey(mock_reg, bootkey)
            assert is_aes is True
            assert hbootkey == expected_hbootkey

    def test_wipe_and_delete_hives(self, tmp_path: Path) -> None:
        """Verify _wipe_and_delete_hives zeroes data, unlinks files, and cleans directory."""
        work_dir = tmp_path / "sentinel_sam_test"
        work_dir.mkdir()
        sam_file = work_dir / "SAM"
        sys_file = work_dir / "SYSTEM"

        sam_file.write_bytes(b"SENSITIVE_SAM_DATA" * 100)
        sys_file.write_bytes(b"SENSITIVE_SYSTEM_DATA" * 100)

        assert sam_file.exists()
        assert sys_file.exists()

        WindowsSAMAcquisitionService._wipe_and_delete_hives(
            temp_dir=str(work_dir), hive_files=[sam_file, sys_file]
        )

        assert not sam_file.exists()
        assert not sys_file.exists()
        assert not work_dir.exists()

    def test_purge_leftover_temp_hives(self) -> None:
        """Verify purge_leftover_temp_hives cleans up stale sentinel_sam_* folders."""
        test_temp_dir = Path(tempfile.gettempdir()) / "sentinel_sam_cleanup_test"
        test_temp_dir.mkdir(exist_ok=True)
        dummy_file = test_temp_dir / "SAM"
        dummy_file.write_bytes(b"OLD_SAM_STALE_BYTES")

        assert test_temp_dir.exists()

        purged_count = WindowsSAMAcquisitionService.purge_leftover_temp_hives()
        assert purged_count >= 1
        assert not test_temp_dir.exists()


class TestWindowsAuditorSAM:
    """Integration tests for WindowsAuditor and AuditEngine Local SAM workflows."""

    def test_audit_local_sam_non_admin_returns_error(self) -> None:
        """
        Verify WindowsAuditor.audit_local_sam() safely returns an error result
        when running unprivileged without crashing.
        """
        dm = DictionaryManager()
        dm.load()
        auditor = WindowsAuditor(dm)

        with patch("collectors.windows_sam_collector.is_admin", return_value=False):
            results = auditor.audit_local_sam()
            assert len(results) == 1
            assert results[0].status == AuditStatus.ERROR.value
            assert "Administrator" in results[0].recommendation

    def test_audit_engine_local_sam_non_admin_returns_summary(self) -> None:
        """
        Verify AuditEngine.run_windows_local_sam_audit() returns a valid AuditSummary
        with error message when unprivileged.
        """
        engine = AuditEngine()
        with patch("collectors.windows_sam_collector.is_admin", return_value=False):
            summary = engine.run_windows_local_sam_audit()
            assert summary.audit_type == "windows"
            assert summary.total_accounts == 1
            assert summary.error_accounts == 1
            assert "Administrator" in summary.results[0].recommendation

    @pytest.mark.integration
    def test_real_live_sam_audit_if_elevated(self) -> None:
        """
        Integration test: runs against live SAM ONLY when executed on Windows as Administrator.
        """
        if not detect_windows() or not is_admin():
            pytest.skip("Integration test requires Windows host with Administrator elevation.")

        engine = AuditEngine()
        summary = engine.run_windows_local_sam_audit()
        assert summary.audit_type == "windows"
        assert summary.error_message is None
        assert summary.total_accounts > 0
