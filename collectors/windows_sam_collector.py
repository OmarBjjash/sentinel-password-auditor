"""
Windows Local SAM acquisition and auditing service.

Implements real local Windows SAM auditing modeled after Ophcrack's Local SAM
and Encrypted SAM workflows:
1. Verifies Windows environment and Administrator elevation.
2. Acquires local SAM and SYSTEM hives through authorized administrative
   APIs (reg save HKLM\\SAM and reg save HKLM\\SYSTEM) to a secure temporary location.
3. Decrypts the BootKey (Syskey) from the SYSTEM hive.
4. Decrypts the SAM domain key from SAM\\Domains\\Account (supporting AES-128 and RC4).
5. Extracts local account usernames and relative identifiers (RIDs).
6. Decrypts user NTLM and LM hashes in-memory.
7. Immediately wipes and removes temporary hive files (zero disk retention).
8. Returns account records as ImportedHash objects for dictionary evaluation.
"""

import ctypes
import gc
import hashlib
import logging
import os
import platform
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from collectors.windows_hash_importer import ImportedHash
from core.password_hasher import compute_ntlm_hash

# Eager package imports for PyInstaller freeze detection
try:
    from cryptography.hazmat.bindings import _rust  # noqa: F401
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: F401
except ImportError:
    pass

try:
    from Registry import Registry  # noqa: F401
except ImportError:
    pass

logger = logging.getLogger(__name__)

# Permutation transform matrix for BootKey (Syskey) from SYSTEM hive
_BOOTKEY_TRANSFORMS = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

# Constants for SAM decryption
_QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
_DIGITS = b"0123456789012345678901234567890123456789\0"
_NTPASSWORD = b"NTPASSWORD\0"
_LMPASSWORD = b"LMPASSWORD\0"

# Standard empty password hash markers
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


def is_admin() -> bool:
    """
    Check if the current process is running with Administrator privileges.

    Returns:
        True if running with elevated administrative tokens on Windows.
    """
    if platform.system().lower() != "windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def detect_windows() -> bool:
    """
    Detect if the current host is running Windows.

    Returns:
        True if platform is Windows.
    """
    return platform.system().lower() == "windows"


@dataclass
class SAMAcquisitionResult:
    """Result of Windows SAM hash acquisition."""

    success: bool
    hashes: List[ImportedHash] = field(default_factory=list)
    error_message: Optional[str] = None
    accounts_found: int = 0
    acquisition_mode: str = "local_live"  # 'local_live' or 'offline_hives'


class WindowsSAMAcquisitionService:
    """
    Dedicated acquisition service for local Windows SAM account hashes.

    Provides both live local SAM acquisition (requiring Administrator rights)
    and offline hive parsing (for authorized SAM & SYSTEM exports).
    """

    @classmethod
    def check_environment(cls) -> Tuple[bool, str]:
        """
        Verify if the current system environment supports local SAM auditing.

        Returns:
            Tuple of (is_supported: bool, message: str)
        """
        if not detect_windows():
            return (
                False,
                f"Local SAM auditing is only supported on Windows (current OS: {platform.system()}).",
            )

        if not is_admin():
            return (
                False,
                "Administrator privileges required. Please launch Sentinel Password Auditor "
                "with 'Run as administrator' to audit the local SAM database.",
            )

        return True, "Environment verified: Windows with Administrator privileges."

    def acquire_live_sam(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> SAMAcquisitionResult:
        """
        Perform live acquisition of the local Windows SAM database.

        Requires Administrator privileges. Temporarily saves SAM and SYSTEM
        hives via standard Windows administrative commands, extracts account
        NTLM hashes in memory, and immediately deletes temporary hive files.

        Args:
            progress_callback: Optional progress reporter (current, total, message).

        Returns:
            SAMAcquisitionResult containing acquired hashes or error details.
        """
        # Step 1: Privilege & Environment Check
        is_ok, reason = self.check_environment()
        if not is_ok:
            logger.warning("Local SAM acquisition check failed: %s", reason)
            return SAMAcquisitionResult(
                success=False,
                error_message=reason,
                acquisition_mode="local_live",
            )

        # Purge any leftover temporary hives from previous runs before starting
        self.purge_leftover_temp_hives()

        if progress_callback:
            progress_callback(1, 5, "Preparing secure temporary acquisition workspace...")

        # Step 2: Create isolated temporary directory
        temp_dir = tempfile.mkdtemp(prefix="sentinel_sam_")
        temp_path = Path(temp_dir)
        sam_hive = temp_path / "SAM"
        system_hive = temp_path / "SYSTEM"

        try:
            if progress_callback:
                progress_callback(2, 5, "Acquiring local SAM and SYSTEM registry hives...")

            creation_flags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Export SAM hive via reg save
            res_sam = subprocess.run(
                ["reg.exe", "save", r"HKLM\SAM", str(sam_hive), "/y"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=creation_flags,
            )
            if res_sam.returncode != 0:
                err_text = res_sam.stderr.strip() or res_sam.stdout.strip()
                if "privilege is not held" in err_text.lower():
                    err_msg = "Administrator privileges required to access HKLM\\SAM."
                else:
                    err_msg = f"Failed to acquire HKLM\\SAM hive: {err_text}"
                logger.error(err_msg)
                return SAMAcquisitionResult(success=False, error_message=err_msg)

            # Export SYSTEM hive via reg save
            res_sys = subprocess.run(
                ["reg.exe", "save", r"HKLM\SYSTEM", str(system_hive), "/y"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=creation_flags,
            )
            if res_sys.returncode != 0:
                err_text = res_sys.stderr.strip() or res_sys.stdout.strip()
                err_msg = f"Failed to acquire HKLM\\SYSTEM hive: {err_text}"
                logger.error(err_msg)
                return SAMAcquisitionResult(success=False, error_message=err_msg)

            if progress_callback:
                progress_callback(3, 5, "Extracting BootKey and decrypting local account hashes...")

            # Step 3: Decrypt and extract account records in memory
            result = self.parse_hives(
                sam_path=sam_hive,
                system_path=system_hive,
                acquisition_mode="local_live",
                progress_callback=progress_callback,
            )
            return result

        except subprocess.TimeoutExpired:
            return SAMAcquisitionResult(
                success=False,
                error_message="SAM acquisition timed out while saving registry hives.",
            )
        except Exception as exc:
            logger.exception("Unexpected error during local SAM acquisition: %s", exc)
            return SAMAcquisitionResult(
                success=False,
                error_message=f"Acquisition error: {exc}",
            )
        finally:
            # Step 4: Zero disk retention — immediately wipe and delete temporary hives
            self._wipe_and_delete_hives(temp_dir=temp_dir, hive_files=[sam_hive, system_hive])

    def acquire_offline_sam(
        self,
        sam_path: str,
        system_path: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> SAMAcquisitionResult:
        """
        Parse previously exported SAM and SYSTEM registry hives (Ophcrack Encrypted SAM mode).

        Args:
            sam_path: File path to the SAM hive file.
            system_path: File path to the SYSTEM hive file.
            progress_callback: Optional progress reporter.

        Returns:
            SAMAcquisitionResult containing extracted account hashes.
        """
        sam_p = Path(sam_path)
        sys_p = Path(system_path)

        if not sam_p.exists():
            return SAMAcquisitionResult(
                success=False,
                error_message=f"SAM hive file not found: {sam_path}",
                acquisition_mode="offline_hives",
            )
        if not sys_p.exists():
            return SAMAcquisitionResult(
                success=False,
                error_message=f"SYSTEM hive file not found: {system_path}",
                acquisition_mode="offline_hives",
            )

        return self.parse_hives(
            sam_path=sam_p,
            system_path=sys_p,
            acquisition_mode="offline_hives",
            progress_callback=progress_callback,
        )

    def parse_hives(
        self,
        sam_path: Path,
        system_path: Path,
        acquisition_mode: str = "local_live",
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> SAMAcquisitionResult:
        """
        Parse SAM and SYSTEM hive files, extract BootKey and decrypt NTLM hashes.

        Args:
            sam_path: Path to SAM hive.
            system_path: Path to SYSTEM hive.
            acquisition_mode: 'local_live' or 'offline_hives'.
            progress_callback: Progress reporting callback.

        Returns:
            SAMAcquisitionResult with extracted account hashes.
        """
        try:
            from Registry import Registry
        except ImportError:
            return SAMAcquisitionResult(
                success=False,
                error_message="Required dependency 'python-registry' is not installed.",
                acquisition_mode=acquisition_mode,
            )

        system_reg = None
        sam_reg = None
        bootkey = None
        hbootkey = None
        try:
            # 1. Open SYSTEM hive and extract BootKey
            system_reg = Registry.Registry(str(system_path))
            bootkey = self._extract_bootkey(system_reg)
            del system_reg
            system_reg = None

            if not bootkey:
                return SAMAcquisitionResult(
                    success=False,
                    error_message="Failed to derive BootKey (Syskey) from SYSTEM hive.",
                    acquisition_mode=acquisition_mode,
                )

            # 2. Open SAM hive and decrypt HBootKey
            sam_reg = Registry.Registry(str(sam_path))
            hbootkey, is_aes = self._extract_hbootkey(sam_reg, bootkey)
            if not hbootkey:
                del sam_reg
                sam_reg = None
                return SAMAcquisitionResult(
                    success=False,
                    error_message="Failed to decrypt HBootKey from SAM hive.",
                    acquisition_mode=acquisition_mode,
                )

            # 3. Enumerate users and decrypt NTLM/LM hashes
            hashes = self._extract_user_hashes(sam_reg, hbootkey, is_aes)
            del sam_reg
            sam_reg = None
            del bootkey
            del hbootkey
            gc.collect()

            if not hashes:
                return SAMAcquisitionResult(
                    success=False,
                    error_message="No auditable local accounts found in SAM.",
                    accounts_found=0,
                    acquisition_mode=acquisition_mode,
                )

            if progress_callback:
                progress_callback(
                    5, 5, f"Successfully acquired {len(hashes)} local account hash records."
                )

            return SAMAcquisitionResult(
                success=True,
                hashes=hashes,
                accounts_found=len(hashes),
                acquisition_mode=acquisition_mode,
            )

        except Registry.RegistryParse.ParseException as parse_err:
            logger.error("Registry parsing error: %s", parse_err)
            return SAMAcquisitionResult(
                success=False,
                error_message=f"Corrupt or invalid registry hive file: {parse_err}",
                acquisition_mode=acquisition_mode,
            )
        except Exception as exc:
            logger.exception("Failed to parse SAM/SYSTEM hives: %s", exc)
            return SAMAcquisitionResult(
                success=False,
                error_message=f"Failed to parse SAM/SYSTEM hives: {exc}",
                acquisition_mode=acquisition_mode,
            )
        finally:
            if system_reg is not None:
                del system_reg
            if sam_reg is not None:
                del sam_reg
            gc.collect()

    def _extract_bootkey(self, system_reg: Any) -> Optional[bytes]:
        """
        Extract and unscramble the 16-byte BootKey from the SYSTEM hive.
        """
        root = system_reg.root()

        # Determine active ControlSet from Select\Current
        control_set_name = "ControlSet001"
        try:
            select_key = self._find_key_case_insensitive(root, "Select")
            if select_key:
                val = select_key.value("Current").value()
                control_set_name = f"ControlSet{val:03d}"
        except Exception:
            pass

        # Try active ControlSet, then fallback to CurrentControlSet
        lsa_key = self._find_key_path(root, [control_set_name, "Control", "Lsa"])
        if not lsa_key:
            lsa_key = self._find_key_path(root, ["CurrentControlSet", "Control", "Lsa"])

        if not lsa_key:
            logger.error("SYSTEM hive missing Control\\Lsa key")
            return None

        # Keys containing bootkey class data
        class_str = ""
        for sub_name in ["JD", "Skew1", "GBG", "Data"]:
            sub = self._find_key_case_insensitive(lsa_key, sub_name)
            if not sub:
                logger.error("SYSTEM hive missing Lsa\\%s key", sub_name)
                return None
            try:
                cname = sub._nkrecord.classname()
                class_str += cname.strip("\x00 \t\r\n")
            except Exception as exc:
                logger.error("Could not read classname for Lsa\\%s: %s", sub_name, exc)
                return None

        if len(class_str) < 32:
            logger.error("Invalid class data length for BootKey: %d", len(class_str))
            return None

        try:
            raw_bytes = bytes.fromhex(class_str[:32])
            # Apply permutation
            bootkey = bytes(raw_bytes[_BOOTKEY_TRANSFORMS[i]] for i in range(16))
            logger.debug("Successfully derived 16-byte BootKey from SYSTEM hive")
            return bootkey
        except Exception as exc:
            logger.error("Failed to unscramble BootKey: %s", exc)
            return None

    def _extract_hbootkey(self, sam_reg: Any, bootkey: bytes) -> Tuple[Optional[bytes], bool]:
        """
        Decrypt the HBootKey from SAM\\Domains\\Account\\F value.

        The F value layout:
          - Key0 starts at offset 0x68 (104)
          - If Revision == 2 (AES-128, Windows Vista+ / 10 / 11):
              - 0x68: Revision (4B)
              - 0x6C: Length (4B)
              - 0x70: CheckSumLen (4B)
              - 0x74: DataLen (4B)
              - 0x78..0x88: Salt (16B)
              - 0x88..0x88+DataLen: Encrypted Data
          - If Revision == 1 (RC4, Windows XP / 2003):
              - 0x68: Revision (4B)
              - 0x6C: Length (4B)
              - 0x70..0x80: Salt (16B)
              - 0x80..0x90: Encrypted Key (16B)
              - 0x90..0xA0: CheckSum (16B)

        Returns:
            Tuple of (hbootkey: bytes, is_aes: bool)
        """
        root = sam_reg.root()
        account_key = self._find_key_path(root, ["Domains", "Account"])
        if not account_key:
            account_key = self._find_key_path(root, ["SAM", "Domains", "Account"])

        if not account_key:
            logger.error("SAM hive missing Domains\\Account key")
            return None, False

        f_val = account_key.value("F")
        if not f_val:
            logger.error("SAM hive missing F value in Domains\\Account")
            return None, False

        f_data = f_val.raw_data()
        if len(f_data) < 0x88:
            logger.error("F value in SAM hive is too short (%d bytes)", len(f_data))
            return None, False

        revision = struct.unpack_from("<I", f_data, 0x68)[0]

        if revision == 2:
            # Modern Windows (Vista / 7 / 8 / 10 / 11 / Server 2016+) using AES-128-CBC
            data_len = struct.unpack_from("<I", f_data, 0x74)[0]
            if len(f_data) < 0x88 + data_len:
                logger.error("F value data truncated for AES Key0")
                return None, False

            salt = f_data[0x78:0x88]
            enc_key = f_data[0x88 : 0x88 + data_len]
            # Decrypt AES ciphertext with bootkey and salt
            decrypted = self._decrypt_aes_cbc(
                bootkey[:16], salt, enc_key[:16] if len(enc_key) >= 16 else enc_key
            )
            hbootkey = decrypted[:16]
            logger.debug("Decrypted HBootKey using AES-128")
            return hbootkey, True

        elif revision == 1:
            # Legacy Windows (XP / 2003) using RC4
            salt = f_data[0x70:0x80]
            enc_key = f_data[0x80:0x90]
            rc4_key = hashlib.md5(salt + _QWERTY + bootkey + _DIGITS).digest()
            decrypted = self._decrypt_rc4(rc4_key, enc_key)
            hbootkey = decrypted[:16]
            logger.debug("Decrypted HBootKey using RC4")
            return hbootkey, False

        else:
            logger.error("Unsupported SAM F-value encryption revision: %d", revision)
            return None, False

    def _extract_user_hashes(
        self, sam_reg: Any, hbootkey: bytes, is_aes: bool
    ) -> List[ImportedHash]:
        """
        Extract user account NTLM/LM hashes from SAM hive.

        Directly enumerates all RID subkeys under Domains\\Account\\Users,
        extracts the username from each user's V value header, and decrypts
        hashes in memory.
        """
        root = sam_reg.root()
        users_key = self._find_key_path(root, ["Domains", "Account", "Users"])
        if not users_key:
            users_key = self._find_key_path(root, ["SAM", "Domains", "Account", "Users"])

        if not users_key:
            logger.error("SAM hive missing Domains\\Account\\Users key")
            return []

        hashes: List[ImportedHash] = []

        # Enumerate each user key (named as 8-character hex RID, e.g. '000001F4', '000003E9')
        for user_entry_key in users_key.subkeys():
            kname = user_entry_key.name()
            if kname.lower() == "names":
                continue

            try:
                rid = int(kname, 16)
            except ValueError:
                continue

            try:
                v_val = user_entry_key.value("V")
                if not v_val:
                    continue
                v_data = v_val.raw_data()
                if len(v_data) < 0xCC:
                    continue

                # Extract username directly from V-value
                name_offset = struct.unpack_from("<I", v_data, 0x0C)[0]
                name_len = struct.unpack_from("<I", v_data, 0x10)[0]
                username = ""
                if 0xCC + name_offset + name_len <= len(v_data):
                    raw_name = v_data[0xCC + name_offset : 0xCC + name_offset + name_len]
                    username = raw_name.decode("utf-16le", errors="replace")

                if not username:
                    username = f"User_{rid}"

                ntlm_hex, lm_hex = self._decrypt_user_hashes_from_v(
                    v_data, rid, hbootkey, is_aes
                )

                if ntlm_hex:
                    hashes.append(
                        ImportedHash(
                            username=username,
                            ntlm_hash=ntlm_hex,
                            line_number=0,
                            lm_hash=lm_hex,
                            source_format="local_sam",
                        )
                    )
            except Exception as exc:
                logger.warning("Error processing user key %s (RID %d): %s", kname, rid, exc)

        return hashes

    def _decrypt_user_hashes_from_v(
        self, v_data: bytes, rid: int, hbootkey: bytes, is_aes: bool
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Decrypt the NTLM and LM hashes of an individual user account from its V value.

        The standard SAM V-value header is 0xCC (204 bytes) long:
          - LMHashOffset:  at offset 0x9C (156) [4 bytes]
          - LMHashLength:  at offset 0xA0 (160) [4 bytes]
          - NTHashOffset:  at offset 0xA8 (168) [4 bytes]
          - NTHashLength:  at offset 0xAC (172) [4 bytes]
        All data offsets are relative to 0xCC (the start of the Data section).

        Returns:
            Tuple of (ntlm_hex: Optional[str], lm_hex: Optional[str])
        """
        if len(v_data) < 0xCC:
            return None, None

        # Read LM hash descriptor
        lm_rel_offset = struct.unpack_from("<I", v_data, 0x9C)[0]
        lm_len = struct.unpack_from("<I", v_data, 0xA0)[0]

        # Read NT hash descriptor
        nt_rel_offset = struct.unpack_from("<I", v_data, 0xA8)[0]
        nt_len = struct.unpack_from("<I", v_data, 0xAC)[0]

        key1, key2 = self._derive_des_keys(rid)

        ntlm_hex: Optional[str] = None
        lm_hex: Optional[str] = None

        # ── 1. Decrypt NTLM Hash ─────────────────────────────────────────
        ntlm_offset = 0xCC + nt_rel_offset
        if nt_len == 0 or nt_len == 24:
            # 0 bytes or 24-byte AES empty-payload header = Blank password
            ntlm_hex = EMPTY_NT_HASH
        elif nt_len > 24 and ntlm_offset + nt_len <= len(v_data):
            crypted_nt = v_data[ntlm_offset : ntlm_offset + nt_len]
            ntlm_hex = self._decrypt_single_hash(
                crypted_data=crypted_nt,
                rid=rid,
                hbootkey=hbootkey,
                is_aes=is_aes,
                key1=key1,
                key2=key2,
                constant=_NTPASSWORD,
            )
        elif nt_len == 20 and ntlm_offset + nt_len <= len(v_data):
            # Legacy 20-byte RC4 hash
            crypted_nt = v_data[ntlm_offset : ntlm_offset + nt_len]
            ntlm_hex = self._decrypt_single_hash(
                crypted_data=crypted_nt,
                rid=rid,
                hbootkey=hbootkey,
                is_aes=False,
                key1=key1,
                key2=key2,
                constant=_NTPASSWORD,
            )

        # ── 2. Decrypt LM Hash ───────────────────────────────────────────
        lm_offset = 0xCC + lm_rel_offset
        if lm_len == 0 or lm_len == 24:
            lm_hex = EMPTY_LM_HASH
        elif lm_len > 24 and lm_offset + lm_len <= len(v_data):
            crypted_lm = v_data[lm_offset : lm_offset + lm_len]
            lm_hex = self._decrypt_single_hash(
                crypted_data=crypted_lm,
                rid=rid,
                hbootkey=hbootkey,
                is_aes=is_aes,
                key1=key1,
                key2=key2,
                constant=_LMPASSWORD,
            )
        elif lm_len == 20 and lm_offset + lm_len <= len(v_data):
            crypted_lm = v_data[lm_offset : lm_offset + lm_len]
            lm_hex = self._decrypt_single_hash(
                crypted_data=crypted_lm,
                rid=rid,
                hbootkey=hbootkey,
                is_aes=False,
                key1=key1,
                key2=key2,
                constant=_LMPASSWORD,
            )

        return ntlm_hex, lm_hex

    def _decrypt_single_hash(
        self,
        crypted_data: bytes,
        rid: int,
        hbootkey: bytes,
        is_aes: bool,
        key1: bytes,
        key2: bytes,
        constant: bytes,
    ) -> Optional[str]:
        """Decrypt an individual encrypted hash structure (AES or RC4)."""
        # Check hash revision in header (byte index 2)
        hash_rev = struct.unpack_from("<H", crypted_data, 2)[0] if len(crypted_data) >= 4 else 0
        use_aes = (hash_rev == 2) or (is_aes and hash_rev != 1)

        if use_aes:
            # Modern Windows (SAM_HASH_AES):
            # PekID (2), Revision (2), DataOffset (4), Salt (16), Hash (16+)
            if len(crypted_data) < 40:
                return EMPTY_NT_HASH if constant == _NTPASSWORD else EMPTY_LM_HASH
            salt = crypted_data[8:24]
            enc_hash = crypted_data[24:40]
            aes_dec = self._decrypt_aes_cbc(hbootkey[:16], salt, enc_hash)
            dec_hash = self._des_decrypt(key1, aes_dec[:8]) + self._des_decrypt(key2, aes_dec[8:16])
            return dec_hash.hex().lower()
        else:
            # Legacy Windows (SAM_HASH):
            # PekID (2), Revision (2), Hash (16)
            if len(crypted_data) < 20:
                return EMPTY_NT_HASH if constant == _NTPASSWORD else EMPTY_LM_HASH
            enc_hash = crypted_data[4:20]
            rc4_key = hashlib.md5(hbootkey[:16] + struct.pack("<I", rid) + constant).digest()
            rc4_dec = self._decrypt_rc4(rc4_key, enc_hash)
            dec_hash = self._des_decrypt(key1, rc4_dec[:8]) + self._des_decrypt(key2, rc4_dec[8:16])
            return dec_hash.hex().lower()

    def _decrypt_user_ntlm(
        self, v_data: bytes, rid: int, hbootkey: bytes, is_aes: bool
    ) -> Optional[str]:
        """Backward-compatible helper for decrypting NTLM hash only."""
        ntlm_hex, _ = self._decrypt_user_hashes_from_v(v_data, rid, hbootkey, is_aes)
        return ntlm_hex

    @staticmethod
    def _derive_des_keys(rid: int) -> Tuple[bytes, bytes]:
        """Derive two 8-byte DES keys from the account RID."""
        rid_bytes = struct.pack("<I", rid)
        k1 = bytes([rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2]])
        k2 = bytes([rid_bytes[3], rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3], rid_bytes[0], rid_bytes[1]])

        def transform_key(key7: bytes) -> bytes:
            key8 = [
                (key7[0] >> 1),
                (((key7[0] & 0x01) << 6) | (key7[1] >> 2)),
                (((key7[1] & 0x03) << 5) | (key7[2] >> 3)),
                (((key7[2] & 0x07) << 4) | (key7[3] >> 4)),
                (((key7[3] & 0x0F) << 3) | (key7[4] >> 5)),
                (((key7[4] & 0x1F) << 2) | (key7[5] >> 6)),
                (((key7[5] & 0x3F) << 1) | (key7[6] >> 7)),
                (key7[6] & 0x7F),
            ]
            for i in range(8):
                key8[i] = (key8[i] << 1) & 0xFE
            return bytes(key8)

        return transform_key(k1), transform_key(k2)

    @staticmethod
    def _des_decrypt(key: bytes, data: bytes) -> bytes:
        """Decrypt 8 bytes using single DES (emulated via TripleDES)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            cipher = Cipher(TripleDES(key * 3), modes.ECB())
        except (ImportError, Exception):
            cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    @staticmethod
    def _decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using AES-128-CBC."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def _decrypt_rc4(key: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using RC4 (ARC4)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
            cipher = Cipher(ARC4(key), mode=None)
        except (ImportError, Exception):
            cipher = Cipher(algorithms.ARC4(key), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @classmethod
    def _find_key_case_insensitive(cls, parent_key: Any, target_name: str) -> Optional[Any]:
        """Search subkeys case-insensitively."""
        target_lower = target_name.lower()
        for sub in parent_key.subkeys():
            if sub.name().lower() == target_lower:
                return sub
        return None

    @classmethod
    def _find_key_path(cls, root: Any, path_parts: List[str]) -> Optional[Any]:
        """Traverse a key path case-insensitively."""
        curr = root
        for part in path_parts:
            nxt = cls._find_key_case_insensitive(curr, part)
            if not nxt:
                return None
            curr = nxt
        return curr

    @classmethod
    def _wipe_and_delete_hives(
        cls,
        temp_dir: Optional[str] = None,
        hive_files: Optional[List[Path]] = None,
    ) -> None:
        """
        Securely wipe and delete temporary SAM/SYSTEM hives (zero disk retention).

        Overwrites hive file bytes with zeros to prevent recovery and avoid
        filesystem caching, clears read-only attributes, unlinks individual files,
        and purges the containing temporary directory.
        """
        gc.collect()

        files_to_clean: List[Path] = []
        if hive_files:
            files_to_clean.extend(hive_files)

        if temp_dir and os.path.exists(temp_dir):
            try:
                for entry in Path(temp_dir).iterdir():
                    if entry.is_file() and entry not in files_to_clean:
                        files_to_clean.append(entry)
            except Exception as scan_err:
                logger.debug("Error listing temp dir %s: %s", temp_dir, scan_err)

        # 1. Overwrite bytes and unlink each hive file
        for file_path in files_to_clean:
            try:
                if file_path.exists() and file_path.is_file():
                    # Clear read-only flags
                    try:
                        os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
                    except OSError:
                        pass

                    # Overwrite file content with zeros
                    try:
                        file_size = file_path.stat().st_size
                        if file_size > 0:
                            with open(file_path, "r+b") as f:
                                chunk_size = 64 * 1024
                                written = 0
                                zero_chunk = b"\x00" * chunk_size
                                while written < file_size:
                                    to_write = min(chunk_size, file_size - written)
                                    f.write(zero_chunk[:to_write])
                                    written += to_write
                                f.flush()
                                os.fsync(f.fileno())
                    except Exception as wipe_err:
                        logger.debug(
                            "Could not overwrite hive before delete (%s): %s",
                            file_path,
                            wipe_err,
                        )

                    # Retry unlinking with small backoff
                    for _ in range(4):
                        try:
                            file_path.unlink(missing_ok=True)
                            break
                        except OSError:
                            time.sleep(0.05)
                            gc.collect()
            except Exception as file_err:
                logger.warning(
                    "Failed to securely delete hive file %s: %s",
                    file_path,
                    file_err,
                )

        # 2. Purge the temporary directory itself
        if temp_dir and os.path.exists(temp_dir):
            def _remove_readonly(func, path, exc_info):
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception:
                    pass

            for _ in range(4):
                try:
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir, onerror=_remove_readonly)
                    logger.debug("Purged temporary acquisition directory: %s", temp_dir)
                    break
                except Exception:
                    time.sleep(0.05)
                    gc.collect()

    @classmethod
    def purge_leftover_temp_hives(cls) -> int:
        """
        Scan system temp directory for any leftover sentinel_sam_* folders and remove them.

        Returns:
            Number of purged leftover directories.
        """
        purged = 0
        temp_base = tempfile.gettempdir()
        try:
            for item in os.listdir(temp_base):
                if item.startswith("sentinel_sam_") or item.startswith("sentinel_smoke_"):
                    full_path = os.path.join(temp_base, item)
                    if os.path.isdir(full_path):
                        cls._wipe_and_delete_hives(temp_dir=full_path)
                        purged += 1
        except Exception as exc:
            logger.debug("Error while purging leftover temp hives: %s", exc)

        # Also purge any test hive artifacts in cwd
        for stale in ["test_sam.save", "test_system.save", "SAM", "SYSTEM"]:
            p = Path(stale)
            if p.exists() and p.is_file():
                try:
                    cls._wipe_and_delete_hives(hive_files=[p])
                except Exception:
                    pass

        return purged
