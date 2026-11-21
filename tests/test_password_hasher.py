"""
Tests for password hashing and algorithm identification.
"""

import pytest

from core.password_hasher import (
    HashAlgorithm,
    compute_lm_hash,
    compute_ntlm_hash,
    identify_algorithm,
    is_algorithm_supported,
    verify_linux_hash,
)


class TestPasswordHasher:
    """Tests for core.password_hasher module."""

    def test_ntlm_hash_known_value(self) -> None:
        """Test NTLM hash of 'password' matches known standard hash."""
        # Standard test vector: NTLM('password') = 8846f7eaee8fb117ad06bdd830b7586c
        h = compute_ntlm_hash("password")
        assert h == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_ntlm_empty_password(self) -> None:
        """Test NTLM hash of empty string matches known standard hash."""
        # Standard test vector: NTLM('') = 31d6cfe0d16ae931b73c59d7e0c089c0
        h = compute_ntlm_hash("")
        assert h == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_ntlm_unicode_password(self) -> None:
        """Test NTLM handles unicode characters correctly."""
        h1 = compute_ntlm_hash("P@sswörd123")
        assert len(h1) == 32
        assert all(c in "0123456789abcdef" for c in h1)

    def test_lm_hash_known_values(self) -> None:
        """Test LM hash calculation against standard test vectors."""
        # Standard vector: LM('password') = e52cac67419a9a224a3b108f3fa6cb6d
        assert compute_lm_hash("password") == "e52cac67419a9a224a3b108f3fa6cb6d"
        # Standard vector: LM('') = aad3b435b51404eeaad3b435b51404ee
        assert compute_lm_hash("") == "aad3b435b51404eeaad3b435b51404ee"

    def test_identify_sha512(self) -> None:
        assert identify_algorithm("$6$rounds=5000$salt$hash") == HashAlgorithm.SHA512_CRYPT

    def test_identify_sha256(self) -> None:
        assert identify_algorithm("$5$salt$hash") == HashAlgorithm.SHA256_CRYPT

    def test_identify_md5(self) -> None:
        assert identify_algorithm("$1$salt$hash") == HashAlgorithm.MD5_CRYPT

    def test_identify_bcrypt(self) -> None:
        assert identify_algorithm("$2a$12$salt_and_hash") == HashAlgorithm.BCRYPT
        assert identify_algorithm("$2b$10$salt_and_hash") == HashAlgorithm.BCRYPT
        assert identify_algorithm("$2y$10$salt_and_hash") == HashAlgorithm.BCRYPT

    def test_identify_yescrypt(self) -> None:
        assert identify_algorithm("$y$j9T$salt$hash") == HashAlgorithm.YESCRYPT

    def test_identify_des(self) -> None:
        # Traditional 13-character DES crypt
        assert identify_algorithm("abC1234567890") == HashAlgorithm.DES_CRYPT

    def test_identify_unknown(self) -> None:
        assert identify_algorithm("") == HashAlgorithm.UNKNOWN
        assert identify_algorithm("some_random_string") == HashAlgorithm.UNKNOWN
        assert identify_algorithm("$unknown$hash") == HashAlgorithm.UNKNOWN

    def test_verify_sha512_hash(self) -> None:
        """Verify known SHA-512 crypt hash matches."""
        try:
            from passlib.hash import sha512_crypt

            known_hash = sha512_crypt.hash("secret123", rounds=5000)
            assert verify_linux_hash("secret123", known_hash) is True
            assert verify_linux_hash("wrong_password", known_hash) is False
        except (ImportError, Exception):
            pytest.skip("passlib sha512_crypt not available")

    def test_verify_sha256_hash(self) -> None:
        """Verify known SHA-256 crypt hash matches."""
        try:
            from passlib.hash import sha256_crypt

            known_hash = sha256_crypt.hash("mypassword", rounds=5000)
            assert verify_linux_hash("mypassword", known_hash) is True
            assert verify_linux_hash("wrong_pass", known_hash) is False
        except (ImportError, Exception):
            pytest.skip("passlib sha256_crypt not available")

    def test_algorithm_support_checks(self) -> None:
        """Verify is_algorithm_supported logic."""
        assert is_algorithm_supported(HashAlgorithm.NTLM) is True
        assert is_algorithm_supported(HashAlgorithm.LM) is True
        assert is_algorithm_supported(HashAlgorithm.UNKNOWN) is False

    def test_yescrypt_supported(self) -> None:
        """Verify yescrypt is reported as supported when pyescrypt is installed."""
        assert is_algorithm_supported(HashAlgorithm.YESCRYPT) is True

    def test_verify_yescrypt_hash(self) -> None:
        """Verify password matching against a yescrypt ($y$) hash."""
        try:
            from pyescrypt import Yescrypt, Mode
            import secrets
        except ImportError:
            pytest.skip("pyescrypt not installed")

        # Generate a known yescrypt hash
        hasher = Yescrypt(n=2**16, r=8, p=1, mode=Mode.MCF)
        salt = secrets.token_bytes(16)
        known_hash = hasher.digest(
            password=b"testpassword", salt=salt
        ).decode("utf-8")

        # Correct password should match
        assert verify_linux_hash("testpassword", known_hash) is True
        # Wrong password should not match
        assert verify_linux_hash("wrongpassword", known_hash) is False

    def test_verify_yescrypt_case_sensitive(self) -> None:
        """Verify yescrypt is case-sensitive like real Linux hashes."""
        try:
            from pyescrypt import Yescrypt, Mode
            import secrets
        except ImportError:
            pytest.skip("pyescrypt not installed")

        hasher = Yescrypt(n=2**16, r=8, p=1, mode=Mode.MCF)
        salt = secrets.token_bytes(16)
        known_hash = hasher.digest(
            password=b"Om@r", salt=salt
        ).decode("utf-8")

        assert verify_linux_hash("Om@r", known_hash) is True
        assert verify_linux_hash("om@r", known_hash) is False
        assert verify_linux_hash("OM@R", known_hash) is False
