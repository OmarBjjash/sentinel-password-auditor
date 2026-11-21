"""
Password hashing and verification support.

Provides NTLM and LM hash calculation for Windows auditing and Linux crypt-based
hash verification using passlib and bcrypt. Supports algorithm identification
from hash string prefixes.
"""

import hashlib
import logging
import struct
from enum import Enum
from typing import Optional

# Eager package imports for PyInstaller freeze detection
try:
    from cryptography.hazmat.bindings import _rust  # noqa: F401
    from cryptography.hazmat.primitives.ciphers import Cipher, modes  # noqa: F401
except ImportError:
    pass

try:
    import bcrypt  # noqa: F401
    import passlib  # noqa: F401
    import pyescrypt  # noqa: F401
except ImportError:
    pass

logger = logging.getLogger(__name__)


class HashAlgorithm(str, Enum):
    """Supported hash algorithm identifiers."""

    SHA512_CRYPT = "SHA-512 (crypt)"
    SHA256_CRYPT = "SHA-256 (crypt)"
    MD5_CRYPT = "MD5 (crypt)"
    DES_CRYPT = "DES (crypt)"
    BCRYPT = "bcrypt"
    YESCRYPT = "yescrypt"
    NTLM = "NTLM"
    LM = "LM"
    UNKNOWN = "Unknown"


# Mapping from hash prefixes to algorithm identifiers (longest prefix first)
_PREFIX_MAP: list[tuple[str, HashAlgorithm]] = [
    ("$6$", HashAlgorithm.SHA512_CRYPT),
    ("$5$", HashAlgorithm.SHA256_CRYPT),
    ("$y$", HashAlgorithm.YESCRYPT),
    ("$2b$", HashAlgorithm.BCRYPT),
    ("$2a$", HashAlgorithm.BCRYPT),
    ("$2y$", HashAlgorithm.BCRYPT),
    ("$1$", HashAlgorithm.MD5_CRYPT),
]


def _pure_python_md4(message: bytes) -> bytes:
    """RFC 1320 MD4 implementation fallback for Python environments lacking native MD4."""
    msg_len = len(message)
    message += b"\x80"
    message += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    message += struct.pack("<Q", msg_len * 8)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def G(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def H(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def lrot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for i in range(0, len(message), 64):
        X = list(struct.unpack("<16I", message[i : i + 64]))
        aa, bb, cc, dd = a, b, c, d
        s1 = [3, 7, 11, 19]
        for j in range(16):
            a = lrot((a + F(b, c, d) + X[j]) & 0xFFFFFFFF, s1[j % 4])
            a, b, c, d = d, a, b, c
        s2 = [3, 5, 9, 13]
        for j in range(16):
            k = (j % 4) * 4 + (j // 4)
            a = lrot((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[j % 4])
            a, b, c, d = d, a, b, c
        s3 = [3, 9, 11, 15]
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            a = lrot((a + H(b, c, d) + X[order3[j]] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[j % 4])
            a, b, c, d = d, a, b, c
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def compute_ntlm_hash(password: str) -> str:
    """
    Compute the NTLM hash of a password.

    NTLM hashing: MD4(UTF-16LE(password))

    Args:
        password: The plaintext password to hash.

    Returns:
        The NTLM hash as a lowercase 32-character hexadecimal string.
    """
    password_utf16le = password.encode("utf-16-le")
    try:
        md4_hash = hashlib.new("md4", password_utf16le).hexdigest()
    except (ValueError, Exception):
        # OpenSSL 3+ / Python 3.15+ often disables MD4 by default
        md4_hash = _pure_python_md4(password_utf16le).hex()
    return md4_hash.lower()


def _str_to_des_key(key7: bytes) -> bytes:
    """Expand a 7-byte string into an 8-byte DES key with odd parity format."""
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


def compute_lm_hash(password: str) -> str:
    """
    Compute the legacy LM (LAN Manager) hash of a password.

    Args:
        password: The plaintext password.

    Returns:
        The 32-character lowercase hexadecimal LM hash.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    # LM hash standard: uppercase, truncated/padded to 14 bytes latin-1
    pwd_bytes = password.upper().encode("latin-1", errors="replace")[:14]
    pwd_bytes = pwd_bytes.ljust(14, b"\x00")

    magic = b"KGS!@#$%"
    k1 = _str_to_des_key(pwd_bytes[:7])
    k2 = _str_to_des_key(pwd_bytes[7:14])

    cipher1 = Cipher(TripleDES(k1 * 3), modes.ECB())
    cipher2 = Cipher(TripleDES(k2 * 3), modes.ECB())

    enc1 = cipher1.encryptor()
    h1 = enc1.update(magic) + enc1.finalize()

    enc2 = cipher2.encryptor()
    h2 = enc2.update(magic) + enc2.finalize()

    return (h1 + h2).hex().lower()


def identify_algorithm(hash_string: str) -> HashAlgorithm:
    """
    Identify the hashing algorithm from a hash string based on its prefix.

    Supports detection of SHA-512, SHA-256, yescrypt, bcrypt, MD5 crypt,
    and DES crypt formats.

    Args:
        hash_string: The hash string to identify.

    Returns:
        The identified HashAlgorithm enum value.
    """
    if not hash_string:
        return HashAlgorithm.UNKNOWN

    for prefix, algorithm in _PREFIX_MAP:
        if hash_string.startswith(prefix):
            return algorithm

    # DES crypt hashes are exactly 13 characters with no $ prefix
    if len(hash_string) == 13 and not hash_string.startswith("$"):
        return HashAlgorithm.DES_CRYPT

    return HashAlgorithm.UNKNOWN


def _is_yescrypt_supported() -> bool:
    """Check if yescrypt is available via the pyescrypt library (cross-platform)."""
    try:
        from pyescrypt import Yescrypt  # noqa: F401

        return True
    except ImportError:
        return False


def verify_linux_hash(password: str, hash_string: str) -> bool:
    """
    Verify a password against a Linux crypt-style hash.

    Supports SHA-512, SHA-256, MD5, DES, bcrypt, and yescrypt algorithms.
    Yescrypt is supported cross-platform via the pyescrypt library.

    Args:
        password: The plaintext password to verify.
        hash_string: The stored hash string to verify against.

    Returns:
        True if the password matches the hash, False otherwise.

    Raises:
        ValueError: If the hash algorithm is unsupported on this platform.
    """
    algorithm = identify_algorithm(hash_string)

    if algorithm == HashAlgorithm.UNKNOWN:
        logger.warning("Unknown hash algorithm for hash: %.10s...", hash_string)
        raise ValueError(f"Unknown hash algorithm for hash: {hash_string[:10]}...")

    if algorithm == HashAlgorithm.YESCRYPT:
        return _verify_yescrypt(password, hash_string)

    if algorithm == HashAlgorithm.BCRYPT:
        return _verify_bcrypt(password, hash_string)

    if algorithm in (
        HashAlgorithm.SHA512_CRYPT,
        HashAlgorithm.SHA256_CRYPT,
        HashAlgorithm.MD5_CRYPT,
        HashAlgorithm.DES_CRYPT,
    ):
        return _verify_passlib(password, hash_string, algorithm)

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def _verify_passlib(
    password: str, hash_string: str, algorithm: HashAlgorithm
) -> bool:
    """Verify a password using passlib handlers."""
    try:
        from passlib.hash import des_crypt, md5_crypt, sha256_crypt, sha512_crypt
    except ImportError:
        logger.error("passlib is not installed. Install it with: pip install passlib")
        raise ImportError(
            "passlib is required for Linux hash verification. "
            "Install with: pip install passlib"
        )

    handler_map = {
        HashAlgorithm.SHA512_CRYPT: sha512_crypt,
        HashAlgorithm.SHA256_CRYPT: sha256_crypt,
        HashAlgorithm.MD5_CRYPT: md5_crypt,
        HashAlgorithm.DES_CRYPT: des_crypt,
    }

    handler = handler_map.get(algorithm)
    if handler is None:
        raise ValueError(f"No passlib handler for algorithm: {algorithm}")

    try:
        return handler.verify(password, hash_string)
    except Exception as exc:
        logger.debug("passlib verification error for %s: %s", algorithm, exc)
        return False


def _verify_bcrypt(password: str, hash_string: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        import bcrypt as bcrypt_lib
    except ImportError:
        logger.error("bcrypt is not installed. Install it with: pip install bcrypt")
        raise ImportError(
            "bcrypt library is required for bcrypt hash verification. "
            "Install with: pip install bcrypt"
        )

    try:
        password_bytes = password.encode("utf-8")
        hash_bytes = hash_string.encode("utf-8")
        return bcrypt_lib.checkpw(password_bytes, hash_bytes)
    except Exception as exc:
        logger.debug("bcrypt verification error: %s", exc)
        return False


def _verify_yescrypt(password: str, hash_string: str) -> bool:
    """
    Verify a password against a yescrypt ($y$) hash.

    Uses the pyescrypt library which works cross-platform (Windows, Linux, macOS).
    """
    try:
        from pyescrypt import Yescrypt, Mode, WrongPassword
    except ImportError:
        raise ValueError(
            "pyescrypt is required for yescrypt hash verification. "
            "Install with: pip install pyescrypt"
        )

    try:
        hasher = Yescrypt(mode=Mode.MCF)
        hasher.compare(password.encode("utf-8"), hash_string.encode("utf-8"))
        return True
    except WrongPassword:
        return False
    except Exception as exc:
        logger.debug("yescrypt verification error: %s", exc)
        return False


def is_algorithm_supported(algorithm: HashAlgorithm) -> bool:
    """
    Check if a given hash algorithm is supported on the current platform.

    Args:
        algorithm: The algorithm to check.

    Returns:
        True if the algorithm can be verified on this platform.
    """
    if algorithm == HashAlgorithm.YESCRYPT:
        return _is_yescrypt_supported()

    if algorithm == HashAlgorithm.BCRYPT:
        try:
            import bcrypt
            return True
        except ImportError:
            return False

    if algorithm in (
        HashAlgorithm.SHA512_CRYPT,
        HashAlgorithm.SHA256_CRYPT,
        HashAlgorithm.MD5_CRYPT,
        HashAlgorithm.DES_CRYPT,
    ):
        try:
            from passlib.hash import sha512_crypt
            return True
        except ImportError:
            return False

    if algorithm in (HashAlgorithm.NTLM, HashAlgorithm.LM):
        return True

    return False
