# Testing & Validation Methodology — Sentinel Password Auditor

## 1. Overview

Testing ensures that Sentinel Password Auditor performs reliable, accurate security assessments across varied operating system environments and hash algorithms while guaranteeing data privacy.

---

## 2. Test Architecture

The testing suite is constructed using **pytest** and covers:

| Test Module | Scope |
|-------------|-------|
| `tests/test_password_checker.py` | Dictionary detection, case-insensitivity, whitespace, entropy scoring, repeated/sequential penalties, policy evaluation |
| `tests/test_password_hasher.py` | NTLM calculation (RFC 1320), prefix identification, passlib verification, bcrypt verification, fallback routines |
| `tests/test_dictionary_manager.py` | Singleton lifecycle, encoding resilience (UTF-8 BOM, cp1252), performance stats, missing file handling |
| `tests/test_linux_auditor.py` | Shadow entry parsing, locked account handling, malformed record resilience, permission handling |
| `tests/test_windows_auditor.py` | NTLM hash validation, malformed file parsing, pre-computed dictionary matching |
| `tests/test_reports.py` | PDF generation, JSON sanitization, credential exclusion verification |

---

## 3. Execution Commands

### Run all tests:
```bash
pytest
```

### Run unit tests only (skipping privileged integration tests):
```bash
pytest -m "not integration"
```

### Run with verbose output and coverage:
```bash
pytest -v
```

---

## 4. Privacy & Sanitization Verification

A dedicated suite of assertion tests in `tests/test_reports.py` validates that:
- Plaintext passwords do not appear anywhere in JSON or PDF report outputs (`test_json_no_plaintext_passwords`).
- Raw cryptographic hashes (NTLM, crypt) are strictly stripped from all exported reports (`test_json_no_raw_hashes`).
