# Assignment Report: Practical Project — Password Auditing & Security Assessment Tool

**Project Name:** Sentinel Password Auditor  
**Course:** Practical Defensive Cybersecurity & Systems Security  
**Academic Assignment:** Assignment 4 — Password Auditing & Policy Enforcement Tool  
**Date:** November 2026  
**Language & Environment:** Python 3.12+ (tested on Python 3.15), CustomTkinter, ReportLab, pytest, python-registry, cryptography  

---

## 1. Introduction

Authentication credentials remain the primary attack vector for initial unauthorized system access. In modern computing environments, weak passwords chosen by end users or systems administrators expose local machines and enterprise domains to credential stuffing, dictionary attacks, and offline brute-force cracking.

**Sentinel Password Auditor** was developed as a comprehensive defensive security assessment and auditing tool. It bridges the gap between administrative account security auditing and proactive end-user password strength verification, providing an end-to-end framework for identifying compromised local accounts and educating users on password entropy.

---

## 2. Assignment Objectives and Learning Outcomes

The primary objectives of this practical assignment are:
1. **Understanding Operating System Password Storage:** Analyze how modern operating systems (Linux and Windows) store and salt authentication credentials.
2. **Defensive Cryptographic Auditing:** Construct modules capable of extracting hash parameters and verifying them against common dictionary wordlists without degrading system integrity.
3. **Real Operating System Integration:** Execute audits against live system stores (Linux `/etc/shadow` and Windows Local SAM) rather than simulated files.
4. **Proactive End-User Assessment:** Provide an interactive, zero-retention password checking interface with entropy evaluation and policy enforcement feedback.
5. **Performance & Security Optimization:** Optimize dictionary lookups for large wordlists ($O(1)$ lookup structures) and implement strict privacy protections ensuring that credential secrets are never stored, logged, or exported.
6. **Executive & Compliance Reporting:** Generate professional PDF security reports and structured JSON exports sanitized of all sensitive data.

---

## 3. Tool Architecture & Design

Sentinel Password Auditor is constructed following a modular, layered architecture adhering to SOLID design principles.

### 3.1 Architecture Overview

```text
                    Sentinel Password Auditor
                               |
                  +-----------+-----------+
                  |                       |
             Linux Auditor          Windows Auditor
                  |                       |
             /etc/shadow         [Local SAM / NTLM Import]
                  |                       |
                  +-----------+-----------+
                               |
                         Audit Engine
                               |
                        Password Hasher
                               |
                          wordlist.txt
                               |
                       Dictionary Manager
                               |
                        Matching Engine
                               |
                        Audit Results
                               |
                     +---------+---------+
                     |                   |
                  GUI Results        PDF / JSON
```

```text
User Input -> Masked Field -> Password Checker -> Dictionary Manager (O(1)) -> Policy Analyzer -> Immediate Feedback
```

### 3.2 Visual Architecture Diagram

The system architecture diagram is generated automatically by `reports/architecture_diagram.py` and is available in high resolution:
- **PDF Diagram:** `docs/architecture_diagram.pdf`
- **PNG Diagram:** `docs/architecture_diagram.png`

---

## 4. Technologies & Core Libraries

- **Python 3.12+ Runtime:** Primary programming language leveraging modern typing, dataclasses, and threading.
- **CustomTkinter (v6.0.0):** Modern dark cybersecurity dashboard GUI with asynchronous threading support.
- **ReportLab (v5.1.0):** Enterprise-grade PDF report generator and vector architecture diagram engine.
- **Passlib (v1.7.4):** Robust cryptographic verification of Unix crypt formats (SHA-512, SHA-256, MD5, DES).
- **Bcrypt (v5.0.0):** Cryptographic verification for modern Blowfish-based password hashes.
- **python-registry (v1.3.1):** Open-source, audited registry hive parser for reading SAM and SYSTEM hives.
- **cryptography (v50.0.2):** Standard cryptographic primitives (AES-128-CBC, TripleDES, RC4) for SAM hash decryption.
- **Pillow (v13.0.0):** High-resolution rasterization and diagram image processing.
- **Pytest (v9.2.0):** Automated test suite for unit and integration verification.

---

## 5. Linux Implementation Details

Under Linux, user authentication secrets are maintained in `/etc/shadow`. Sentinel Password Auditor implements safe, read-only collection and multi-format algorithm verification:

### 5.1 Access & Privilege Handling
- **Read-Only Operation:** `/etc/shadow` is accessed in read-only mode (`r`). The collector never modifies system files or resets account credentials.
- **Privilege Checking:** `check_shadow_access()` verifies that the tool has appropriate root or `shadow` group permissions before attempting to parse records.
- **Account Filtering:** Entries flagged with `!` or `*` are classified as `LOCKED` and skipped. Empty passwords are identified and flagged accordingly.

### 5.2 Supported Hash Formats
The Linux auditor detects and verifies standard hash prefixes:
- **SHA-512 Crypt (`$6$`):** Standard modern Linux default (5,000+ rounds).
- **SHA-256 Crypt (`$5$`):** Secure Linux hashing format.
- **Bcrypt (`$2a$`, `$2b$`, `$2y$`):** Blowfish-based adaptive hashing.
- **MD5 Crypt (`$1$`):** Legacy Unix format.
- **DES Crypt:** Traditional 13-character salt+hash.
- **yescrypt (`$y$`):** Native support on modern Linux distributions via `libcrypt`.

---

## 6. Windows Implementation Details

Windows stores local user account hashes in the Security Account Manager (SAM) registry database (`%SystemRoot%\System32\config\SAM`), encrypted under a master system key (BootKey / Syskey) derived from the SYSTEM hive (`%SystemRoot%\System32\config\SYSTEM`).

Sentinel Password Auditor provides two distinct, comprehensive auditing modes modeled after Ophcrack's Local SAM and Encrypted SAM workflows:

### 6.1 Mode A: Real Live Local SAM Auditing (Ophcrack Local SAM Workflow)
When executed with administrative privileges on Windows, Sentinel performs live local SAM auditing:

1. **Privilege & Environment Verification:**
   The `WindowsSAMAcquisitionService.check_environment()` function confirms that the host is running Windows and verifies elevated administrative token possession (`ctypes.windll.shell32.IsUserAnAdmin()`). If the application is launched by an unprivileged user, it cleanly reports the elevation requirement without attempting stealth bypasses or displaying simulated results.

2. **Authorized Live Acquisition:**
   Using Windows standard administrative tooling (`reg.exe save HKLM\SAM` and `reg.exe save HKLM\SYSTEM`), live hive snapshots are saved to an isolated, secure temporary directory.

3. **Syskey Extraction & Permutation:**
   The service reads the class names from the 4 subkeys under `SYSTEM\ControlSet001\Control\Lsa`: `JD`, `Skew1`, `GBG`, and `Data`. These class name strings are concatenated and unscrambled using the standard 16-element permutation matrix:
   $$\text{Transforms} = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]$$
   yielding the 16-byte BootKey.

4. **Domain Key Decryption (HBootKey):**
   The service reads the `F` value from `SAM\Domains\Account`. It inspects the revision byte at offset `0x68`:
   - **Revision 2 (Windows 10, 11, Server 2016+):** Decrypts the 16-byte domain key using **AES-128-CBC** with the BootKey and the 16-byte salt at offset `0x70`.
   - **Revision 1 (Legacy Windows XP/2003):** Decrypts using **RC4** with an MD5-derived key.

5. **Local Account Enumeration & NTLM Decryption:**
   The service parses `SAM\Domains\Account\Users\Names` to map all local account usernames to their respective Relative Identifiers (RIDs). For each RID:
   - Reads the user's `V` structure at `Users\<RID_HEX>`.
   - Extracts the encrypted NTLM record at the offset defined in the header table.
   - Decrypts the record using **AES-128-CBC** (or RC4).
   - Derives two 8-byte single-DES keys from the user's RID using parity bit transformation.
   - Performs DES decryption of the two 8-byte halves to reconstruct the plaintext 16-byte NTLM hash.

6. **Strict Zero-Retention Guarantee:**
   In an explicit `finally:` block, all temporary registry hive snapshots on disk are wiped and the temporary directory is deleted before dictionary matching commences. Sensitive hash data exists exclusively in volatile memory.

### 6.2 Mode B: Authorized NTLM Hash Import (Ophcrack Encrypted SAM / Offline Mode)
For non-elevated executions or audits of remote systems:
- Administrators import a text file containing `username:NTLM_HASH` records.
- Strict validation rejects invalid records (must be 32 hexadecimal characters).
- Pre-computed NTLM hash tables allow $O(1)$ matching across large wordlists.

---

## 7. Interactive Password Checker

The Interactive Password Checker operates independently of system privileges, enabling unprivileged users to test proposed passwords safely:

### 7.1 Multi-Dimensional Evaluation
1. **Dictionary Exposure:** Case-insensitive lookup against loaded dictionary (`frozenset`).
2. **Base Length Score:** Up to 30 points for length up to 20+ characters.
3. **Character Diversity:** Up to 40 points (uppercase, lowercase, digits, special characters).
4. **Penalties Applied For:**
   - Repeated characters (e.g., `aaaa`).
   - Sequential characters (e.g., `12345`, `abcdef`).
   - Common patterns & keyboard walks (e.g., `qwerty`, `letmein`).
   - Leetspeak predictable substitutions (e.g., `P@ssw0rd` -> `password`).
5. **Configurable Password Policy:** Evaluates compliance against enterprise rules (min length, required sets, repeated limits).

---

## 8. Performance Considerations

1. **In-Memory Frozenset:** The dictionary manager loads `wordlist.txt` into an immutable `frozenset` of lowercased strings once via a thread-safe singleton, providing $O(1)$ average lookup time.
2. **NTLM Pre-computation:** Computing MD4(UTF-16LE(word)) for the dictionary upfront avoids repeated hashing per user account.
3. **Encoding Resilience:** Handles UTF-8 with BOM (`utf-8-sig`), plain UTF-8, and fallback CP1252/Latin-1 encodings seamlessly.
4. **Pure-Python MD4 Fallback:** Ensures continuous operation on modern Python 3.15+ / OpenSSL 3+ environments where legacy MD4 is disabled by default.
5. **Responsive Threading:** All audit operations execute on background worker threads, reporting progress to the CustomTkinter GUI via thread-safe callbacks without freezing the interface.

---

## 9. Security & Privacy Considerations

- **Zero Secret Retention:** Plaintext passwords entered into the checker and raw NTLM hashes are never stored on disk, logged, or cached.
- **Volatile Processing:** Credential comparisons happen strictly in volatile process memory and are discarded immediately.
- **Sanitized Reporting:** Exported PDF and JSON reports contain account usernames, hashing algorithms, and remediation guidance, but explicitly exclude credential secrets.
- **Offline & Air-Gapped:** Zero external network communication, zero telemetry.

---

## 10. Testing Methodology & Results

Testing was conducted using `pytest` across unit, security sanitization, and integration tests:

```text
================== 71 passed, 2 skipped in 0.47s ==================
```

### Verified Test Categories:
- **`test_windows_sam.py` (15 tests):** Admin privilege detection, Windows environment detection, unprivileged error reporting, missing/corrupted hive handling, BootKey transform math, DES key derivation, AES/RC4 decryption routines, auditor integration.
- **`test_password_checker.py` (16 tests):** Common password detection, case-insensitivity, whitespace trimming, entropy scoring, repeated/sequential penalties, policy evaluation.
- **`test_password_hasher.py` (13 tests):** NTLM RFC-compliant hash calculation, prefix identification, passlib verification, bcrypt verification, fallback routines.
- **`test_dictionary_manager.py` (7 tests):** Singleton lifecycle, encoding resilience, performance metrics, missing file handling.
- **`test_linux_auditor.py` (8 tests):** Shadow parsing, locked account skipping, malformed record resilience, permission handling.
- **`test_windows_auditor.py` (7 tests):** NTLM hash validation, malformed file parsing, pre-computed dictionary matching.
- **`test_reports.py` (6 tests):** Sanitization verification, JSON schema validation, PDF generation.

---

## 11. Execution Evidence & Screenshots

*Instructions for capturing screenshots:* Run the application using `python main.py` or the CLI commands below, use `Win + Shift + S` (Windows) or `gnome-screenshot` (Linux) to capture the window, and place the images in `docs/screenshots/`.

### Screenshot 1: Main Dashboard
Displays system environment, privilege status, dictionary status, and last audit posture.

```text
[SCREENSHOT: Main Dashboard — System overview and dictionary metrics]
Path: docs/screenshots/01_dashboard.png
```

---

### Screenshot 2: Linux Weak-Password Detection
Demonstrates Linux `/etc/shadow` audit detecting an account using a dictionary password.

```text
[SCREENSHOT: Linux Weak-Password Detection — testuser with weak SHA-512 password]
Path: docs/screenshots/02_linux_weak_detection.png
```

---

### Screenshot 3: Linux Complex-Password Account
Demonstrates Linux `/etc/shadow` audit verifying an account with a strong, non-dictionary password.

```text
[SCREENSHOT: Linux Complex-Password Account — secure user not found in dictionary]
Path: docs/screenshots/03_linux_complex_account.png
```

---

### Screenshot 4: Windows Local SAM & NTLM Weak-Account Detection
Demonstrates Windows Local SAM / NTLM audit detecting local accounts with weak passwords.

```text
[SCREENSHOT: Windows Weak-Account Detection — NTLM hash match against wordlist]
Path: docs/screenshots/04_windows_weak_detection.png
```

---

### Screenshot 5: Interactive Common-Password Test
Demonstrates the Interactive Password Checker testing a common password (e.g. `password`), displaying `UNSAFE` verdict and entropy score of `0/100`.

```text
[SCREENSHOT: Interactive Common-Password Test — Warning banner and dictionary detection]
Path: docs/screenshots/05_interactive_common_test.png
```

---

### Screenshot 6: Interactive Uncommon-Password Test
Demonstrates testing a complex password (e.g. `Xk9#mZp!2026StrongPass#Winter`), displaying `VERY_STRONG` verdict, high score, and 100% policy compliance.

```text
[SCREENSHOT: Interactive Uncommon-Password Test — High entropy and policy compliance]
Path: docs/screenshots/06_interactive_uncommon_test.png
```

---

## 12. Analytical Discussion & Answers

### Q1: Why are salted hashes significantly more secure against dictionary attacks than unsalted hashes (like raw NTLM)?
**Analysis:** Salted hashes (such as Unix SHA-512 crypt or bcrypt) append a unique random value (the salt) to the password before hashing. This ensures that two users with identical passwords will produce completely different hash strings. As a consequence, attackers cannot use pre-computed lookup structures (such as Rainbow Tables or static hash dictionaries) across multiple accounts; they must re-hash the candidate dictionary independently for each user's unique salt. Conversely, raw NTLM does not incorporate a salt, allowing defenders and attackers alike to pre-compute hashes for an entire dictionary once and perform instantaneous $O(1)$ lookups across all accounts.

### Q2: Why is offline dictionary auditing preferable to online brute-force auditing?
**Analysis:** Online brute-force auditing involves sending authentication requests directly to active authentication endpoints (such as SSH, RDP, or domain controllers). Online attacks generate extensive network traffic, risk triggering account lockout thresholds (causing denial-of-service for legitimate users), and are throttled by network latency. Offline auditing inspects non-volatile hash storage locally, eliminating network overhead, avoiding account lockouts, and allowing high-throughput cryptographic verification.

### Q3: How does Windows SAM encryption protect credentials at rest, and why are administrative rights strictly required to inspect it?
**Analysis:** On Windows systems, password hashes are not stored in plaintext within the SAM database. Instead, each user's hash is encrypted using a domain-wide secret (the SAM key), which itself is encrypted with the BootKey (Syskey) stored across class values in the SYSTEM hive. The active SAM hive is locked exclusively by the Windows operating system kernel (`ntoskrnl.exe`) and subsystem services, preventing unprivileged processes from opening the file for reading. Accessing these hives requires administrative privileges (`SeBackupPrivilege`), which ensures that unprivileged local accounts cannot read credential hashes of other accounts on the system.

---

## 13. Limitations & Future Work

1. **Yescrypt on Windows:** The modern `yescrypt` hash format (`$y$`) requires `libcrypt` native binaries available on Linux. Future enhancements could embed an independent yescrypt C-extension for cross-platform support.
2. **GPU Acceleration:** Future versions could integrate OpenCL/CUDA acceleration for auditing massive enterprise wordlists containing tens of millions of entries.

---

## 14. Conclusion

Sentinel Password Auditor demonstrates that robust defensive security assessments can be achieved while maintaining strict privacy boundaries. By combining real operating-system data collection (Linux `/etc/shadow` and Windows Local SAM), optimized cryptographic matching, proactive user education, and enterprise-grade reporting, the tool provides administrators with actionable insights to remediate credential vulnerabilities before exploitation occurs.

---

## 15. PDF Conversion Instructions

To convert this Markdown report into a formatted PDF document:

### Option A: Using Pandoc (Recommended)
```bash
pandoc docs/assignment_report.md -o docs/assignment_report.pdf --pdf-engine=xelatex
```

### Option B: Using VS Code Markdown PDF Extension
1. Open `docs/assignment_report.md` in VS Code.
2. Press `Ctrl + Shift + P` -> Select **Markdown PDF: Export (pdf)**.

### Option C: Using Chrome / Edge Browser
1. Render this markdown file in any browser or viewer.
2. Press `Ctrl + P` -> Select **Save as PDF** -> Set margins to Normal.
