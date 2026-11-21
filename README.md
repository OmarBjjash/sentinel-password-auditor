# Sentinel Password Auditor

[![Python Version](https://img.shields.io/badge/python-3.12%20--%203.15-blue.svg)](https://www.python.org/)
![Security](https://img.shields.io/badge/Purpose-Defensive%20Security-green)
[![LICENSE](https://img.shields.io/github/license/OmarBjjash/sentinel-password-auditor)](https://github.com/OmarBjjash/sentinel-password-auditor/blob/main/LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/tests-101%20passed-brightgreen.svg)]()
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter%20(Dark%20%26%20Light)-blueviolet.svg)]()
[![Standalone](https://img.shields.io/badge/build-.exe%20%7C%20.AppImage-orange.svg)]()

> **A defensive password auditing and security assessment application that enables system administrators to identify weak local accounts across Linux and Windows systems and empowers users to evaluate candidate passwords against common password leaks.**

> [!WARNING]
> **Disclaimer:**
> This tool is intended for educational and authorized defensive security purposes only. Use it only on systems you own or have explicit permission to audit. The developers are not responsible for misuse or unauthorized activities.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Standalone Binaries (Executable Builds)](#standalone-binaries-executable-builds)
  - [Windows Single Executable (.exe)](#windows-single-executable-exe)
  - [Linux Universal AppImage (.AppImage)](#linux-universal-appimage-appimage)
- [Usage Instructions](#usage-instructions)
  - [Launching the GUI](#launching-the-gui)
  - [Theme & Appearance (Dark & Light Mode)](#theme--appearance-dark--light-mode)
  - [Linux System Auditing (Mode A & Mode B)](#linux-system-auditing)
  - [Windows System Auditing (Mode A & Mode B)](#windows-system-auditing)
  - [Interactive Password Checker](#interactive-password-checker)
  - [Report Generation (PDF & JSON)](#report-generation)
- [Security & Privacy Guarantees](#security--privacy-guarantees)
- [Testing & Validation](#testing--validation)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

Password security remains one of the primary vulnerabilities exploited by threat actors during initial access and lateral movement. **Sentinel Password Auditor** is engineered as a defensive, read-only security assessment suite designed to:

1. **Audit Local Linux Accounts:** Inspect real `/etc/shadow` files or imported shadow exports to detect accounts utilizing weak or dictionary passwords without compromising cryptographic salts.
2. **Audit Windows Local Accounts:** Safely extract and audit local SAM account hashes in-memory on live systems, or validate authorized NTLM hash exports (pwdump, LM:NT, username:NTLM, raw hashes).
3. **Interactive Password Strength Assessment:** Allow unprivileged users to evaluate candidate passwords in a masked interface with immediate entropy scoring, pattern detection, and policy compliance feedback.
4. **Professional Audit Reporting:** Generate executive-ready PDF compliance reports and structured JSON exports sanitized of all sensitive credentials.
5. **Portable Packaging:** Distribute as a zero-dependency standalone Windows executable (`.exe`) or universal Linux `.AppImage`.

---

## Key Features

- **Linux Local Account Auditing:**
  - **Mode A (Live `/etc/shadow`):** Read-only inspection of the active system shadow database (requires `root` or `shadow` group membership).
  - **Mode B (Shadow File Import):** Offline audit of authorized `/etc/shadow` file copies, backups, or container mounts without requiring root privileges.
  - **Comprehensive Hash Algorithm Support:**
    - **SHA-512 crypt (`$6$`)** and **SHA-256 crypt (`$5$`)**
    - **yescrypt (`$y$`)** (fully supported cross-platform on both Linux and Windows via `pyescrypt`)
    - **bcrypt (`$2a$`, `$2b$`, `$2y$`)**
    - **MD5 crypt (`$1$`)** and legacy **DES crypt**
  - Safely skips locked accounts (`!`, `*`) and expired or empty password entries.

- **Windows Local Account Auditing:**
  - **Mode A (Live Local SAM Audit):** Live in-memory audit of local accounts via authorized administrative Registry hive acquisition (`SAM` and `SYSTEM`), decrypting syskey and SAM hashes strictly in volatile memory (requires Administrator privileges).
  - **Mode B (Authorized Hash Import):** Multi-format parser supporting `pwdump` formats (`username:RID:LM:NTLM:::`, `LM:NTLM`), `username:NTLM_HASH`, and raw 32-character hexadecimal NTLM hashes.
  - Pre-computed NTLM hash lookup table for $O(1)$ batch comparison across large dictionaries.

- **Clean, Human-Centric Interface & Dual Theming:**
  - **Dark & Light Themes:** Instant toggle between Dark, Light, and System appearance modes with high-contrast accessibility.
  - **Responsive Scrollable Layout:** Fully responsive `CTkScrollableFrame` containers ensuring the results table and audit cards remain accessible on small laptop displays (min resolution 820x480).
  - **Jitter-Free Status Indicator:** Live progress monitoring (`[username] 28% ( 28/100) | current status: "..."`) with fixed-width formatting and stationary progress bars to eliminate UI layout jumps or double-header artifacts.

- **Interactive Password Checker & Policy Engine:**
  - Masked password input field with show/hide toggle.
  - Case-insensitive $O(1)$ dictionary lookup against loaded wordlist.
  - Multi-dimensional strength assessment (Shannon entropy, character diversity, sequential patterns, keyboard walks, repeated characters, and leetspeak substitution detection).
  - Configurable password policy compliance analyzer (length, complexity, dictionary exposure).

- **Enterprise Reporting:**
  - Professional PDF security reports generated via ReportLab (executive summary, account findings table, remediation recommendations, and security notices).
  - Sanitized JSON exports structured for SIEM integration or compliance archiving.
  - Complete zero-retention guarantee: no plaintext passwords or raw hashes are ever logged or exported.

---

## System Architecture

```text
                           Sentinel Password Auditor
                                      |
         +----------------------------+----------------------------+
         |                                                         |
   Linux Auditor                                            Windows Auditor
         |                                                         |
  +------+------+                                           +------+------+
  |             |                                           |             |
Mode A:       Mode B:                                     Mode A:       Mode B:
Live /etc/    Shadow File                                 Live SAM/     Authorized Hash
shadow        Importer                                    SYSTEM Hives  Export (pwdump/NTLM)
  |             |                                           |             |
  +------+------+                                           +------+------+
         |                                                         |
         +----------------------------+----------------------------+
                                      |
                                Audit Engine
                                      |
                              Password Hasher
           (yescrypt, bcrypt, sha512_crypt, sha256_crypt, md5_crypt, NTLM)
                                      |
                             Dictionary Manager
                             (O(1) Set / NTLM Map)
                                      |
                                Audit Results
                                      |
                         +------------+------------+
                         |                         |
                    GUI Results               PDF / JSON
                (Dark/Light Display)     Sanitized Compliance Reports
```

```text
User Input -> Masked Field -> Password Checker -> Dictionary Manager (O(1)) -> Policy Analyzer -> Immediate Feedback
```

For detailed architectural diagrams and data flow documentation, see [`docs/architecture.md`](docs/architecture.md) and [`docs/architecture_diagram.pdf`](docs/architecture_diagram.pdf).

---

## Requirements

- **Python:** 3.12, 3.13, 3.14, or 3.15.
- **Operating Systems:**
  - **Linux:** Ubuntu 22.04+, Debian 12+, RHEL 9+, Arch Linux, Fedora.
  - **Windows:** Windows 10, Windows 11, Windows Server 2019/2022/2025.
- **Python Libraries:**
  - `customtkinter >= 5.2.0` (Modern dual-theme GUI framework)
  - `reportlab >= 4.0.0` (PDF report and compliance documentation)
  - `passlib >= 1.7.4` (Unix crypt verification)
  - `bcrypt >= 4.0.0` (Bcrypt verification)
  - `pyescrypt >= 1.0.0` (Yescrypt hash verification across Linux and Windows)
  - `cryptography >= 41.0.0` (Windows SAM decryption and cryptographic primitives)
  - `python-registry >= 1.4.0` (Offline/in-memory SAM and SYSTEM registry hive parsing)
  - `Pillow >= 10.0.0` (Image handling and UI icon rendering)
  - `pytest >= 7.4.0` (Automated testing suite)

---

## Installation

### Standard Python Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/OmarBjjash/sentinel-password-auditor.git
   cd sentinel-password-auditor
   ```

2. **Create and activate a virtual environment:**
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - **Windows:**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Standalone Binaries (Executable Builds)

Sentinel Password Auditor can be compiled into completely self-contained, zero-dependency executable packages for distribution.

### Windows Single Executable (`.exe`)

The Windows executable bundles Python, CustomTkinter themes, dictionaries, and cryptographic extensions (including Rust-backed `cryptography` and `python3t.dll` compatibility) into a single portable binary.

1. **Install build requirements:**
   ```powershell
   pip install -r requirements.txt pyinstaller
   ```

2. **Build using the optimized spec file:**
   ```powershell
   pyinstaller sentinel-password-checker.spec --noconfirm
   ```

3. **Run the standalone executable:**
   ```powershell
   .\dist\sentinel-password-checker.exe
   ```

> [!NOTE]
> To run **Mode A (Live Local SAM Audit)**, right-click `sentinel-password-checker.exe` and select **"Run as administrator"**.

---

### Linux Universal AppImage (`.AppImage`)

The AppImage package runs on any modern 64-bit Linux distribution (Ubuntu, Debian, Fedora, Arch, RHEL) without requiring Python or system libraries to be pre-installed.

1. **Prerequisites (Linux build machine):**
   ```bash
   sudo apt update && sudo apt install -y python3-venv python3-pip curl file
   ```

2. **Run the automated build script:**
   ```bash
   chmod +x build_appimage.sh
   ./build_appimage.sh
   ```

   The script automatically:
   - Downloads `appimagetool` if not already installed.
   - Creates an isolated build virtual environment and installs all dependencies.
   - Generates the PyInstaller bundle with bundled shared libraries (`libcrypt.so`, etc.).
   - Assembles the standard AppDir directory structure with Desktop Entry and icon.
   - Compiles `dist/Sentinel_Password_Auditor-x86_64.AppImage`.

3. **Run the AppImage:**
   ```bash
   chmod +x dist/Sentinel_Password_Auditor-x86_64.AppImage
   ./dist/Sentinel_Password_Auditor-x86_64.AppImage
   ```

   To run Live `/etc/shadow` audits:
   ```bash
   sudo ./dist/Sentinel_Password_Auditor-x86_64.AppImage
   ```

---

## Usage Instructions

### Launching the GUI

Start the graphical interface:

```bash
python main.py
```

The GUI consists of four main views accessible via the sidebar navigation:
- **Dashboard:** System health, OS detection, elevation status, dictionary load statistics, and audit history.
- **System Audit:** Run Linux or Windows account audits (both Live and Import modes).
- **Password Checker:** Securely evaluate candidate passwords against policies and dictionaries.
- **Audit Reports:** Preview sanitized JSON audit data and export official PDF compliance reports.

---

### Theme & Appearance (Dark & Light Mode)

Switch themes seamlessly using the **Appearance Mode** dropdown in the lower-left sidebar:
- **Dark Mode:** High-contrast cybersecurity theme optimized for low-light environments.
- **Light Mode:** Crisp, clean corporate reporting theme with accessible contrast borders and readable button styling.
- **System:** Automatically synchronizes with your operating system's light/dark preference.

---

### Linux System Auditing

Sentinel provides two independent auditing workflows for Linux systems:

#### Mode A: Real Live `/etc/shadow` Audit (Root Required)
Directly audits local accounts on the active Linux machine.

- **GUI Execution:**
  ```bash
  sudo .venv/bin/python main.py
  ```
  1. Navigate to **System Audit** -> **Linux Audit**.
  2. In the **Mode A (Live /etc/shadow)** card, click **Start Live Linux Audit**.
  3. View real-time progress (`[user] 28% (28/100) | current status: "..."`) and account findings.

- **CLI Execution:**
  ```bash
  sudo python main.py --audit-linux --export-pdf linux_report.pdf --export-json linux_report.json
  ```

#### Mode B: Shadow File Importer (No Root Required)
Safely audit an offline copy of `/etc/shadow` (e.g. from a server backup, container image, or authorized audit artifact).

- **GUI Execution:**
  1. Navigate to **System Audit** -> **Linux Audit**.
  2. In the **Mode B (Import Shadow File)** card, click **Browse Shadow File...** and select your file.
  3. Click **Start Shadow File Audit**.

- **CLI Execution:**
  ```bash
  python main.py --audit-linux-file /path/to/shadow --export-pdf shadow_report.pdf --export-json shadow_report.json
  ```

---

### Windows System Auditing

Sentinel provides two distinct Windows auditing modes modeled after enterprise credential assessment workflows:

#### Mode A: Real Live Local SAM Audit (Administrator Required)
Directly audits local user accounts on the active Windows system. It acquires the `SAM` and `SYSTEM` registry hives using authorized Windows backup APIs, derives the syskey, decrypts user NTLM hashes in-memory, and matches them against `wordlist.txt`.

- **GUI Execution:**
  Launch PowerShell or CMD as Administrator, then:
  ```powershell
  python main.py
  ```
  Navigate to **System Audit** -> **Windows Audit** -> Mode A -> click **Start Local SAM Audit**.

- **CLI Execution:**
  ```powershell
  # In an elevated Administrator terminal:
  python main.py --audit-windows-sam --export-pdf windows_sam_report.pdf --export-json windows_sam_report.json
  ```
- **Zero Retention:** Hive copies are removed from disk immediately after in-memory parsing, and raw decrypted hashes are never stored in reports or logs.

#### Mode B: Authorized Hash Export Import
For environments without administrator rights or when evaluating password dumps from authorized external audits:

1. Prepare a text file containing NTLM hashes. Supported formats include:
   - **pwdump / fgdump format:**
     ```text
     Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C:::
     jdoe:1001:aad3b435b51404eeaad3b435b51404ee:E19CCF750465A06B4D603A684D4511A8:::
     ```
   - **username:NTLM format:**
     ```text
     administrator:8846F7EAEE8FB117AD06BDD830B7586C
     jdoe:E19CCF750465A06B4D603A684D4511A8
     ```
   - **LM:NTLM or raw 32-character hex hashes:**
     ```text
     aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C
     8846F7EAEE8FB117AD06BDD830B7586C
     ```

2. **GUI Execution:**
   Navigate to **System Audit** -> **Windows Audit** -> Mode B -> click **Browse Hash File...** -> click **Start Hash File Audit**.

3. **CLI Execution:**
   ```bash
   python main.py --audit-windows sample_hashes.txt --export-pdf windows_report.pdf --export-json windows_report.json
   ```

---

### Interactive Password Checker

The Password Checker functions independently of administrative privileges and tests candidate passwords in real-time.

#### GUI Mode:
1. Navigate to **Password Checker**.
2. Type a candidate password in the masked field. Click **Show** to inspect plaintext if desired.
3. Click **Check Password** or press **Enter**.
4. Review the calculated score (0-100), strength classification, dictionary breach status, and policy breakdown.

#### CLI Mode:
```bash
python main.py --check "P@ssw0rd2026!"
```

---

### Report Generation

Reports can be exported directly from the GUI **Audit Reports** tab or via CLI flags:

- **PDF Compliance Report:** Formats an executive summary, metrics cards, account findings table (with color-coded risk tags), remediation guidance, and formal legal notices.
- **JSON Structured Report:** Generates clean, sanitized JSON suitable for programmatic ingestion into SIEM platforms, ticket queues, or compliance archives.

---

## Security & Privacy Guarantees

- **Zero Secret Retention:** Plaintext passwords entered into the checker and raw NTLM hashes are never written to disk, logged to the console, or exported into reports.
- **Read-Only Access:** The application strictly opens system files with read-only access and never modifies `/etc/shadow`, SAM registry keys, or user credentials.
- **Volatile In-Memory Matching:** Candidate comparison and pre-computed tables exist solely in volatile process memory and are released upon completion.
- **Sanitized Outputs:** PDF and JSON reports contain account usernames, hashing algorithms, and remediation guidance, but explicitly exclude credential secrets.

For full details, review [`docs/security.md`](docs/security.md).

---

## Testing & Validation

The project includes an extensive automated test suite of **101 unit and integration tests** utilizing `pytest`.

Run all tests:

```bash
pytest
```

Run unit tests only (excluding integration tests requiring elevated system access):

```bash
pytest -m "not integration"
```

Verify all 13 core modules:

```bash
python test_all.py
```

Test suite coverage breakdown:
- `test_password_checker.py`: Dictionary detection, case-insensitivity, whitespace, entropy scoring, repeated/sequential penalties.
- `test_password_hasher.py`: NTLM RFC-compliant hashing, prefix identification, passlib/bcrypt verification, and cross-platform yescrypt support.
- `test_dictionary_manager.py`: Singleton lifecycle, encoding resilience (UTF-8 BOM), memory efficiency, and lookup performance.
- `test_linux_auditor.py`: Shadow parsing, locked account skipping, permission handling.
- `test_linux_shadow_importer.py`: Offline shadow format parsing, salt extraction, yescrypt/sha512/bcrypt evaluation.
- `test_windows_sam.py`: Administrator privilege detection, hive acquisition, syskey decryption, in-memory cleanup.
- `test_windows_auditor.py`: NTLM hash validation, pwdump parser, malformed record handling, batch lookup matching.
- `test_reports.py`: Sanitization verification, JSON schema validation, and PDF generation.

---

## Known Limitations

1. **Elevation Requirements for Live Auditing:** Direct live auditing of `/etc/shadow` (Linux) and Local SAM registry hives (Windows) requires elevated privileges (`root` or `Administrator`) by design of the host operating system's security model. Users without administrative privileges should utilize **Mode B (Import Mode)** on both platforms.
2. **Dictionary-Bound Auditing:** Sentinel Password Auditor is designed as a defensive policy and compliance auditor. It evaluates account susceptibility against common dictionaries (`wordlist.txt`) and does not perform distributed unconstrained brute-force cracking.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
