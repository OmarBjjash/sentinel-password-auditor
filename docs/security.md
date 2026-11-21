# Security & Privacy Policy — Sentinel Password Auditor

## 1. Principles of Defensive Auditing

**Sentinel Password Auditor** is engineered strictly as a defensive auditing and policy compliance tool. It adheres to standard computer security ethics and defensibility requirements.

---

## 2. Key Defensive Safeguards

### 2.1 Read-Only File System Access
- On Linux, `/etc/shadow` is opened strictly using read-only mode (`open(SHADOW_PATH, "r")` / `os.O_RDONLY`).
- The application possesses no functionality or methods to modify `/etc/shadow`, reset user passwords, or alter account configuration files.
- The tool does not modify Windows SAM databases or registry settings.

### 2.2 Authorized Security Boundaries on Windows
- Sentinel explicitly rejects unauthorized memory-dumping or unprivileged credential extraction techniques (such as LSASS memory dumping or registry SAM extraction).
- Windows auditing is restricted to administrator-provided, authorized hash lists formatted as `username:NTLM_HASH`.
- If an authorized hash file is unavailable, the application provides clear educational guidance on administrative export procedures rather than attempting unprivileged bypasses.

### 2.3 Zero Credential Retention Policy
- **No Disk Logging:** Passwords entered into the Interactive Password Checker are never written to disk, cached in temporary files, or stored in system logs.
- **No Report Exposure:** Exported PDF and JSON reports explicitly exclude plaintext passwords and raw cryptographic hashes. Reports include only username, detected algorithm, pass/fail status, and remediation recommendations.
- **Volatile In-Memory Processing:** System hashes and dictionary lookups exist solely in volatile process memory and are deallocated upon garbage collection.

### 2.4 Offline Operation & Network Isolation
- Sentinel Password Auditor operates 100% locally.
- It makes no outbound network requests, sends no telemetry, and transmits no credential material to external services or online APIs.
- The tool can be run completely isolated in air-gapped environments.

---

## 3. Remediation Recommendations

When an account is flagged with `WEAK_PASSWORD`, administrators should:
1. **Mandate Reset:** Enforce an immediate password reset on next login.
2. **Educate Users:** Guide users on passphrase creation (e.g., Diceware passphrases).
3. **Upgrade Hashing:** Migrate legacy Unix DES or MD5 hashes to SHA-512 crypt or yescrypt.
4. **Deploy MFA:** Implement multi-factor authentication across all endpoints.
