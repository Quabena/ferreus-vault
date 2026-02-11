# Ferreus Vault

**High-Assurance Offline Password Vault**

**Forged in iron. Built for privacy.**

Ferreus Vault is a **security-focused, offline password vault** designed for users who
prioritize control, auditability, and minimal attack surface over convenience features.

This software **never connects to the internet** — by design, not by configuration.

---

## Philosophy

### What Ferreus Vault _Is_

- **Offline-only** — no network access, no cloud sync, no telemetry
- **Memory-safe** — written in Rust with a strict security posture
- **Minimal** — fewer features, fewer attack surfaces
- **Transparent** — open source and auditable
- **Disciplined** — security through deliberate exclusion

### What Ferreus Vault _Is Not_

- A cloud password manager
- A multi-device sync solution
- A recovery-based system
- A convenience-first product

If you forget your master password, **your data cannot be recovered**.

---

## Threat Model (Explicit)

Ferreus Vault is designed to protect against:

- Theft of the encrypted vault file
- Offline brute-force attacks
- Accidental plaintext exposure

Ferreus Vault does **not** protect against:

- A fully compromised operating system
- Keyloggers or screen capture malware
- Physical access while the vault is unlocked

Security guarantees apply **only** within this threat model.

---

## Security Architecture

### Core Principles

| Principle       | Implementation                                 |
| --------------- | ---------------------------------------------- |
| Zero Network    | Network APIs disabled at build and runtime     |
| Least Privilege | Minimal OS permissions, no background services |
| Fail Secure     | Immediate memory wipe on error or lock         |
| No Recovery     | Forgotten password = permanent data loss       |
| Auditability    | Simple architecture, no hidden components      |

---

### Cryptographic Stack

Ferreus Vault uses **no custom cryptography**.

| Component      | Implementation            |
| -------------- | ------------------------- |
| Key Derivation | Argon2id (memory-hard)    |
| Encryption     | XChaCha20-Poly1305        |
| Randomness     | OS-provided CSPRNG        |
| Memory Wiping  | `zeroize`                 |
| Key Storage    | RAM-only, never persisted |

All vault contents are encrypted as **one opaque payload**.  
No plaintext metadata is stored.

---

## Architecture Overview

Master Password
↓
Argon2id (memory-hard KDF)
↓
Vault Key (RAM only)
↓
XChaCha20-Poly1305
↓
Encrypted Vault File (.sark)

- Single-process desktop application
- No IPC
- No background services
- No temporary plaintext files

---

## MVP Scope (Intentionally Limited)

### Included

- Vault creation with master password
- Encrypted credential storage
- Manual and automatic locking
- Clipboard auto-clear
- Immediate memory zeroization on exit

### Explicitly Excluded

- Cloud sync
- Browser extensions
- Account recovery
- Telemetry or analytics
- Auto-update mechanisms
- Password sharing

Restraint is a **security feature**.

---

## Installation

### Pre-built Binaries

Download from GitHub Releases and verify checksums before use.

```bash
shasum -a 256 ferreus_vault_*.tar.gz
Build From Source
Requirements

Rust (stable)

Tauri toolchain

Platform system dependencies

git clone https://github.com/Quabena/ferreus-vault.git
cd ferreus-vault
cargo tauri build --release
Only build from source if you understand the implications.

Usage Notes
Choose a strong master password

Maintain regular encrypted backups

Lock the vault when unattended

Keep your operating system secure

Ferreus Vault assumes a competent and cautious user.

Verification (For Advanced Users)
You may independently verify:

No network activity at runtime

File permissions of the vault file

Absence of unsafe Rust code

Dependency security status

See SECURITY.md for details.

License
Source code is licensed under:

GPL-3.0-only
See the LICENSE file for full terms.

Trademark
“Ferreus Vault” is a protected trademark.

Forks are permitted.
Impersonation is not.

See TRADEMARK.md for details.

Security Reporting
If you discover a vulnerability:

Do not open a public issue

Follow the responsible disclosure process in SECURITY.md

Contributions
Contributions are welcome only if they align with the security model.

By contributing, you agree to the terms in CLA.md.

Features that increase attack surface will not be accepted.

Final Note
Ferreus Vault exists for a specific audience:

People who value control over convenience
and security over features.

Trust is earned by what software refuses to do.
```
