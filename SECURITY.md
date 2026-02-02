# Security Policy — Ferreus Vault

## Project Scope

Ferreus Vault is an **offline, desktop password vault** designed to:

- Never connect to the internet
- Minimize attack surface
- Use modern, audited cryptography
- Be simple enough to audit

Security is a primary design constraint, not a feature.

---

## Supported Versions

Only the **latest released version** of Ferreus Vault is supported.

Older versions may contain known vulnerabilities and should not be used
to store sensitive data.

---

## Threat Model (Explicit)

Ferreus Vault is designed to protect against:

- Offline theft of the encrypted vault file
- Opportunistic malware reading files at rest
- Accidental credential disclosure

Ferreus Vault does NOT protect against:

- A fully compromised operating system
- Keyloggers or screen capture malware
- Physical access while the vault is unlocked

Users are expected to maintain a secure OS environment.

---

## Cryptography Overview

Ferreus Vault uses **no custom cryptography**.

- Key Derivation: Argon2id
- Encryption: XChaCha20-Poly1305
- Randomness: OS-provided CSPRNG
- Memory wiping: `zeroize`

All vault contents are encrypted as a single unit.
No plaintext metadata is stored.

---

## Responsible Disclosure

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Email the security contact with:
   - Description of the issue
   - Steps to reproduce (if applicable)
   - Potential impact

Email: web4adu@gmail.com

We aim to acknowledge reports within **72 hours**.

---

## Disclosure Policy

- Confirmed vulnerabilities will be fixed as quickly as possible
- Public disclosure will occur **after a fix is available**
- Credit will be given to reporters unless anonymity is requested

---

## Build & Runtime Guarantees

- Network access is disabled by design
- No telemetry, analytics, or auto-updates
- Single-process architecture
- Minimal system permissions

Any deviation from these guarantees is considered a security defect.

---

## Final Note

Ferreus Vault favors **discipline over convenience**.

If a feature increases attack surface, it does not belong in this project.
