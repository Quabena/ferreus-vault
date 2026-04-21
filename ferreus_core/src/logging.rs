// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferreus Vault Contributors
//
// This file is part of Ferreus Vault.
//
// Ferreus Vault is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 only,
// as published by the Free Software Foundation.
//
// Ferreus Vault is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

//! Security event logging for FerreusVault.
//!
//! All security-relevant events (vault unlock, lock, failed attempts, lockout)
//! are routed through this module so that a future integration with a syslog
//! backend, rotating file appender, or SIEM forwarder requires changes in
//! exactly one place.
//!
//! # Current implementation
//! Events are emitted via the [`log`] crate at the `warn` level. The calling
//! binary is responsible for initialising a log subscriber (e.g. `env_logger`,
//! `tracing-subscriber`). Until a subscriber is registered, events are silently
//! discarded — this is the standard behaviour of the `log` façade.
//!
//! # Event format
//! ```text
//! [FERREUS_SECURITY] <ISO-8601 timestamp> | <event message>
//! ```
//! The prefix and timestamp are added by this module; callers supply only the
//! message string.
//!
//! # Future work
//! - Integrate a structured logging backend (e.g., `tracing` with JSON output)
//!   for machine-parseable SIEM ingestion.
//! - Add event severity levels (INFO / WARN / CRIT) to allow fine-grained
//!   alerting rules.
//! - Consider a rate limiter to prevent log flooding under an active attack.

use chrono::Utc;

/// Emits a structured security audit event at the `warn` log level.
///
/// Events are intended for security-relevant transitions: vault unlock/lock,
/// failed authentication attempts, lockout imposition, and session lifecycle.
///
/// Callers should pass a concise, machine-readable message without embedded
/// newlines. Sensitive values (passwords, key bytes) must **never** appear in
/// the message string.
///
/// # Example
/// ```ignore
/// log_security_event("vault unlocked: session=abc123");
/// log_security_event("unlock failed: attempt 3 of 5");
/// log_security_event("hard lockout imposed: 30s");
/// ```
pub fn log_security_event(event: &str) {
    let timestamp = Utc::now().to_rfc3339();
    log::warn!("[FERREUS_SECURITY] {} | {}", timestamp, event);
}

/// Emits a debug-level diagnostic event.
///
/// Use for non-security operational events (e.g., vault saved, entry added).
/// These are suppressed at most log levels in production; enable the `debug`
/// log level only when diagnosing issues in a controlled environment.
///
/// # Security note
/// Even at the debug level, callers must not include sensitive data (passwords,
/// key material, or plaintext entry content) in the event string.
pub fn log_debug_event(event: &str) {
    let timestamp = Utc::now().to_rfc3339();
    log::debug!("[FERREUS_DEBUG] {} | {}", timestamp, event);
}
