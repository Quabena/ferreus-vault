/**
 * features/vault/EntryModal.tsx
 *
 * Modal dialog for creating a new entry or editing an existing one.
 *
 * When `entry` is null, the modal is in "add" mode.
 * When `entry` is provided, it is in "edit" mode.
 *
 * The password field is write-only from the frontend's perspective:
 * - In add mode, the user types a new password and it is sent to the backend.
 * - In edit mode, the field starts empty; leaving it empty means "keep existing".
 *   If the user types a new value, it replaces the existing one.
 *
 * The password is NEVER stored in component state beyond the duration of this
 * form interaction. It is moved into the IPC call and then the field is cleared.
 */

import { useRef, useEffect, type FormEvent, type KeyboardEvent } from "react";
import { useState } from "react";
import type { EntryView } from "../../lib/api";
import { useVault } from "./useVault";
import "../../styles/EntryModal.css";

interface EntryModalProps {
  entry: EntryView | null; // null = add mode
  onClose: () => void;
}

const PASSWORD_CHARS =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";

function generatePassword(length = 20) {
  const values = new Uint32Array(length);
  window.crypto.getRandomValues(values);
  return Array.from(
    values,
    (value) => PASSWORD_CHARS[value % PASSWORD_CHARS.length],
  ).join("");
}

export function EntryModal({ entry, onClose }: EntryModalProps) {
  const isEdit = entry !== null;
  const { addEntry, updateEntry, isLoading } = useVault();

  const [accountName, setAccountName] = useState(entry?.account_name ?? "");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [password, setPassword] = useState(""); // always starts empty
  const [notes, setNotes] = useState(entry?.notes ?? "");
  const [showPw, setShowPw] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const firstInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstInputRef.current?.focus();
  }, []);

  // Close on Escape
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape") onClose();
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!accountName.trim()) {
      setLocalError("Account name is required.");
      return;
    }

    try {
      if (isEdit) {
        await updateEntry(
          entry.index,
          accountName.trim(),
          username.trim(),
          // Only send password if user typed one; null = keep existing
          password.length > 0 ? password : undefined,
          notes.trim(),
        );
      } else {
        if (password.length === 0) {
          setLocalError("Password is required for a new entry.");
          return;
        }
        await addEntry(
          accountName.trim(),
          username.trim(),
          password,
          notes.trim(),
        );
      }
      // Clear password field before closing
      setPassword("");
      onClose();
    } catch (e) {
      setLocalError(String(e));
    }
  };

  const handleGeneratePassword = () => {
    setPassword(generatePassword());
    setShowPw(true);
    setLocalError(null);
  };

  return (
    <>
      {/* Backdrop */}
      <div className="modal-backdrop" onClick={onClose} aria-hidden="true" />

      <div
        className="modal-panel animate-scale-in"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        onKeyDown={handleKeyDown}
      >
        <div className="modal-header">
          <h2 className="modal-title text-display" id="modal-title">
            {isEdit ? "Edit entry" : "New entry"}
          </h2>
          <button
            className="fv-btn-icon modal-close"
            onClick={onClose}
            aria-label="Close"
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <form className="modal-form" onSubmit={handleSubmit} noValidate>
          {/* Account name */}
          <div className="modal-field">
            <label className="modal-label" htmlFor="m-account">
              Account / service
            </label>
            <input
              id="m-account"
              ref={firstInputRef}
              className="fv-input"
              type="text"
              value={accountName}
              onChange={(e) => setAccountName(e.target.value)}
              placeholder="e.g. GitHub"
              disabled={isLoading}
              required
            />
          </div>

          {/* Username */}
          <div className="modal-field">
            <label className="modal-label" htmlFor="m-username">
              Username / email
            </label>
            <input
              id="m-username"
              className="fv-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="user@example.com"
              autoComplete="username"
              disabled={isLoading}
            />
          </div>

          {/* Password */}
          <div className="modal-field">
            <div className="modal-label-row">
              <label className="modal-label" htmlFor="m-password">
                {isEdit ? "New password" : "Password"}
              </label>
              <button
                type="button"
                className="modal-generate-btn"
                onClick={handleGeneratePassword}
                disabled={isLoading}
                title="Generate strong password"
              >
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M21 12a9 9 0 11-2.64-6.36" />
                  <path d="M21 3v6h-6" />
                </svg>
                Generate
              </button>
            </div>
            <div className="modal-pw-wrap">
              <input
                id="m-password"
                className="fv-input"
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isEdit ? "Leave blank to keep current" : "Required"}
                autoComplete={isEdit ? "new-password" : "new-password"}
                disabled={isLoading}
                required={!isEdit}
              />
              <button
                type="button"
                className="fv-btn-icon modal-eye"
                onClick={() => setShowPw((p) => !p)}
                tabIndex={-1}
                aria-label={showPw ? "Hide" : "Show"}
              >
                {showPw ? (
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
                    <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                ) : (
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          {/* Notes */}
          <div className="modal-field">
            <label className="modal-label" htmlFor="m-notes">
              Notes (optional)
            </label>
            <textarea
              id="m-notes"
              className="fv-input modal-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Recovery codes, 2FA info, etc."
              rows={3}
              disabled={isLoading}
            />
          </div>

          {localError && (
            <div className="fv-error animate-fade-in" role="alert">
              {localError}
            </div>
          )}

          <div className="modal-actions">
            <button
              type="button"
              className="fv-btn fv-btn-ghost"
              onClick={onClose}
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="fv-btn fv-btn-primary"
              disabled={isLoading || accountName.trim().length === 0}
            >
              {isLoading ? (
                <span className="unlock-spinner" aria-label="Saving…" />
              ) : isEdit ? (
                "Save changes"
              ) : (
                "Add entry"
              )}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}
