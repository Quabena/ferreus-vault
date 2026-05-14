/**
 * Shown when a vault file exists but is locked. Renders a password input
 * and calls `unlock` on the store. Also acts as the "create vault" screen
 * when no vault exists yet.
 */

import { useState, useRef, useEffect } from "react";
import { useVaultStore } from "../../state/vaultStore";
import "../../styles/UnlockScreen.css";

export function UnlockScreen() {
  const vaultExists = useVaultStore((s) => s.vaultExists);
  const isLoading = useVaultStore((s) => s.isLoading);
  const error = useVaultStore((s) => s.error);
  const unlock = useVaultStore((s) => s.unlock);
  const createVault = useVaultStore((s) => s.createVault);
  const clearError = useVaultStore((s) => s.clearError);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const isCreating = !vaultExists;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Clear errors when user types
  const handlePasswordChange = (v: string) => {
    setPassword(v);
    setLocalError(null);
    clearError();
  };

  // FIX 1: Correct event handler type; FIX 4: submit logic moved inside handler
  const handleSubmit: React.FormEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();
    setLocalError(null);

    if (isCreating) {
      if (password.length < 12) {
        setLocalError("Password must be at least 12 characters.");
        return;
      }
      if (password !== confirm) {
        setLocalError("Passwords do not match.");
        return;
      }
      try {
        await createVault(password);
        // Unlock immediately after creation
        await unlock(password);
      } catch {
        // error already in store
      }
    } else {
      try {
        await unlock(password);
      } catch {
        // error already in store
      }
    }

    // Clear the password from local state after the call
    setPassword("");
    setConfirm("");
  };

  // FIX 5: moved inside the component
  const displayError = localError ?? error;

  // FIX 5: return statement moved inside the component
  return (
    <div className="unlock-root">
      {/* Background Texture */}
      <div className="unlock-bg" aria-hidden="true">
        <div className="unlock-bg__grid" />
        <div className="unlock-bg__vignette" />
      </div>

      <div className="unlock-panel animate-scale-in">
        {/* Logo Mark */}
        <div className="unlock-logomark" aria-hidden="true">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <rect
              x="6"
              y="10"
              width="36"
              height="28"
              rx="3"
              stroke="var(--copper)"
              strokeWidth="2"
            />
            <rect
              x="14"
              y="18"
              width="20"
              height="14"
              rx="2"
              stroke="var(--copper-bright)"
              strokeWidth="1.5"
            />
            <circle cx="24" cy="25" r="3" fill="var(--copper)" />
            <line
              x1="24"
              y1="28"
              x2="24"
              y2="32"
              stroke="var(--copper)"
              strokeWidth="1.5"
            />
          </svg>
        </div>

        <h1 className="unlock-title text-display">
          {isCreating ? "Create Vault" : "Ferreus Vault"}
        </h1>

        <p className="unlock-subtitle">
          {isCreating
            ? "Choose a strong master password to protect your vault."
            : "Enter your master password to unlock."}
        </p>

        <form className="unlock-form" onSubmit={handleSubmit} noValidate>
          {/* Password */}
          <div className="unlock-field">
            {/* FIX 6: typo "unlock-lable" → "unlock-label" */}
            <label htmlFor="master-password" className="unlock-label">
              {isCreating ? "Master Password" : "Password"}
            </label>
            <div className="unlock-input-wrap">
              <input
                id="master-password"
                ref={inputRef}
                className="fv-input unlock-input"
                type={showPw ? "text" : "password"}
                value={password}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder={isCreating ? "12+ characters" : "Enter Password"}
                autoComplete={isCreating ? "new-password" : "current-password"}
                disabled={isLoading}
                required
              />
              <button
                type="button"
                className="fv-btn-icon unlock-eye"
                onClick={() => setShowPw((p) => !p)}
                aria-label={showPw ? "Hide password" : "Show password"}
                tabIndex={-1}
              >
                {showPw ? (
                  <svg
                    width="16"
                    height="16"
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
                    width="16"
                    height="16"
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

          {/* Confirm (create only) */}
          {isCreating && (
            <div className="unlock-field animate-fade-in">
              <label htmlFor="confirm-password" className="unlock-label">
                Confirm password
              </label>
              <input
                id="confirm-password"
                className="fv-input unlock-input"
                type={showPw ? "text" : "password"}
                value={confirm}
                onChange={(e) => {
                  setConfirm(e.target.value);
                  setLocalError(null);
                }}
                placeholder="Repeat password"
                autoComplete="new-password"
                disabled={isLoading}
                required
              />
            </div>
          )}

          {/* Error */}
          {displayError && (
            <div className="fv-error animate-fade-in" role="alert">
              {displayError}
            </div>
          )}

          {/* FIX 2: was `getPassword.length` (function length), now `password.length` */}
          <button
            type="submit"
            className="fv-btn fv-btn-primary unlock-submit"
            disabled={isLoading || password.length === 0}
          >
            {isLoading ? (
              <span className="unlock-spinner" aria-label="Working..." />
            ) : isCreating ? (
              "Create vault"
            ) : (
              "Unlock"
            )}
          </button>
        </form>

        <p className="unlock-footer">
          {isCreating
            ? "Your vault is stored locally and never leaves this device."
            : "Vault is stored locally on this device"}
        </p>
      </div>
    </div>
  );
}
