/**
 * Header bar widget showing:
 *  - Current autolock timeout with an inline editor
 *  - A manual "Lock Now" button
 *
 * Rendered inside the VaultDashboard header.
 * Keeps the security policy visible and one-click accessible without a
 * separate settings screem
 */

import { useState, useEffect, type SubmitEventHandler } from "react";
import { useVaultStore } from "../../state/vaultStore";
import { getAutoLockTimeout, setAutoLockTimeout } from "../../lib/api";
import "../../styles/SecurityIndicator.css";

export function SecurityIndicator() {
  const lock = useVaultStore((s) => s.lock);
  const isLoading = useVaultStore((s) => s.isLoading);

  const [timeoutSecs, setTimeoutSecs] = useState<number | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  //Loading current timeout on mount
  useEffect(() => {
    getAutoLockTimeout()
      .then((s) => setTimeoutSecs(s))
      .catch(() => setTimeoutSecs(300));
  }, []);

  const handleEditSubmit: SubmitEventHandler<HTMLFormElement> = async (e) => {
    e.preventDefault();
    setSaveError(null);
    const secs = parseInt(draft, 10);
    if (isNaN(secs) || secs < 10 || secs > 900) {
      setSaveError("10-900 s");
      return;
    }
    try {
      await setAutoLockTimeout(secs);
      setTimeoutSecs(secs);
      setEditing(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 1800);
    } catch (e) {
      setSaveError(String(e));
    }
  };

  const formatTimeout = (s: number) => {
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const rem = s % 60;
    return rem === 0 ? `${m}m` : `${m}m ${rem}s`;
  };

  return (
    <div className="sec-indicator">
      {/* Auto-lock badge */}
      <div className="sec-timeout">
        {!editing ? (
          <button
            className="sec-timeout__badge"
            onClick={() => {
              setEditing(true);
              setDraft(String(timeoutSecs ?? 300));
              setSaveError(null);
            }}
            title="Click to change auto-lock timeout"
          >
            <svg
              className="sec-icon"
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <span>
              {timeoutSecs !== null ? formatTimeout(timeoutSecs) : "..."}
            </span>
            {saved && <span className="sec-saved">✓</span>}
          </button>
        ) : (
          <form onSubmit={handleEditSubmit} className="sec-timeout__form">
            <input
              type="number"
              className="sec-timeout__input"
              min={10}
              max={900}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              autoFocus
              onBlur={() => setEditing(false)}
              onKeyDown={(e) => e.key === "Escape" && setEditing(false)}
            />
            <span className="sec-timeout__unit">s</span>
            {saveError && <span className="sec-timeout__err">{saveError}</span>}
          </form>
        )}
      </div>

      {/* Lock Button */}
      <button
        className="fv-btn fv-btn-ghost sec-lock-btn"
        onClick={() => lock()}
        disabled={isLoading}
        title="Lock Vault"
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0110 0v4" />
        </svg>
        Lock
      </button>
    </div>
  );
}
