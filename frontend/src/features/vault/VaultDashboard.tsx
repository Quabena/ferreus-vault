/**
 * The main application view, shown when the vault is unlocked
 *
 * The EntryModal floats over the layout as a portal-like overlay
 */

import { useState } from "react";
import type { EntryView } from "../../lib/api";
import { useVault } from "./useVault";
import { EntryList } from "./EntryList";
import { EntryModal } from "./EntryModal";
import { SecurityIndicator } from "../security/SecurityIndicator";
import "../../styles/VaultDashboard.css";

export function VaultDashboard() {
  const { entries, error, clearError } = useVault();
  const [modalEntry, setModalEntry] = useState<EntryView | null | undefined>(
    undefined, // undefined = modal closed; null = add mode; EntryView = edit mode
  );

  const isModalOpen = modalEntry !== undefined;

  return (
    <div className="dashboard-root">
      {/* ---- Header ---- */}
      <header className="dashboard-header">
        <div className="dashboard-brand">
          <svg
            width="18"
            height="18"
            viewBox="0 0 48 48"
            fill="none"
            aria-hidden="true"
          >
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
          <span className="dashboard-brand-name text-display">
            Ferreus Vault
          </span>
        </div>
        <SecurityIndicator />
      </header>

      {/* ---- Toolbar ---- */}
      <div className="dashboard-toolbar">
        <button
          className="fv-btn fv-btn-primary dashboard-add-btn"
          onClick={() => setModalEntry(null)}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
          >
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          New entry
        </button>

        <span className="dashboard-count">
          {entries.length === 0
            ? "No entries"
            : entries.length === 1
              ? "1 entry"
              : `${entries.length} entries`}
        </span>
      </div>

      {/* ---- Global error banner ---- */}
      {error && (
        <div
          className="dashboard-error-bar fv-error animate-fade-in"
          role="alert"
        >
          <span>{error}</span>
          <button
            className="fv-btn-icon"
            onClick={clearError}
            aria-label="Dismiss"
          >
            x
          </button>
        </div>
      )}

      {/* ---- Entry list ---- */}
      <main className="dashboard-content">
        <EntryList onEdit={(entry) => setModalEntry(entry)} />
      </main>

      {/* Entry modal */}
      {isModalOpen && (
        <EntryModal
          entry={modalEntry ?? null}
          onClose={() => setModalEntry(undefined)}
        />
      )}
    </div>
  );
}
