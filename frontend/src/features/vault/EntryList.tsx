/**
 * Renders the list of vault entries. Handles:
 *  - Empty state
 *  - Search / filter by account name or username
 *  - Per-row copy, edit, and delete actions
 *  - Confirm-before-delete flow (inline, no extra modal)
 */

import { useState } from "react";
import type { EntryView } from "../../lib/api";
import { useVault } from "./useVault";
import { CopyButton } from "./CopyButton";
import "../../styles/EntryList.css";

interface EntryListProps {
  onEdit: (entry: EntryView) => void;
}

export function EntryList({ onEdit }: EntryListProps) {
  const { entries, isEmpty, deleteEntry, isLoading } = useVault();
  const [search, setSearch] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);

  const filtered = entries.filter((e) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      e.account_name.toLowerCase().includes(q) ||
      e.username.toLocaleLowerCase().includes(q)
    );
  });

  const handleDelete = async (index: number) => {
    if (confirmDelete !== index) {
      setConfirmDelete(index);
      return;
    }
    setConfirmDelete(null);
    await deleteEntry(index);
  };

  return (
    <div className="entry-list-root">
      {/* Search Bar */}
      <div className="entry-search-wrap">
        <svg
          className="entry-search-icon"
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="search"
          className="entry-search fv-input"
          placeholder="Filter entries..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          disabled={isLoading}
        />
        {search && (
          <button
            className="entry-search-clear fv-btn-icon"
            onClick={() => setSearch("")}
            aria-label="Clear filter"
          >
            x
          </button>
        )}
      </div>

      {/* Empty State */}
      {isEmpty && !search && (
        <div className="entry-empty animate-fade-in">
          <svg
            width="40"
            height="40"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--text-dim)"
            strokeWidth="1.5"
          >
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
          <p>No entries yet.</p>
          <p className="entry-empty__sub">
            Add your first entry with the button above
          </p>
        </div>
      )}

      {/* No results */}
      {!isEmpty && filtered.length === 0 && (
        <div className="entry-empty animate-fade-in">
          <p>No entries match "{search}"</p>
        </div>
      )}

      {/* List */}
      <ul className="entry-list" aria-label="Vault entries">
        {filtered.map((entry, i) => (
          <li
            key={entry.index}
            className="entry-row animate-fade-in"
            style={{ animationDelay: `${i * 30}ms` }}
          >
            {/* Left: account info */}
            <div className="entry-info">
              <span className="entry-account">{entry.account_name}</span>
              {entry.username && (
                <span className="entry-surname">{entry.username}</span>
              )}
              {entry.notes && (
                <span className="entry-notes-preview">
                  {entry.notes.length > 60
                    ? entry.notes.slice(0, 60) + "..."
                    : entry.notes}
                </span>
              )}
            </div>

            {/* Right: actions */}
            <div className="entry-actions">
              <CopyButton entryIndex={entry.index} />

              <button
                className="fv-btn-icon entry-action-btn"
                onClick={() => onEdit(entry)}
                title="Edit entry"
                disabled={isLoading}
              >
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
                  <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
                </svg>
              </button>

              {confirmDelete === entry.index ? (
                <button
                  className="fv-btn fv-btn-danger entry-confirm-del"
                  onClick={() => handleDelete(entry.index)}
                  title="Confirm delete"
                  disabled={isLoading}
                >
                  Delete?
                </button>
              ) : (
                <button
                  className="fv-btn-icon entry-action-btn entry-action-del"
                  onClick={() => handleDelete(entry.index)}
                  onBlur={() => setTimeout(() => setConfirmDelete(null), 200)}
                  title="Delete entry"
                  disabled={isLoading}
                >
                  <svg
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <polyline points="3 6 5 6 21 6" />
                    <path d="M19 6l-1 14H6L5 6" />
                    <path d="M10 11v6M14 11v6" />
                    <path d="M9 6V4h6v2" />
                  </svg>
                </button>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
