/**
 * Central application state store built on Zustand.
 *
 * This store is the single source of truth for:
 * - Vault lock / unlock status
 * - Whether a vault file has been created on disk
 * - The in-memory list of entry views (password-free)
 * - Loading and error states for async operations
 *
 * All mutations go through the async actions defined here so that IPC calls,
 * state updates, and error handling happen in one place. Components read from
 * the store and call actions — they never call lib/api.ts directly.
 *
 * Security notes:
 * - Passwords are NEVER stored in this file. They exist only on the stack
 *   of the action that receives them from a form, passed immediately into
 *   the IPC layer and then discarded.
 * - `entries` contains EntryView objects (no password field) as enforced
 *   by the backend's IPC contract.
 */

import { create } from "zustand";
import * as api from "../lib/api";
import type { EntryView } from "../lib/api";

export interface VaultState {
  /** Whether a vault file exists on disk. */
  vaultExists: boolean;
  /** Whether the vault is currently unlocked and data is in memory. */
  isUnlocked: boolean;
  /** True after the initial backend status check has completed. */
  hasCheckedStatus: boolean;
  /** Password-free entry list, mirrors backend state when unlocked. */
  entries: EntryView[];
  /** True during any async IPC operation. Used to disable UI controls. */
  isLoading: boolean;
  /** Last error message from a failed IPC call; null when no error. */
  error: string | null;

  /** Fetches vault_status from the backend and syncs local state. */
  fetchStatus: () => Promise<void>;
  /** Creates a new vault file. Throws on failure. */
  createVault: (password: string) => Promise<void>;
  /** Unlocks the vault and immediately loads the entry list. */
  unlock: (password: string) => Promise<void>;
  /** Locks the vault and clears the in-memory entry list. */
  lock: () => Promise<void>;
  /** Re-fetches the entry list from the backend. */
  refreshEntries: () => Promise<void>;
  /** Adds a new entry and refreshes the list. */
  addEntry: (
    accountName: string,
    username: string,
    password: string,
    notes: string,
  ) => Promise<void>;
  /** Updates an entry and refreshes the list. */
  updateEntry: (
    index: number,
    accountName?: string,
    username?: string,
    password?: string,
    notes?: string,
  ) => Promise<void>;
  /** Deletes an entry and refreshes the list. */
  deleteEntry: (index: number) => Promise<void>;
  /** Copies the entry's password to the clipboard via the backend. */
  copyPassword: (index: number) => Promise<void>;
  /** Clears the current error. */
  clearError: () => void;
  /**
   * Called by the vault_locked event listener when the backend auto-locks.
   * Synchronises frontend state without an additional IPC round-trip.
   */
  handleAutoLock: () => void;
}

export const useVaultStore = create<VaultState>((set, get) => ({
  vaultExists: false,
  isUnlocked: false,
  hasCheckedStatus: false,
  entries: [],
  isLoading: false,
  error: null,
  fetchStatus: async () => {
    set({ isLoading: true, error: null });
    try {
      const status = await api.getVaultStatus();
      set({
        vaultExists: status.vault_exists,
        isUnlocked: status.unlocked,
        hasCheckedStatus: true,
        isLoading: false,
      });
      // If already unlocked (e.g., a hot-reload during development), sync entries.
      if (status.unlocked) {
        await get().refreshEntries();
      }
    } catch (e) {
      set({ hasCheckedStatus: true, isLoading: false, error: String(e) });
    }
  },
  createVault: async (password: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.createVault(password);
      set({ vaultExists: true, isUnlocked: false, isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },
  unlock: async (password: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.unlockVault(password);
      // Password variable is now out of scope after this await.
      const entries = await api.listEntries();
      set({ isUnlocked: true, entries, isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },
  lock: async () => {
    set({ isLoading: true, error: null });
    try {
      await api.lockVault();
      // Clear in-memory entry list immediately.
      set({ isUnlocked: false, entries: [], isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },
  refreshEntries: async () => {
    try {
      const entries = await api.listEntries();
      set({ entries });
    } catch (e) {
      set({ error: String(e) });
    }
  },
  addEntry: async (
    accountName: string,
    username: string,
    password: string,
    notes: string,
  ) => {
    set({ isLoading: true, error: null });
    try {
      await api.addEntry(accountName, username, password, notes);
      // Password variable goes out of scope here.
      await get().refreshEntries();
      set({ isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },
  updateEntry: async (
    index: number,
    accountName?: string,
    username?: string,
    password?: string,
    notes?: string,
  ) => {
    set({ isLoading: true, error: null });
    try {
      await api.updateEntry(index, accountName, username, password, notes);
      await get().refreshEntries();
      set({ isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },
  deleteEntry: async (index: number) => {
    set({ isLoading: true, error: null });
    try {
      await api.deleteEntry(index);
      await get().refreshEntries();
      set({ isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },
  copyPassword: async (index: number) => {
    try {
      await api.copyPassword(index);
    } catch (e) {
      set({ error: String(e) });
      throw e;
    }
  },
  clearError: () => set({ error: null }),
  handleAutoLock: () => {
    // Sync frontend state when the backend watchdog fires vault_locked.
    // No IPC call needed — the backend has already locked the vault.
    set({ isUnlocked: false, entries: [] });
  },
}));
