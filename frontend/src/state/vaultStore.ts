/**
 * Central application state store build on zustand
 *
 * This store is the single source of truth for:
 * - Vault lock / unlock status
 * - Whether a vaul file has been created on disk
 * - the in-memory list of entry views (password-free)
 * - Loading and error states for async operations
 *
 * All mutations go through the async actins defined here so that IPC calls,
 * state updates, and error handling happen in one place. Components read from
 * the store and call actions - they never call api.ts directly
 *
 */

import { create } from "zustand";
import * as api from "../lib/api";
import type { EntryView } from "../lib/api";

/* -------------------------- State shape ------------------------ */

export interface VaultStore {
  /** Whether a vault file exist on disk */
  vaultExist: boolean;
  /** Whether the vault is currently unlocked and data is is memory */
  inUnlocked: boolean;
  /** Password-free entry list, mirrors backend state when unlocked */
  entries: EntryView[];
  /** True during any async IPC operation. Used to disable controls */
  isLoading: boolean;
  /** Last error message from a failed IPC call; null when no error */

  /* ----- Actions ----- */

  /** Fetches vault_status from the backedn and syncs local state */
  fetchStatus: () => Promise<void>;
  /** Creates a new vault file. Throws on failure */
  createVault: (password: string) => Promise<void>;
  /** Unlocks the vault and immediately loads the entry list */
  unlock: (password: string) => Promise<void>;
  /** Locks the vault and clears the in-memory entry list */
  lock: () => Promise<void>;
  /** Refetches the entry list from the backend */
  refreshEntries: () => Promise<void>;
  /** Adds a new entry and refreshes the list */
  addEntry: (
    accountName: string,
    username: string,
    password: string,
    notes: string,
  ) => Promise<void>;
  /** Updates an entry and refreshes then list */
  updateEntry: (
    index: number,
    accountName?: string,
    username?: string,
    password?: string,
    notes?: string,
  ) => Promise<void>;
  /** Deletes an entry and refreshes the list */
  deleteEntry: (index: number) => Promise<void>;
  /** Copies the entry's password to the clipboard via the backend. */
  copyPassword: (index: number) => Promise<void>;
  /** Clears the current error. */
  clearError: () => void;
  /** Called by the vault_locked event listener when the backend auto-locks
   * Synchronizes frontend state without an additional IPC round-trip
   */
  handleAutoLock: () => void;
}

/* ------------- Store ------------------ */

export const useVaultStore = create<VaultState>((set, get) => ({
  vaultExists: false,
  inUnlocked: false,
  entries: [],
  isLoading: false,
  error: null,

  /* ---- fetchStatus----- */
  fetchStatus: async () => {
    set({ isLoading: true, error: null });
    try {
      const status = await api.getVaultStatus();
      set({
        vaultExists: status.vault_exists,
        isUlocked: status.unlocked,
        isLoading: false,
      });
      // if already unlocked (eg. a hot-reload during development) sync entries
      if (status.unlocked) {
        await get().refreshEntries();
      }
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  /* ------- createVault -------- */
  createVault: async (password: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.createVault(password);
      set({ vaultExists: true, inUnlocked: false, isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },

  /* ------- unlock-------- */
  unlock: async (password: string) => {
    set({ isLoading: true, error: null });
    try {
      await api.unlockVault(password);
      const entries = await api.listEntries;
      set({ isUnlocked: true, entries, isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },

  /* ------- lock -------- */
  lock: async () => {
    set({ isLoading: true, error: null });
    try {
      await api.lockVault();
      // clearing in-memory list immediately
      set({ isUnlocked: false, entries: [], isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  /* ------- refreshEntries -------- */
  refreshEntries: async () => {
    try {
      const entries = await api.listEntries();
      set({ entries });
    } catch (e) {
      set({ error: String(e) });
    }
  },

  /* ------- addEntry -------- */
  addEntry: async (
    accountName: string,
    username: string,
    password: string,
    notes: string,
  ) => {
    set({ isLoading: true, error: null });
    try {
      await api.addEntry(accountName, username, password, notes);
      await get().refreshEntries();
      set({ isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
      throw e;
    }
  },

  /* ------- updateEntry -------- */
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

  /* ------- deleteEntry -------- */
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

  /* ------- copyPassword -------- */
  copyPassword: async (index: number) => {
    try {
      await api.copyPassword(index);
    } catch (e) {
      set({ error: String(e) });
    }
  },

  /* ------- clearError -------- */
  clearError: () => set({ error: null }),

  /* ------- handleAutoLock -------- */
  handleAutoLock: () => {
    set({ isUnlocked: false, entries: [] });
  },
}));
