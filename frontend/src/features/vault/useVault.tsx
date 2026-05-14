/**
 * Convenience hook that surfaces the vault entry slice of the store together
 * with derived UI state, so vault components don't need to compute things
 *
 * Components that only need lock/unlock status should use useVaultStore
 * directly. This hook is for component that render or mutate entries
 */

import { useVaultStore } from "../../state/vaultStore";
import type { EntryView } from "../../lib/api";

export interface UseVaultReturn {
  entries: EntryView[];
  isLoading: boolean;
  error: string | null;
  isEmpty: boolean;
  addEntry: (
    accountName: string,
    username: string,
    password: string,
    notes: string,
  ) => Promise<void>;
  updateEntry: (
    index: number,
    accountName?: string,
    username?: string,
    password?: string,
    notes?: string,
  ) => Promise<void>;
  deleteEntry: (index: number) => Promise<void>;
  copyPassword: (index: number) => Promise<void>;
  clearError: () => void;
}

export function useVault(): UseVaultReturn {
  const entries = useVaultStore((s) => s.entries);
  const isLoading = useVaultStore((s) => s.isLoading);
  const error = useVaultStore((s) => s.error);
  const addEntry = useVaultStore((s) => s.addEntry);
  const updateEntry = useVaultStore((s) => s.updateEntry);
  const deleteEntry = useVaultStore((s) => s.deleteEntry);
  const copyPassword = useVaultStore((s) => s.copyPassword);
  const clearError = useVaultStore((s) => s.clearError);

  return {
    entries,
    isLoading,
    error,
    isEmpty: entries.length === 0,
    addEntry,
    updateEntry,
    deleteEntry,
    copyPassword,
    clearError,
  };
}
