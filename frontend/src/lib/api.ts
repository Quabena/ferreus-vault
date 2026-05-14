/**
 * Typed wrappers around every Tauri IPC command exposed by the backend
 *
 * Design rules:
 * - Functions throw on error (the string the backend returns become the error message)
 * so callers use try/catch naturally
 * - No raw passwords returned; copy_password sends directly to the clipboard
 * via the backend without the value ever reaching JS.
 * - All shapes mirror the RUst structs exactly
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/* ---------- Shared types ---------- */
/** Read-only view of a vault entry - password field deliberately absent */
export interface EntryView {
  index: number;
  account_name: string;
  username: string;
  notes: string;
}

/** Current state of the vault file and in-memory lock status. */
export interface VaultStatus {
  unlocked: boolean;
  vault_exists: boolean;
}

/* ---------- Vault lifecycle ---------- */
/**
 * creates a new vault protected by `password`
 * Throws if the password fails complexity validation or a vault already exists
 */
export async function createVault(password: string): Promise<void> {
  await invoke<void>("create_vault", { password });
}

/**
 * Decrypts the vault and loads it into memory
 * Throws "Invalid password or corrupted vault" on auth failure.
 */
export async function unlockVault(password: string): Promise<void> {
  await invoke<void>("unlock_vault", { password });
}

/**
 * Locks the vault, zeroizing all in-memory key material
 * Safe to call when already locked (idempotent)
 */
export async function lockVault(): Promise<void> {
  await invoke<void>("lock_vault");
}

/**
 * Returns the current lock state and whether a vault file exists on disk
 */
export async function getVaultStatus(): Promise<VaultStatus> {
  return invoke<VaultStatus>("vault_status");
}

/* --------------------------------- Entry CRUD --------------------------------- */

/**
 * Returns all vault entries without the password field
 * Throws "Vault is locked" if the vault has not been unlocked
 */
export async function listEntries(): Promise<EntryView[]> {
  return invoke<EntryView[]>("list_entries");
}

/**
 * Adds a new entry to the vault
 * The password is moved into the backend and never returned
 */

export async function addEntry(
  account_name: string,
  username: string,
  password: string,
  notes: string,
): Promise<void> {
  await invoke<void>("add_entry", { account_name, username, password, notes });
}

/**
 * Updates selected fields of the entry at `index`
 * Passing `null` for a field leaves it unchanged
 */
export async function updateEntry(
  index: number,
  account_name?: string | null,
  username?: string | null,
  password?: string | null,
  notes?: string | null,
): Promise<void> {
  await invoke<void>("update_entry", {
    index,
    account_name: account_name ?? null,
    username: username ?? null,
    password: password ?? null,
    notes: notes ?? null,
  });
}

/**
 * Deletes the entry at `index`
 * Throws "Entry not found" if the index is out of bounds
 */
export async function deleteEntry(index: number): Promise<void> {
  await invoke<void>("delete_entry", { index });
}

/* --------------------------------- Clipboard --------------------------------- */

/**
 * Copies the password of the entry at `index` directly to the clipboard
 * via the backend - the raw password never reaches JavaScript
 * An auto-clear timer is set automatically
 */
export async function copyPassword(index: number): Promise<void> {
  await invoke<void>("copy_password", { index });
}

/**
 * Writes arbitrary `content` to the clipboard with an auto-clear timer
 * Using `copyPassword` for entry passwords to avoid IPC exposure
 */
export async function copyToClipboard(content: string): Promise<void> {
  await invoke<void>("copy_to_clipboard", { content });
}

/* --------------------------------- Security Policy --------------------------------- */

/**
 * Sets the vault inactivity timeout
 */
export async function setAutoLockTimeout(seconds: number): Promise<void> {
  await invoke<void>("set_auto_lock_timeout", { seconds });
}

/**
 * Returns the current auto-lock timeout in seconds
 */
export async function getAutoLockTimeout(): Promise<number> {
  return invoke<number>("get_auto_lock_timeout");
}

/* --------------------------------- Backend Events --------------------------------- */

/**
 * Subscribes to the `vault_locked` event emitted by the auto-lock watchdog
 * when the inactivity timeout fires
 * Returns an unsubscribed function, call it in a React cleanup effect to
 * avoid listener leaks
 */
export async function onVaultLocked(cb: () => void): Promise<UnlistenFn> {
  return listen("vault_locked", cb);
}
