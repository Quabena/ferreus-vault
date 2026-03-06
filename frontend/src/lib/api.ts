import { invoke } from "@tauri-apps/api/core";

export async function createVault(password: string) {
  return invoke("create_vault", { password });
}

export async function unlockVault(password: string) {
  return invoke("unlock_vault", { password });
}

export async function lockVault() {
  return invoke("lock_vault");
}
export async function vaultStatus() {
  return invoke("vault_status");
}
export async function listEntries() {
  return invoke("list_entries");
}

export async function addEntry(payload: {
  accountName: string;
  username: string;
  password: string;
  notes: string;
}) {
  return invoke("add_entry", {
    accountName: payload.accountName,
    username: payload.username,
    password: payload.password,
    notes: payload.notes,
  });
}

export async function getPassword(id: number) {
  return invoke("get_password", { id });
}

export async function copyToClipboard(content: string) {
  return invoke("copy_to_clipboard", { content });
}

export async function setAutoLock(seconds: number) {
  return invoke("set_auto_lock_timeout", { seconds });
}
