/**
 * Application root.
 *  ---Responsibilities:
 *
 * 1. Mounts the auto-lock event listener (useAutoLock) exactly once for the
 * lifetime of the app so the store is notified whenever the backend
 * watchdog fires `vault_locked`
 *
 * 2. Renders the AuthGate, which decides whether to show UnlockScreen or
 * VaultDashboard based on the current lock state in the Zustand store
 */

import { useAutoLock } from "./hooks/useAutoLock";
import { AuthGate } from "./features/auth/AuthGate";
import { VaultDashboard } from "./features/vault/VaultDashboard";

export default function App() {
  // Subscribe to the backend `vault_locked` event once at the root level.
  // The hook registers the Tauri event lister on mount and cleans it up on
  // unmount...because App never unmounts during normal use, this listener
  // persists for the entire session.

  useAutoLock();

  return (
    <AuthGate>
      <VaultDashboard />
    </AuthGate>
  );
}
