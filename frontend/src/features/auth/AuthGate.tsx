/**
 * Route guard that renders children only when the vault is unlocked.
 * When locked, (or during the initial status fetch), it renders UnlockScreen
 *
 * This is the single place in the app that decides which top-level view is shown
 * Components inside the gate never need to check isUnlocked themsleves
 */

import { useEffect } from "react";
import { useVaultStore } from "../../state/vaultStore";
import { UnlockScreen } from "./UnlockScreen";

interface AuthGateProps {
  children: React.ReactNode;
}

export function AuthGate({ children }: AuthGateProps) {
  const isUnlocked = useVaultStore((s) => s.isUnlocked);
  const fetchStatus = useVaultStore((s) => s.fetchStatus);

  // Fetch vault status once on mount so the screen is shown immediately
  useEffect(() => {
    fetchStatus();
  }, []);

  if (!isUnlocked) {
    return <UnlockScreen />;
  }

  return <>{children}</>;
}
