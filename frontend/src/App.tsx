import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import AuthGate from "./features/auth/AuthGate";
import VaultDashboard from "./features/vault/VaultDashboard";

export default function App() {
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    const unlisten = listen("vault_locked", () => {
      setUnlocked(false);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  return unlocked ? (
    <VaultDashboard onLocked={() => setUnlocked(false)} />
  ) : (
    <AuthGate onUnlocked={() => setUnlocked(true)} />
  );
}
