import { useState } from "react";
import { unlockVault, createVault } from "../../lib/api";

export default function AuthGate({ onUnlocked }: { onUnlocked: () => void }) {
  const [password, setPassword] = useState("");

  async function handleUnlock() {
    try {
      await unlockVault(password);
      setPassword(""); // immediately clear state
      onUnlocked();
    } catch {
      alert("unlock failed");
      setPassword("");
    }
  }

  async function handleCreate() {
    try {
      await createVault(password);
      setPassword("");
      alert("Vault created");
    } catch {
      alert("Creation failed");
      setPassword("");
    }
  }

  return (
    <div>
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        autoComplete="off"
      />
      <button onClick={handleUnlock}>Unlock</button>
      <button onClick={handleCreate}>Create</button>
    </div>
  );
}
