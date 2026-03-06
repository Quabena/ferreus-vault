import { useEffect, useState } from "react";
import { listEntries, lockVault } from "../../lib/api";
import EntryList from "./EntryList";

export default function VaultDashboard({ onLocked }: { onLocked: () => void }) {
  const [entries, setEntries] = useState<any[]>([]);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    const result = await listEntries();
    setEntries(result as any[]);
  }

  async function handleLock() {
    await lockVault();
    setEntries([]); // wipe memory
    onLocked();
  }

  return (
    <div>
      <button onClick={handleLock}>Lock</button>
      <EntryList entries={entries} refresh={load} />
    </div>
  );
}
