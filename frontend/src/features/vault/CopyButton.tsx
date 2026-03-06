import { getPassword, copyToClipboard } from "../../lib/api";

export default function CopyButton({ id }: { id: number }) {
  async function handleCopy() {
    try {
      const password = await getPassword(id);
      await copyToClipboard(password);

      // Destroy local reference
    } catch {
      alert("Failed to copy");
    }
  }

  return <button onClick={handleCopy}></button>;
}
