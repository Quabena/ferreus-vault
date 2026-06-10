/**
 * Button that calls `copy_password` on the backend for the entry at `index`
 * The password never reaches JavaScript - the backend writes it directly to
 * the clipboard
 *
 * Shows a brief "Copied" confirmation state after a successful copu
 *
 */

import { useState } from "react";
import { useVaultStore } from "../../state/vaultStore";
import "../../styles/CopyButton.css";

interface CopyButtonProps {
  entryIndex: number;
  label?: string;
}

export function CopyButton({ entryIndex, label = "Copy" }: CopyButtonProps) {
  const copyPassword = useVaultStore((s) => s.copyPassword);
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");

  const handleCopy = async () => {
    if (state !== "idle") return;
    try {
      await copyPassword(entryIndex);
      setState("copied");
      setTimeout(() => setState("idle"), 1800);
    } catch {
      setState("error");
      setTimeout(() => setState("idle"), 2200);
    }
  };

  return (
    <button
      className={`copy-btn copy-btn--${state}`}
      onClick={handleCopy}
      disabled={state !== "idle"}
      title={
        state === "copied"
          ? "Copied to clipboard"
          : state === "error"
            ? "Copy failed"
            : "Copy password to clipboard"
      }
    >
      {state === "idle" && (
        <>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
          </svg>
          {label}
        </>
      )}

      {state === "copied" && (
        <>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
          Copied
        </>
      )}
      {state === "error" && (
        <>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          Failed
        </>
      )}
    </button>
  );
}
