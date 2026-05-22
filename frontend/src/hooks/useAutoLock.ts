/**
 * Subscribes to the `vault_locked` backend event and synchronises the
 * Zustand store when the watchdog thread fires.
 *
 * This hook is mounted once the application root (App.tsx) It sets up the
 * Tauri event listener on mount and cleans it up on unmount, so there is
 * never more than one active subscription regardless of re-renders
 *
 * The hook does NOT navigate on auto-lock.
 */

import { useEffect } from "react";
import { onVaultLocked } from "../lib/api";
import { useVaultStore } from "../state/vaultStore";

export function useAutoLock(): void {
  const handleAutoLock = useVaultStore((s) => s.handleAutoLock);

  useEffect(() => {
    let unlisten: (() => void) | null = null;

    // `onVaultLocked` returns a Promise<UnlistenFn>. The unlisten function is captured
    // so that the cleanup can synchronously cancel the subscription even if the
    // component unmounts before the Promise resolves

    let cancelled = false;

    onVaultLocked(() => {
      handleAutoLock();
    }).then((fn) => {
      if (cancelled) {
        // Component already unmounted - immediately release the listener

        fn();
      } else {
        unlisten = fn;
      }
    });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [handleAutoLock]);
}
