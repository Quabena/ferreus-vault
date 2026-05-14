/**
 * Tauri environment guard and re-export point
 *
 * In development mode, the Vite dev server may serve the frontend outside
 * the Tauri Webview (eg. in a browser for a hot-reload). This module
 * provides a single place to detect that case and surface a clear error
 * rather than letting invoke() fail silentlu deep in a component
 *
 * All application code that touches the Tauri API should import from `lib/api.ts` (the typed wrappers), not directly from @tauri-apps/api.
 * This file is the one exception - it is consumed only by api.ts itself
 * and tests that need to mock the Tauri Bridge
 */

/**
 * True when running inside the Tauri webview with a functioning IPC bridge
 *
 * This flag is set by the Tauri runtime on the `window` object before the
 * webview navigates to the app URL. It is absent when the page is opened in a
 * pain browser
 */
export const IS_TAURI: boolean =
  typeof window !== "undefined" &&
  typeof (window as Window & { __TAURI__?: unknown }).__TAURI__ !== "undefined";

/**
 * Throw a clear error if the app is not running inside Tauri
 */
export function assertTauriEnvironment(): void {
  if (!IS_TAURI) {
    throw new Error(
      "FerreusVault must run inside the Tauri desktop shell. " +
        "Opening it directly in a browser is not supported.",
    );
  }
}
