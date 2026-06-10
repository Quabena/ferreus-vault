/**
 * Tauri environment guard and re-export point.
 *
 * In development mode, the Vite dev server may serve the frontend outside
 * the Tauri webview (e.g., in a browser for hot-reload). This module
 * provides a single place to detect that case and surface a clear error
 * rather than letting invoke() fail silently deep in a component.
 *
 * All application code that touches the Tauri API should import from
 * `lib/api.ts` (the typed wrappers), not directly from @tauri-apps/api.
 * This file is the one exception — it is consumed only by api.ts itself
 * and tests that need to mock the Tauri bridge.
 */

/**
 * True when running inside the Tauri webview with a functioning IPC bridge.
 *
 * Tauri v2 injects `window.__TAURI_INTERNALS__` before the webview navigates
 * to the app URL. The v1 global (`window.__TAURI__`) is absent in v2 builds.
 */
export const IS_TAURI: boolean =
  typeof window !== "undefined" &&
  typeof (window as Window & { __TAURI_INTERNALS__?: unknown })
    .__TAURI_INTERNALS__ !== "undefined";

/**
 * Asserts that the current environment has a functioning Tauri IPC bridge.
 *
 * Call this once during application bootstrap (e.g., in main.tsx) to surface
 * a clear error rather than a cryptic "invoke is not a function" crash later.
 *
 * @throws {Error} if the app is not running inside Tauri.
 */
export function assertTauriEnvironment(): void {
  if (!IS_TAURI) {
    throw new Error(
      "FerreusVault must run inside the Tauri desktop shell. " +
        "Opening it directly in a browser is not supported.",
    );
  }
}
