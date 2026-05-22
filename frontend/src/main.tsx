/**
 * App entry point
 *
 * Renders the React tree into #root and imports the global stylesheet.
 * The Tauri environment guard is checked here so a clear error is surfaced.
 */

import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/index.css";

import { IS_TAURI } from "./api/tauri";
if (!IS_TAURI) {
  console.warn(
    "[FerreusVault] Not running inside the Tauri shell. " +
      "IPC calls will fail. " +
      "Open the app via `tauri dev` or the installed executable.",
  );
}

const root = document.getElementById("root");
if (!root) {
  throw new Error(
    "Fatal: #root element not found." +
      'Check that index.html contains <div id="root"></div>.',
  );
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
