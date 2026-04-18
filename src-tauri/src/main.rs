#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auto_lock;
mod clipboard;
mod commands;
mod state;

use auto_lock::ShutdownHandle;
use clipboard::ClipboardState;
use state::AppState;

use std::sync::Mutex;
use tauri::Manager;

/* ---------------- Shutdown State ---------------- */

pub struct ShutdownState {
    pub handle: Mutex<Option<ShutdownHandle>>,
}

/* ---------------- Main Entry ---------------- */

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();

            // Initialize core application state
            let state =
                AppState::new(&app_handle).map_err(|e| Box::<dyn std::error::Error>::from(e))?;

            app.manage(state);
            app.manage(ClipboardState::new());

            // Start auto-lock watchdog AFTER state is registered
            let handle = auto_lock::start_auto_lock_task(app_handle.clone());

            // Store shutdown handle safely in managed state
            app.manage(ShutdownState {
                handle: Mutex::new(Some(handle)),
            });

            Ok(())
        })
        .on_window_event(|event| {
            // Trigger shutdown when window is destroyed
            if let tauri::WindowEvent::Destroyed = event.event() {
                let app_handle = event.window().app_handle();

                if let Some(state) = app_handle.try_state::<ShutdownState>() {
                    if let Some(handle) = state.handle.lock().unwrap().take() {
                        handle.signal();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::create_vault,
            commands::vault::unlock_vault,
            commands::vault::lock_vault,
            commands::vault::vault_status,
            commands::entries::add_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::entries::list_entries,
            commands::clipboard::copy_to_clipboard,
            commands::security::set_auto_lock_timeout,
        ])
        .run(tauri::generate_context!())
        .expect("fatal error while running FerreusVault");
}
