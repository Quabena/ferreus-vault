#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auto_lock;
mod clipboard;
mod commands;
mod config;
mod state;

use state::AppState;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();

            let state = AppState::new(&app_handle);
            app.manage(state);

            app.manage(clipboard::ClipboardState::new());

            // Start background aut-lock watchdog
            auto_lock::start_auto_lock_task(app_handle.clone());

            Ok(())
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
        .expect("error while running FerreusVault");
}
