mod commands;
pub mod config;
mod engine;
mod errors;
pub mod import;
pub mod models;
mod platform;
mod protocols;
mod state;

use engine::SingBoxEngine;
pub use errors::{Result, VpnError};
pub use models::*;
use state::VpnState;
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_vpn);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("vpn")
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::status,
            commands::import_server,
            commands::validate_profile,
            commands::list_protocols,
        ])
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let mobile = Some(api.register_android_plugin("com.kostra.vpn.plugin", "VpnPlugin")?);

            #[cfg(target_os = "ios")]
            let mobile = Some(api.register_ios_plugin(init_plugin_vpn)?);

            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let mobile: Option<tauri::plugin::PluginHandle<R>> = None;
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            let _ = &api;

            app.manage(VpnState::new(SingBoxEngine::default(), mobile));
            Ok(())
        })
        .build()
}
