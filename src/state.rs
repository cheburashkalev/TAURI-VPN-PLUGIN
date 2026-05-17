use crate::{engine::SingBoxEngine, models::ConnectionStatus};
use tauri::{plugin::PluginHandle, Runtime};
use tokio::sync::Mutex;

pub struct VpnState<R: Runtime> {
    pub engine: SingBoxEngine,
    pub mobile: Option<PluginHandle<R>>,
    pub status: Mutex<ConnectionStatus>,
}

impl<R: Runtime> VpnState<R> {
    pub fn new(engine: SingBoxEngine, mobile: Option<PluginHandle<R>>) -> Self {
        Self {
            engine,
            mobile,
            status: Mutex::new(ConnectionStatus::default()),
        }
    }
}
