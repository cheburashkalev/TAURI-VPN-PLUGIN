use crate::{import, models::*, protocols, state::VpnState, Result, VpnError};
use tauri::{AppHandle, Emitter, Runtime, State};

#[tauri::command]
pub async fn connect<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, VpnState<R>>,
    options: ConnectOptions,
) -> Result<ConnectionStatus> {
    {
        let mut status = state.status.lock().await;
        if matches!(
            status.phase,
            ConnectionPhase::Connected | ConnectionPhase::Connecting
        ) {
            return Err(VpnError::AlreadyRunning);
        }
        status.phase = ConnectionPhase::Connecting;
        status.active_profile_id = Some(options.profile.id);
        status.message = Some("Connecting".into());
        let _ = app.emit("vpn:status", status.clone());
    }

    match state
        .engine
        .start(&app, &options, state.mobile.as_ref())
        .await
    {
        Ok(warnings) => {
            let mut status = state.status.lock().await;
            status.phase = ConnectionPhase::Connected;
            status.message = warnings
                .first()
                .cloned()
                .or_else(|| Some("Connected".into()));
            let _ = app.emit("vpn:status", status.clone());
            Ok(status.clone())
        }
        Err(error) => {
            let mut status = state.status.lock().await;
            status.phase = ConnectionPhase::Failed;
            status.message = Some(error.to_string());
            let _ = app.emit("vpn:error", status.clone());
            Err(error)
        }
    }
}

#[tauri::command]
pub async fn disconnect<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, VpnState<R>>,
) -> Result<ConnectionStatus> {
    {
        let mut status = state.status.lock().await;
        status.phase = ConnectionPhase::Disconnecting;
        status.message = Some("Disconnecting".into());
        let _ = app.emit("vpn:status", status.clone());
    }

    state.engine.stop(&app, state.mobile.as_ref()).await?;
    let mut status = state.status.lock().await;
    *status = ConnectionStatus::default();
    let _ = app.emit("vpn:status", status.clone());
    Ok(status.clone())
}

#[tauri::command]
pub async fn status<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, VpnState<R>>,
) -> Result<ConnectionStatus> {
    let _ = app;
    let mut status = state.status.lock().await;

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        if let Ok((established, profile_id)) = state
            .engine
            .get_mobile_status(&app, state.mobile.as_ref())
            .await
        {
            if established {
                if status.phase == ConnectionPhase::Disconnected {
                    status.phase = ConnectionPhase::Connected;
                    status.message = Some("Connected (Recovered)".into());
                }
                if let Some(id_str) = profile_id {
                    if let Ok(uuid) = uuid::Uuid::parse_str(&id_str) {
                        status.active_profile_id = Some(uuid);
                    }
                }
            } else if matches!(
                status.phase,
                ConnectionPhase::Connected | ConnectionPhase::Connecting
            ) {
                status.phase = ConnectionPhase::Disconnected;
                status.message = None;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match crate::macos_vpn::is_vpn_profile_connected() {
            Ok(true) if status.phase == ConnectionPhase::Disconnected => {
                status.phase = ConnectionPhase::Connected;
                status.message = Some("Connected (Recovered)".into());
            }
            Ok(false)
                if matches!(
                    status.phase,
                    ConnectionPhase::Connected | ConnectionPhase::Connecting
                ) =>
            {
                status.phase = ConnectionPhase::Disconnected;
                status.message = None;
            }
            _ => {}
        }
    }

    Ok(status.clone())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn import_server(input: String) -> Result<ImportedServer> {
    import::import_server(&input)
}

#[tauri::command(rename_all = "camelCase")]
pub async fn validate_profile(profile: VpnProfile) -> Result<ValidationResult> {
    Ok(protocols::validate(&profile))
}

#[tauri::command]
pub async fn list_protocols() -> Result<Vec<ProtocolInfo>> {
    Ok(protocols::list_protocols())
}
