#![cfg_attr(
    any(target_os = "android", target_os = "ios"),
    allow(dead_code, unused_imports)
)]

use crate::{
    config,
    models::{ConnectOptions, TrafficStats, VpnProtocol},
    olcrtc::{self, OlcRtcRuntime},
    platform, Result, VpnError,
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tauri::{plugin::PluginHandle, AppHandle, Emitter, Manager, Runtime};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, Duration},
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct SingBoxEngine {
    child: Mutex<Option<Child>>,
    olcrtc: Mutex<Option<OlcRtcRuntime>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    mobile_connected: Mutex<bool>,
    stats_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl Default for SingBoxEngine {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            olcrtc: Mutex::new(None),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            mobile_connected: Mutex::new(false),
            stats_task: Mutex::new(None),
        }
    }
}

impl SingBoxEngine {
    pub async fn start<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        options: &ConnectOptions,
        mobile: Option<&PluginHandle<R>>,
    ) -> Result<Vec<String>> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return self.start_mobile(app, options, mobile).await;
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = mobile;
            self.start_desktop(app, options).await
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn start_desktop<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        options: &ConnectOptions,
    ) -> Result<Vec<String>> {
        let mut guard = self.child.lock().await;
        if guard.is_some() {
            return Err(VpnError::AlreadyRunning);
        }

        let warnings = platform::check_platform_requirements()?;
        let config = config::generate_sing_box_config(options)?;
        let config_text = serde_json::to_string_pretty(&config)
            .map_err(|error| VpnError::Engine(format!("failed to serialize config: {error}")))?;
        let config_path = write_runtime_config(app, &config_text)?;
        let binary = resolve_core_binary(app)?;

        check_config(&binary, &config_path).await?;
        cleanup_desktop_artifacts(&config_path).await?;

        let mut olcrtc_runtime = if matches!(options.profile.protocol, VpnProtocol::OlcRtc) {
            let runtime =
                OlcRtcRuntime::start(olcrtc::OlcRtcConfig::from_profile(&options.profile)?).await?;
            let _ = app.emit("vpn:log", "OLC RTC client connected to WB Stream");
            Some(runtime)
        } else {
            None
        };

        let mut command = Command::new(&binary);
        command.arg("run").arg("-c").arg(&config_path);
        command.kill_on_drop(true);
        hide_tokio_command_window(&mut command);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match command.spawn() {
            Ok(mut child) => {
                pipe_logs(app, child.stdout.take(), "stdout");
                pipe_logs(app, child.stderr.take(), "stderr");
                sleep(Duration::from_millis(1200)).await;
                if let Some(status) = child.try_wait().map_err(|error| {
                    VpnError::Engine(format!("failed to inspect sing-box process: {error}"))
                })? {
                    if let Some(runtime) = olcrtc_runtime.take() {
                        runtime.stop().await;
                    }
                    let _ = cleanup_desktop_artifacts(&config_path).await;
                    return Err(VpnError::Engine(format!(
                        "sing-box exited during startup with status {status}. Check vpn logs for details."
                    )));
                }
                *guard = Some(child);
                *self.olcrtc.lock().await = olcrtc_runtime;
                self.start_stats_polling(app).await;
                let _ = app.emit(
                    "vpn:log",
                    format!("sing-box started with config {}", config_path.display()),
                );
                Ok(warnings)
            }
            Err(error) => {
                if let Some(runtime) = olcrtc_runtime.take() {
                    runtime.stop().await;
                }
                Err(VpnError::Engine(format!(
                    "failed to start bundled sing-box core at {}: {error}",
                    binary.display()
                )))
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn start_mobile<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        options: &ConnectOptions,
        mobile: Option<&PluginHandle<R>>,
    ) -> Result<Vec<String>> {
        if matches!(options.profile.protocol, VpnProtocol::OlcRtc) {
            return Err(VpnError::Unsupported(
                "OLC RTC mobile support needs a native/Rust WebRTC adapter; Windows desktop is implemented first".into(),
            ));
        }

        {
            let guard = self.mobile_connected.lock().await;
            if *guard {
                return Err(VpnError::AlreadyRunning);
            }
        }

        let warnings = platform::check_platform_requirements()?;
        let config = config::generate_sing_box_config(options)?;
        let config_json = serde_json::to_string(&config)
            .map_err(|error| VpnError::Engine(format!("failed to serialize config: {error}")))?;

        let Some(mobile) = mobile else {
            return Err(VpnError::Platform(
                "native VPN plugin is not registered for this mobile platform".into(),
            ));
        };

        mobile
            .run_mobile_plugin_async::<NativeStartResponse>(
                "startNativeVpn",
                NativeConnectArgs { config_json },
            )
            .await
            .map_err(|error| VpnError::Platform(format!("native VPN start failed: {error}")))?;

        *self.mobile_connected.lock().await = true;
        #[cfg(target_os = "android")]
        self.start_mobile_stats_polling(app, mobile.clone()).await;
        let _ = app.emit("vpn:log", "native mobile VPN start requested");
        Ok(warnings)
    }

    pub async fn stop<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        mobile: Option<&PluginHandle<R>>,
    ) -> Result<()> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            self.stop_mobile(app, mobile).await
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = mobile;
            self.stop_desktop(app).await
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn stop_desktop<R: Runtime>(&self, app: &AppHandle<R>) -> Result<()> {
        let mut guard = self.child.lock().await;
        self.stop_stats_polling().await;
        let Some(mut child) = guard.take() else {
            cleanup_desktop_artifacts(&runtime_config_path(app)?).await?;
            return Err(VpnError::NotRunning);
        };
        let kill_result = child.kill().await;
        if let Some(runtime) = self.olcrtc.lock().await.take() {
            runtime.stop().await;
        }
        if let Err(error) = kill_result {
            let _ = cleanup_desktop_artifacts(&runtime_config_path(app)?).await;
            return Err(VpnError::Engine(format!(
                "failed to stop sing-box: {error}"
            )));
        }
        cleanup_desktop_artifacts(&runtime_config_path(app)?).await?;
        let _ = app.emit("vpn:log", "sing-box process stopped");
        Ok(())
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn stop_mobile<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        mobile: Option<&PluginHandle<R>>,
    ) -> Result<()> {
        let mut connected = self.mobile_connected.lock().await;
        if !*connected {
            return Err(VpnError::NotRunning);
        }

        let Some(mobile) = mobile else {
            return Err(VpnError::Platform(
                "native VPN plugin is not registered for this mobile platform".into(),
            ));
        };

        mobile
            .run_mobile_plugin_async::<NativeStopResponse>("stopNativeVpn", ())
            .await
            .map_err(|error| VpnError::Platform(format!("native VPN stop failed: {error}")))?;

        self.stop_stats_polling().await;
        *connected = false;
        let _ = app.emit("vpn:log", "native mobile VPN stop requested");
        Ok(())
    }

    async fn start_stats_polling<R: Runtime>(&self, app: &AppHandle<R>) {
        let mut guard = self.stats_task.lock().await;
        if let Some(task) = guard.take() {
            task.abort();
        }

        let app = app.clone();
        *guard = Some(tauri::async_runtime::spawn(async move {
            let client = reqwest::Client::new();
            let url = format!("http://{}/connections", config::CLASH_API_ADDR);

            loop {
                sleep(Duration::from_secs(1)).await;
                match client.get(&url).send().await {
                    Ok(response) => match response.json::<ConnectionsStats>().await {
                        Ok(stats) => {
                            let traffic = TrafficStats {
                                uploaded_bytes: stats.upload_total,
                                downloaded_bytes: stats.download_total,
                            };
                            let _ = app.emit("vpn:stats", traffic);
                        }
                        Err(error) => {
                            let _ = app.emit(
                                "vpn:log",
                                format!("failed to decode traffic stats: {error}"),
                            );
                        }
                    },
                    Err(error) => {
                        let _ =
                            app.emit("vpn:log", format!("failed to query traffic stats: {error}"));
                    }
                }
            }
        }));
    }

    async fn stop_stats_polling(&self) {
        if let Some(task) = self.stats_task.lock().await.take() {
            task.abort();
        }
    }

    #[cfg(target_os = "android")]
    async fn start_mobile_stats_polling<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        mobile: PluginHandle<R>,
    ) {
        let mut guard = self.stats_task.lock().await;
        if let Some(task) = guard.take() {
            task.abort();
        }

        let app = app.clone();
        *guard = Some(tauri::async_runtime::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                match mobile
                    .run_mobile_plugin_async::<NativeTrafficStats>("getNativeTrafficStats", ())
                    .await
                {
                    Ok(stats) => {
                        let traffic = TrafficStats {
                            uploaded_bytes: stats.uploaded_bytes,
                            downloaded_bytes: stats.downloaded_bytes,
                        };
                        let _ = app.emit("vpn:stats", traffic);
                    }
                    Err(error) => {
                        let _ = app.emit(
                            "vpn:log",
                            format!("failed to query Android traffic stats: {error}"),
                        );
                    }
                }
            }
        }));
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectArgs {
    config_json: String,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(Deserialize)]
struct NativeStartResponse {
    #[allow(dead_code)]
    started: bool,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(Deserialize)]
struct NativeStopResponse {
    #[allow(dead_code)]
    stopped: bool,
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeTrafficStats {
    uploaded_bytes: u64,
    downloaded_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsStats {
    upload_total: u64,
    download_total: u64,
}

async fn check_config(binary: &Path, config_path: &Path) -> Result<()> {
    let mut command = Command::new(binary);
    command.arg("check").arg("-c").arg(config_path);
    hide_tokio_command_window(&mut command);
    let output = command
        .output()
        .await
        .map_err(|error| {
            VpnError::Engine(format!(
                "failed to run sing-box config check at {}: {error}",
                binary.display()
            ))
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(VpnError::Engine(format!(
        "sing-box config check failed: {}{}",
        stdout.trim(),
        stderr.trim()
    )))
}

fn pipe_logs<R, T>(app: &AppHandle<R>, stream: Option<T>, label: &'static str)
where
    R: Runtime,
    T: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(stream) = stream else {
        return;
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let _ = app.emit("vpn:log", format!("sing-box {label}: {line}"));
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = app.emit("vpn:log", format!("sing-box {label} read error: {error}"));
                    break;
                }
            }
        }
    });
}

fn write_runtime_config<R: Runtime>(app: &AppHandle<R>, config_text: &str) -> Result<PathBuf> {
    let config_path = runtime_config_path(app)?;
    if let Some(dir) = config_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&config_path, config_text)?;
    Ok(config_path)
}

pub(crate) fn runtime_config_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf> {
    let dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| VpnError::Platform(format!("app data directory unavailable: {error}")))?;
    Ok(dir.join("sing-box.generated.json"))
}

#[cfg(target_os = "windows")]
async fn cleanup_desktop_artifacts(config_path: &Path) -> Result<()> {
    cleanup_desktop_artifacts_blocking(config_path)?;
    sleep(Duration::from_millis(300)).await;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn cleanup_desktop_artifacts_blocking(config_path: &Path) -> Result<()> {
    let config_path = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let mut command = std::process::Command::new("powershell");
    command.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$target = [System.IO.Path]::GetFullPath($env:KOSTRA_VPN_CONFIG_PATH)
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -ieq 'sing-box.exe' -and $_.CommandLine -and $_.CommandLine.Contains($target) } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 2080 -State Listen |
  ForEach-Object {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)"
    if ($process -and $process.Name -ieq 'sing-box.exe') {
      Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
  }

Start-Sleep -Milliseconds 250

$indices = @{}
Get-NetIPAddress -AddressFamily IPv4 -IPAddress '172.19.0.1' |
  ForEach-Object { $indices[$_.InterfaceIndex] = $true }
Get-NetAdapter |
  Where-Object { $_.Name -like 'tun*' -or $_.InterfaceDescription -like '*sing-tun*' } |
  ForEach-Object { $indices[$_.ifIndex] = $true }

foreach ($index in $indices.Keys) {
  Get-NetRoute -InterfaceIndex $index | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetIPAddress -InterfaceIndex $index | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction SilentlyContinue
}
"#,
    ]);
    command
        .env("KOSTRA_VPN_CONFIG_PATH", config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_std_command_window(&mut command);
    let status = command
        .status()
        .map_err(|error| {
            VpnError::Engine(format!("failed to clean up stale Windows TUN state: {error}"))
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(VpnError::Engine(format!(
            "Windows TUN cleanup exited with status {status}"
        )))
    }
}

#[cfg(not(target_os = "windows"))]
async fn cleanup_desktop_artifacts(_config_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn cleanup_desktop_artifacts_blocking(_config_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn hide_tokio_command_window(command: &mut Command) {
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_tokio_command_window(_command: &mut Command) {}

#[cfg(target_os = "windows")]
fn hide_std_command_window(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_std_command_window(_command: &mut std::process::Command) {}

fn resolve_core_binary<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf> {
    let core_name = platform::default_core_name();
    let mut candidates = vec![
        std::env::var_os("KOSTRA_VPN_SING_BOX").map(PathBuf::from),
        app.path()
            .resolve(core_name, tauri::path::BaseDirectory::Resource)
            .ok(),
        app.path()
            .resolve(
                Path::new("resources").join(core_name),
                tauri::path::BaseDirectory::Resource,
            )
            .ok(),
        app.path()
            .resolve(
                Path::new("_up_").join("resources").join(core_name),
                tauri::path::BaseDirectory::Resource,
            )
            .ok(),
        std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .map(|dir| dir.join("resources").join(core_name))
        }),
        std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .map(|dir| dir.join("_up_").join("resources").join(core_name))
        }),
        std::env::current_dir()
            .ok()
            .map(|dir| dir.join("resources").join(core_name)),
        Some(PathBuf::from(core_name)),
    ];

    if let Ok(current_dir) = std::env::current_dir() {
        add_ancestor_resource_candidates(&mut candidates, &current_dir, core_name);
    }
    if let Ok(current_exe) = std::env::current_exe() {
        add_ancestor_resource_candidates(&mut candidates, &current_exe, core_name);
    }

    candidates
        .into_iter()
        .flatten()
        .find(|path| path.exists())
        .ok_or_else(|| {
            VpnError::Engine(format!(
                "sing-box core not found. Put {} in KOSTRA-VPN/resources or add it to the app resources.",
                core_name
            ))
        })
}

fn add_ancestor_resource_candidates(
    candidates: &mut Vec<Option<PathBuf>>,
    start: &Path,
    core_name: &str,
) {
    for ancestor in start.ancestors().take(8) {
        candidates.push(Some(ancestor.join("resources").join(core_name)));
    }
}

#[allow(dead_code)]
async fn write_child_stdin(child: &mut Child, input: &[u8]) -> Result<()> {
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input).await?;
    }
    Ok(())
}
