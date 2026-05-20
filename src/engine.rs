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
    sync::Mutex as StdMutex,
};
use tauri::{plugin::PluginHandle, AppHandle, Emitter, Manager, Runtime};
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout, Duration},
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const DESKTOP_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const DESKTOP_STATS_TIMEOUT: Duration = Duration::from_secs(3);
const PORT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "macos")]
const MACOS_ADMIN_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(target_os = "macos")]
const MACOS_SYSTEM_TUNNEL_TIMEOUT: Duration = Duration::from_secs(20);

pub struct SingBoxEngine {
    child: Mutex<Option<Child>>,
    #[cfg(target_os = "macos")]
    privileged_pid: Mutex<Option<u32>>,
    #[cfg(target_os = "macos")]
    macos_system_connected: Mutex<bool>,
    olcrtc: Mutex<Option<OlcRtcRuntime>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    mobile_connected: Mutex<bool>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    stats_task: StdMutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl Default for SingBoxEngine {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            #[cfg(target_os = "macos")]
            privileged_pid: Mutex::new(None),
            #[cfg(target_os = "macos")]
            macos_system_connected: Mutex::new(false),
            olcrtc: Mutex::new(None),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            mobile_connected: Mutex::new(false),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            stats_task: StdMutex::new(None),
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
        #[cfg(target_os = "macos")]
        let guard = self.child.lock().await;
        #[cfg(not(target_os = "macos"))]
        let mut guard = self.child.lock().await;
        if guard.is_some() {
            return Err(VpnError::AlreadyRunning);
        }
        #[cfg(target_os = "macos")]
        {
            if self.privileged_pid.lock().await.is_some() {
                return Err(VpnError::AlreadyRunning);
            }
            if *self.macos_system_connected.lock().await {
                return Err(VpnError::AlreadyRunning);
            }
        }

        let warnings = platform::check_platform_requirements()?;
        let config = config::generate_sing_box_config(options)?;
        let config_text = serde_json::to_string_pretty(&config)
            .map_err(|error| VpnError::Engine(format!("failed to serialize config: {error}")))?;
        let config_path = write_runtime_config(app, &config_text)?;
        let binary = resolve_core_binary(app)?;

        check_config(&binary, &config_path).await?;
        #[cfg(target_os = "macos")]
        crate::macos_vpn::install_vpn_profile()?;
        cleanup_desktop_artifacts(&config_path).await?;

        let mut olcrtc_runtime = if matches!(options.profile.protocol, VpnProtocol::OlcRtc) {
            let runtime =
                OlcRtcRuntime::start(olcrtc::OlcRtcConfig::from_profile(&options.profile)?).await?;
            let _ = app.emit("vpn:log", "OLC RTC client connected to WB Stream");
            Some(runtime)
        } else {
            None
        };

        #[cfg(target_os = "macos")]
        {
            if let Err(error) =
                crate::macos_vpn::start_vpn_profile(&config_text, Some(&options.profile.id.to_string()))
            {
                if let Some(runtime) = olcrtc_runtime.take() {
                    runtime.stop().await;
                }
                return Err(error);
            }
            if let Err(error) = wait_for_macos_system_tunnel().await {
                if let Some(runtime) = olcrtc_runtime.take() {
                    runtime.stop().await;
                }
                let _ = crate::macos_vpn::stop_vpn_profile();
                return Err(error);
            }
            *self.macos_system_connected.lock().await = true;
            *self.olcrtc.lock().await = olcrtc_runtime;
            self.start_stats_polling(app).await;
            let _ = app.emit("vpn:log", "macOS system VPN tunnel start requested");
            return Ok(warnings);
        }

        #[cfg(not(target_os = "macos"))]
        {
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
                    if let Some(status) = wait_for_desktop_readiness(&mut child).await? {
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
                NativeConnectArgs {
                    config_json,
                    profile_id: Some(options.profile.id.to_string()),
                },
            )
            .await
            .map_err(|error| VpnError::Platform(format!("native VPN start failed: {error}")))?;

        *self.mobile_connected.lock().await = true;
        let _ = app.emit("vpn:log", "native mobile VPN start requested");
        Ok(warnings)
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub async fn get_mobile_status<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        mobile: Option<&PluginHandle<R>>,
    ) -> Result<(bool, Option<String>)> {
        let Some(mobile) = mobile else {
            return Ok((false, None));
        };

        // If the bridge is not ready, it might return an error.
        // We retry up to 3 times with increasing delay.
        let mut last_error = None;
        for i in 0..3 {
            match mobile
                .run_mobile_plugin_async::<NativeStatusResponse>("getNativeVpnStatus", ())
                .await
            {
                Ok(response) => {
                    if response.established {
                        *self.mobile_connected.lock().await = true;
                        if let (Some(up), Some(down)) =
                            (response.uploaded_bytes, response.downloaded_bytes)
                        {
                            let _ = app.emit(
                                "vpn:stats",
                                TrafficStats {
                                    uploaded_bytes: up,
                                    downloaded_bytes: down,
                                },
                            );
                        }
                    } else {
                        *self.mobile_connected.lock().await = false;
                    }
                    return Ok((response.established, response.active_profile_id));
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(std::time::Duration::from_millis(500 * (i + 1))).await;
                }
            }
        }

        let error = last_error.unwrap();
        Err(VpnError::Platform(format!(
            "failed to query native VPN status after retries: {error}"
        )))
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
        #[cfg(target_os = "macos")]
        {
            if *self.macos_system_connected.lock().await {
                if let Some(runtime) = self.olcrtc.lock().await.take() {
                    runtime.stop().await;
                }
                crate::macos_vpn::stop_vpn_profile()?;
                *self.macos_system_connected.lock().await = false;
                cleanup_desktop_artifacts(&runtime_config_path(app)?).await?;
                let _ = app.emit("vpn:log", "macOS system VPN tunnel stop requested");
                return Ok(());
            }
            if let Some(pid) = self.privileged_pid.lock().await.take() {
                if let Some(runtime) = self.olcrtc.lock().await.take() {
                    runtime.stop().await;
                }
                stop_macos_privileged_sing_box(Some(pid), &runtime_config_path(app)?).await?;
                let _ = app.emit("vpn:log", "sing-box administrator process stopped");
                return Ok(());
            }
        }
        let Some(mut child) = guard.take() else {
            cleanup_desktop_artifacts(&runtime_config_path(app)?).await?;
            return Err(VpnError::NotRunning);
        };
        let kill_result = timeout(DESKTOP_STOP_TIMEOUT, child.kill())
            .await
            .map_err(|_| VpnError::Engine("timed out while stopping sing-box".into()))?;
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
        if !*self.mobile_connected.lock().await {
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
        *self.mobile_connected.lock().await = false;
        let _ = app.emit("vpn:log", "native mobile VPN stop requested");
        Ok(())
    }

    pub async fn start_stats_polling<R: Runtime>(&self, app: &AppHandle<R>) {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let _ = app;
            return;
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            {
                let mut guard = self.stats_task.lock().unwrap();
                if let Some(task) = guard.take() {
                    task.abort();
                }
            }

            let app = app.clone();
            let task = tauri::async_runtime::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(DESKTOP_STATS_TIMEOUT)
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());
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
                            let _ = app
                                .emit("vpn:log", format!("failed to query traffic stats: {error}"));
                        }
                    }
                }
            });

            if let Ok(mut guard) = self.stats_task.lock() {
                *guard = Some(task);
            }
        }
    }

    pub async fn stop_stats_polling(&self) {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(mut guard) = self.stats_task.lock() {
            if let Some(task) = guard.take() {
                task.abort();
                // On some runtimes, task doesn't immediately stop.
                // We don't wait here because it's async, but we've removed it from the state.
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for SingBoxEngine {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.stats_task.lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectArgs {
    config_json: String,
    profile_id: Option<String>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeStartResponse {
    #[allow(dead_code)]
    started: bool,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeStopResponse {
    #[allow(dead_code)]
    stopped: bool,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeStatusResponse {
    established: bool,
    #[allow(dead_code)]
    last_error: Option<String>,
    active_profile_id: Option<String>,
    uploaded_bytes: Option<u64>,
    downloaded_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsStats {
    upload_total: u64,
    download_total: u64,
}

#[cfg(target_os = "macos")]
async fn wait_for_macos_system_tunnel() -> Result<()> {
    let start = std::time::Instant::now();
    let mut last_error = None;

    while start.elapsed() < MACOS_SYSTEM_TUNNEL_TIMEOUT {
        match crate::macos_vpn::is_vpn_profile_connected() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => last_error = Some(error.to_string()),
        }
        sleep(Duration::from_millis(500)).await;
    }

    let detail = last_error
        .map(|error| format!(" Last status error: {error}"))
        .unwrap_or_default();
    Err(VpnError::Platform(format!(
        "macOS system VPN tunnel did not become connected within {} seconds.{}",
        MACOS_SYSTEM_TUNNEL_TIMEOUT.as_secs(),
        detail
    )))
}

async fn check_config(binary: &Path, config_path: &Path) -> Result<()> {
    let mut command = Command::new(binary);
    command.arg("check").arg("-c").arg(config_path);
    hide_tokio_command_window(&mut command);
    let output = timeout(CONFIG_CHECK_TIMEOUT, command.output())
        .await
        .map_err(|_| VpnError::Engine("sing-box config check timed out".into()))?
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

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
async fn wait_for_desktop_readiness(child: &mut Child) -> Result<Option<std::process::ExitStatus>> {
    for _ in 0..20 {
        if let Some(status) = child.try_wait().map_err(|error| {
            VpnError::Engine(format!("failed to inspect sing-box process: {error}"))
        })? {
            return Ok(Some(status));
        }

        if tcp_connects("127.0.0.1:2080").await || tcp_connects(config::CLASH_API_ADDR).await {
            sleep(Duration::from_millis(700)).await;
            if let Some(status) = child.try_wait().map_err(|error| {
                VpnError::Engine(format!("failed to inspect sing-box process: {error}"))
            })? {
                return Ok(Some(status));
            }
            return Ok(None);
        }

        sleep(Duration::from_millis(300)).await;
    }

    if let Some(status) = child
        .try_wait()
        .map_err(|error| VpnError::Engine(format!("failed to inspect sing-box process: {error}")))?
    {
        return Ok(Some(status));
    }

    Err(VpnError::Engine(
        "sing-box did not open local proxy ports during startup".into(),
    ))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn tcp_connects(addr: &str) -> bool {
    matches!(
        timeout(PORT_PROBE_TIMEOUT, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
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

#[cfg(target_os = "macos")]
async fn start_macos_privileged_sing_box<R: Runtime>(
    app: &AppHandle<R>,
    binary: &Path,
    config_path: &Path,
) -> Result<u32> {
    let log_path = macos_privileged_log_path(config_path);
    let _ = std::fs::remove_file(&log_path);
    let shell_script = format!(
        "cd /; {} run -c {} >> {} 2>&1 < /dev/null & echo $!",
        shell_quote(&binary.to_string_lossy()),
        shell_quote(&config_path.to_string_lossy()),
        shell_quote(&log_path.to_string_lossy())
    );
    let _ = app.emit(
        "vpn:log",
        "macOS administrator approval is required to start the system tunnel",
    );
    let output = run_macos_admin_script(&shell_script).await?;
    output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<u32>().ok())
        .ok_or_else(|| {
            VpnError::Engine(format!(
                "failed to read privileged sing-box pid from osascript output: {}",
                output.trim()
            ))
        })
}

#[cfg(target_os = "macos")]
async fn wait_for_macos_privileged_readiness(pid: u32, config_path: &Path) -> Result<()> {
    for _ in 0..20 {
        if tcp_connects("127.0.0.1:2080").await || tcp_connects(config::CLASH_API_ADDR).await {
            return Ok(());
        }

        if !process_exists(pid).await {
            return Err(VpnError::Engine(format!(
                "sing-box administrator process exited during startup. {}",
                macos_privileged_log_tail(config_path)
            )));
        }

        sleep(Duration::from_millis(500)).await;
    }

    Err(VpnError::Engine(format!(
        "sing-box did not open local proxy ports during startup. {}",
        macos_privileged_log_tail(config_path)
    )))
}

#[cfg(target_os = "macos")]
async fn stop_macos_privileged_sing_box(pid: Option<u32>, config_path: &Path) -> Result<()> {
    let mut commands = Vec::new();
    if let Some(pid) = pid {
        commands.push(format!("kill {}", pid));
    }
    commands.push(format!(
        "pkill -f {}",
        shell_quote(&format!("sing-box.*{}", config_path.display()))
    ));
    commands.push("lsof -tiTCP:2080 -sTCP:LISTEN -a -c sing-box | xargs kill".into());
    let shell_script = format!("{} 2>/dev/null || true", commands.join("; "));
    run_macos_admin_script(&shell_script).await.map(|_| ())
}

#[cfg(target_os = "macos")]
async fn macos_has_sing_box_listener() -> bool {
    Command::new("lsof")
        .args(["-tiTCP:2080", "-sTCP:LISTEN", "-a", "-c", "sing-box"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn macos_has_sing_box_listener_blocking() -> bool {
    std::process::Command::new("lsof")
        .args(["-tiTCP:2080", "-sTCP:LISTEN", "-a", "-c", "sing-box"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
async fn run_macos_admin_script(shell_script: &str) -> Result<String> {
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_string(shell_script)
    );
    let output = timeout(
        MACOS_ADMIN_TIMEOUT,
        Command::new("osascript").arg("-e").arg(script).output(),
    )
    .await
    .map_err(|_| VpnError::Engine("administrator approval timed out".into()))?
    .map_err(|error| {
        VpnError::Engine(format!("failed to request administrator approval: {error}"))
    })?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(VpnError::Engine(format!(
        "administrator command failed: {}",
        stderr.trim()
    )))
}

#[cfg(target_os = "macos")]
async fn process_exists(pid: u32) -> bool {
    Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn macos_privileged_log_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("sing-box.macos.log")
}

#[cfg(target_os = "macos")]
fn macos_privileged_log_tail(config_path: &Path) -> String {
    let log_path = macos_privileged_log_path(config_path);
    let Ok(contents) = std::fs::read_to_string(&log_path) else {
        return format!("Log file: {}", log_path.display());
    };
    let tail = contents
        .lines()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    format!("Log file: {}\n{}", log_path.display(), tail)
}

#[cfg(target_os = "macos")]
fn shell_quote(value: impl AsRef<str>) -> String {
    format!("'{}'", value.as_ref().replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
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
    let status = command.status().map_err(|error| {
        VpnError::Engine(format!(
            "failed to clean up stale Windows TUN state: {error}"
        ))
    })?;

    if status.success() {
        Ok(())
    } else {
        Err(VpnError::Engine(format!(
            "Windows TUN cleanup exited with status {status}"
        )))
    }
}

#[cfg(target_os = "macos")]
async fn cleanup_desktop_artifacts(config_path: &Path) -> Result<()> {
    if macos_has_sing_box_listener().await {
        stop_macos_privileged_sing_box(None, config_path).await?;
        sleep(Duration::from_millis(300)).await;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn cleanup_desktop_artifacts(config_path: &Path) -> Result<()> {
    cleanup_desktop_artifacts_blocking(config_path)?;
    sleep(Duration::from_millis(300)).await;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn cleanup_desktop_artifacts_blocking(_config_path: &Path) -> Result<()> {
    let output = std::process::Command::new("lsof")
        .args(["-tiTCP:2080", "-sTCP:LISTEN", "-a", "-c", "sing-box"])
        .stdin(Stdio::null())
        .output();

    let Ok(output) = output else {
        return Ok(());
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for pid in stdout.lines().map(str::trim).filter(|pid| !pid.is_empty()) {
        let _ = std::process::Command::new("kill")
            .arg(pid)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn cleanup_desktop_artifacts_blocking(config_path: &Path) -> Result<()> {
    if !macos_has_sing_box_listener_blocking() {
        return Ok(());
    }

    let shell_script = format!(
        "pkill -f {} 2>/dev/null || true; lsof -tiTCP:2080 -sTCP:LISTEN -a -c sing-box | xargs kill 2>/dev/null || true",
        shell_quote(&format!("sing-box.*{}", config_path.display()))
    );
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_string(&shell_script)
    );
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            VpnError::Engine(format!(
                "failed to request administrator cleanup on macOS: {error}"
            ))
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(VpnError::Engine(format!(
            "macOS administrator cleanup exited with status {status}"
        )))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
async fn cleanup_desktop_artifacts(_config_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
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
#[allow(dead_code)]
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
