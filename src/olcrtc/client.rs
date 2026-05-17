use crate::{
    olcrtc::{crypto::OlcCipher, mux::Multiplexer, OlcRtcConfig},
    Result, VpnError,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time::{timeout, Duration},
};

const TUNNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use crate::olcrtc::wbstream::WbStreamPeer;

pub struct OlcRtcRuntime {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    peer: WbStreamPeer,
}

impl OlcRtcRuntime {
    pub async fn start(config: OlcRtcConfig) -> Result<Self> {
        start_platform(config).await
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        self.peer.close().await;
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
async fn start_platform(config: OlcRtcConfig) -> Result<OlcRtcRuntime> {
    if config.provider != "wb_stream" {
        return Err(VpnError::Unsupported(format!(
            "unsupported OLC RTC provider {}",
            config.provider
        )));
    }

    let local_addr = format!("{}:{}", config.local_host, config.local_port)
        .parse::<SocketAddr>()
        .map_err(|error| {
            VpnError::InvalidProfile(format!("invalid OLC RTC local address: {error}"))
        })?;

    let listener = TcpListener::bind(local_addr)
        .await
        .map_err(|error| VpnError::Engine(format!("OLC RTC SOCKS5 bind failed: {error}")))?;

    let cipher = OlcCipher::from_hex(&config.key_hex)?;
    let (peer, mut incoming) = WbStreamPeer::connect(&config).await?;
    let peer_for_mux = peer.clone();
    let cipher_for_mux = cipher.clone();

    let mux = Arc::new(Multiplexer::new(random_client_id(), move |frame| {
        let cipher = cipher_for_mux.clone();
        let peer = peer_for_mux.clone();
        Box::pin(async move {
            let encrypted = cipher.encrypt(&frame)?;
            peer.send(encrypted).await
        })
    }));

    mux.send_client_reset().await?;

    let mux_for_incoming = mux.clone();
    tokio::spawn(async move {
        while let Some(data) = incoming.recv().await {
            match cipher.decrypt(&data) {
                Ok(frame) => mux_for_incoming.handle_frame(&frame).await,
                Err(_) => continue,
            }
        }
    });

    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, mux, shutdown_rx));

    Ok(OlcRtcRuntime {
        shutdown,
        task,
        peer,
    })
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
async fn start_platform(_config: OlcRtcConfig) -> Result<OlcRtcRuntime> {
    Err(VpnError::Unsupported(
        "OLC RTC Rust client is currently enabled for Windows/macOS/Linux desktop only".into(),
    ))
}

async fn accept_loop(
    listener: TcpListener,
    mux: Arc<Multiplexer>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let mux = mux.clone();
                        tokio::spawn(async move {
                            let _ = handle_socks5(stream, mux).await;
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn handle_socks5(mut stream: TcpStream, mux: Arc<Multiplexer>) -> Result<()> {
    socks5_handshake(&mut stream).await?;
    let (addr, port) = socks5_request(&mut stream).await?;
    let sid = mux.open_stream().await;

    if let Err(error) = setup_tunnel(&mut stream, &mux, sid, &addr, port).await {
        let _ = mux.close_stream(sid).await;
        return Err(error);
    }

    let (reader, writer) = stream.into_split();
    let to_mux = pump_to_mux(reader, mux.clone(), sid);
    let from_mux = pump_from_mux(writer, mux.clone(), sid);
    tokio::select! {
        _ = to_mux => {}
        _ = from_mux => {}
    }
    let _ = mux.close_stream(sid).await;
    Ok(())
}

async fn setup_tunnel(
    stream: &mut TcpStream,
    mux: &Multiplexer,
    sid: u16,
    addr: &str,
    port: u16,
) -> Result<()> {
    let request = json!({ "cmd": "connect", "addr": addr, "port": port });
    mux.send_data(sid, request.to_string().as_bytes()).await?;

    match timeout(TUNNEL_SETUP_TIMEOUT, mux.wait_for_data(sid)).await {
        Ok(()) => {
            let response = mux.read_stream(sid).await;
            if response.first() == Some(&0x00) {
                stream.write_all(&reply_success()).await?;
                Ok(())
            } else {
                stream.write_all(&reply_host_unreachable()).await?;
                Err(VpnError::Engine("OLC RTC tunnel setup failed".into()))
            }
        }
        Err(_) => {
            stream.write_all(&reply_host_unreachable()).await?;
            Err(VpnError::Engine("OLC RTC tunnel setup timed out".into()))
        }
    }
}

async fn socks5_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(VpnError::Engine("invalid SOCKS5 version".into()));
    }

    let mut methods = vec![0_u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    Ok(())
}

async fn socks5_request(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 1 {
        return Err(VpnError::Engine(format!(
            "unsupported SOCKS5 command {}",
            header[1]
        )));
    }

    let addr = match header[3] {
        1 => {
            let mut ip = [0_u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|error| VpnError::Engine(format!("invalid SOCKS5 domain: {error}")))?
        }
        4 => {
            let mut ip = [0_u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        other => {
            return Err(VpnError::Engine(format!(
                "unsupported SOCKS5 address type {other}"
            )));
        }
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((addr, u16::from_be_bytes(port)))
}

async fn pump_to_mux(mut reader: tokio::net::tcp::OwnedReadHalf, mux: Arc<Multiplexer>, sid: u16) {
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if mux.send_data(sid, &buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn pump_from_mux(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mux: Arc<Multiplexer>,
    sid: u16,
) {
    loop {
        mux.wait_for_data(sid).await;
        let data = mux.read_stream(sid).await;
        if !data.is_empty() && writer.write_all(&data).await.is_err() {
            break;
        }
        if mux.stream_closed(sid).await {
            break;
        }
    }
}

fn random_client_id() -> u32 {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    u32::from_be_bytes(bytes)
}

fn reply_success() -> [u8; 10] {
    [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
}

fn reply_host_unreachable() -> [u8; 10] {
    [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]
}
