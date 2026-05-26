use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VpnProfile {
    pub id: Uuid,
    pub name: String,
    pub protocol: VpnProtocol,
    pub server: String,
    pub port: u16,
    pub auth: AuthOptions,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: Option<TlsOptions>,
    #[serde(default)]
    pub reality: Option<RealityOptions>,
    #[serde(default)]
    pub wireguard: Option<WireGuardOptions>,
    #[serde(default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthOptions {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VpnProtocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    WireGuard,
    Hysteria,
    Hysteria2,
    Tuic,
    Tun,
    Mixed,
    Socks,
    Http,
    OlcRtc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Transport {
    pub kind: TransportKind,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            kind: TransportKind::Tcp,
            path: None,
            host: None,
            service_name: None,
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    Tcp,
    WebSocket,
    Grpc,
    HttpUpgrade,
    Xhttp,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TlsOptions {
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RealityOptions {
    pub public_key: String,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardOptions {
    pub private_key: String,
    #[serde(default)]
    pub peer_public_key: Option<String>,
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    #[serde(default)]
    pub local_address: Vec<String>,
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsOptions {
    pub strategy: DnsStrategy,
    pub servers: Vec<String>,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            strategy: DnsStrategy::Ipv4Only,
            servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsStrategy {
    Ipv4Only,
    Ipv6Only,
    PreferIpv4,
    PreferIpv6,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMode {
    #[default]
    Global,
    Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectOptions {
    pub profile: VpnProfile,
    #[serde(default)]
    pub route_mode: RouteMode,
    #[serde(default)]
    pub route_bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub dns: DnsOptions,
    #[serde(default)]
    pub kill_switch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedServer {
    pub profile: VpnProfile,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolInfo {
    pub protocol: VpnProtocol,
    pub display_name: String,
    pub supported_on: Vec<String>,
    pub uri_schemes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionPhase {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatus {
    pub phase: ConnectionPhase,
    #[serde(default)]
    pub active_profile_id: Option<Uuid>,
    #[serde(default)]
    pub message: Option<String>,
    pub stats: TrafficStats,
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        Self {
            phase: ConnectionPhase::Disconnected,
            active_profile_id: None,
            message: None,
            stats: TrafficStats {
                uploaded_bytes: 0,
                downloaded_bytes: 0,
            },
        }
    }
}
