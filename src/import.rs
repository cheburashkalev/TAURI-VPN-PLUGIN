use crate::{
    errors::{Result, VpnError},
    models::{
        AuthOptions, ImportedServer, RealityOptions, TlsOptions, Transport, TransportKind,
        VpnProfile, VpnProtocol,
    },
};
use base64::{engine::general_purpose, Engine as _};
use std::collections::BTreeMap;
use url::Url;
use uuid::Uuid;

pub fn import_server(input: &str) -> Result<ImportedServer> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(VpnError::Import("empty import input".into()));
    }

    let profile = if trimmed.starts_with("vmess://") {
        parse_vmess(trimmed)?
    } else if trimmed.starts_with("ss://") {
        parse_shadowsocks(trimmed)?
    } else {
        parse_url_profile(trimmed)?
    };

    Ok(ImportedServer {
        profile,
        warnings: Vec::new(),
    })
}

fn parse_url_profile(input: &str) -> Result<VpnProfile> {
    let url = Url::parse(input)?;
    let protocol = match url.scheme() {
        "vless" => VpnProtocol::Vless,
        "trojan" => VpnProtocol::Trojan,
        "wireguard" | "wg" => VpnProtocol::WireGuard,
        "hysteria" => VpnProtocol::Hysteria,
        "hysteria2" | "hy2" => VpnProtocol::Hysteria2,
        "tuic" => VpnProtocol::Tuic,
        "socks" | "socks5" => VpnProtocol::Socks,
        "http" | "https" => VpnProtocol::Http,
        "olcrtc" | "olcrtc+wbstream" | "wbstream" => VpnProtocol::OlcRtc,
        other => return Err(VpnError::Import(format!("unsupported URI scheme {other}"))),
    };

    let query = query_map(&url);
    let name = fragment_name(&url).unwrap_or_else(|| {
        url.host_str()
            .map(String::from)
            .unwrap_or_else(|| protocol_name(protocol).into())
    });
    let server = if matches!(protocol, VpnProtocol::OlcRtc) {
        parse_olcrtc_room_id(&url, &query)?
    } else {
        url.host_str()
            .ok_or_else(|| VpnError::Import("server host is required".into()))?
            .to_string()
    };
    let port = url.port().unwrap_or(default_port(protocol));
    let credential = url.username().to_string();
    let password = url.password().map(String::from);

    let auth = match protocol {
        VpnProtocol::Vless => AuthOptions {
            uuid: Some(credential),
            password: None,
            method: None,
            username: None,
        },
        VpnProtocol::Trojan
        | VpnProtocol::Hysteria
        | VpnProtocol::Hysteria2
        | VpnProtocol::Tuic => AuthOptions {
            uuid: query.get("uuid").cloned(),
            password: Some(percent_decode(&credential)),
            method: None,
            username: None,
        },
        VpnProtocol::Socks | VpnProtocol::Http => AuthOptions {
            uuid: None,
            password,
            method: None,
            username: if credential.is_empty() {
                None
            } else {
                Some(percent_decode(&credential))
            },
        },
        VpnProtocol::OlcRtc => AuthOptions {
            uuid: None,
            password: query
                .get("key")
                .cloned()
                .or(password)
                .or_else(|| (!credential.is_empty()).then(|| percent_decode(&credential))),
            method: None,
            username: None,
        },
        _ => AuthOptions {
            uuid: None,
            password: password.or_else(|| Some(percent_decode(&credential))),
            method: None,
            username: None,
        },
    };

    Ok(VpnProfile {
        id: Uuid::new_v4(),
        name,
        protocol,
        server,
        port,
        auth,
        transport: parse_transport(&query),
        tls: parse_tls(&query),
        reality: parse_reality(&query),
        wireguard: None,
        extra: query
            .into_iter()
            .map(|(key, value)| (key, serde_json::Value::String(value)))
            .collect(),
    })
}

fn parse_vmess(input: &str) -> Result<VpnProfile> {
    let encoded = input.trim_start_matches("vmess://");
    let decoded = decode_base64(encoded)?;
    let json: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|error| VpnError::Import(format!("invalid vmess json: {error}")))?;

    Ok(VpnProfile {
        id: Uuid::new_v4(),
        name: json["ps"].as_str().unwrap_or("VMess").into(),
        protocol: VpnProtocol::Vmess,
        server: json["add"].as_str().unwrap_or_default().into(),
        port: json["port"]
            .as_str()
            .and_then(|port| port.parse().ok())
            .or_else(|| json["port"].as_u64().map(|port| port as u16))
            .unwrap_or(443),
        auth: AuthOptions {
            uuid: json["id"].as_str().map(String::from),
            password: None,
            method: None,
            username: None,
        },
        transport: Transport {
            kind: match json["net"].as_str().unwrap_or("tcp") {
                "ws" => TransportKind::WebSocket,
                "grpc" => TransportKind::Grpc,
                "httpupgrade" => TransportKind::HttpUpgrade,
                "xhttp" => TransportKind::Xhttp,
                "quic" => TransportKind::Quic,
                _ => TransportKind::Tcp,
            },
            path: json["path"].as_str().map(String::from),
            host: json["host"].as_str().map(String::from),
            service_name: json["path"].as_str().map(String::from),
            headers: BTreeMap::new(),
        },
        tls: Some(TlsOptions {
            enabled: matches!(json["tls"].as_str(), Some("tls") | Some("reality")),
            server_name: json["sni"]
                .as_str()
                .or_else(|| json["host"].as_str())
                .map(String::from),
            alpn: Vec::new(),
            insecure: false,
            fingerprint: json["fp"].as_str().map(String::from),
        }),
        reality: None,
        wireguard: None,
        extra: BTreeMap::new(),
    })
}

fn parse_shadowsocks(input: &str) -> Result<VpnProfile> {
    let without_scheme = input.trim_start_matches("ss://");
    let mut parts = without_scheme.splitn(2, '#');
    let main = parts.next().unwrap_or_default();
    let name = parts
        .next()
        .map(percent_decode)
        .unwrap_or_else(|| "Shadowsocks".into());

    let decoded_main = if main.contains('@') {
        main.to_string()
    } else {
        String::from_utf8(decode_base64(main)?)
            .map_err(|error| VpnError::Import(format!("invalid shadowsocks base64: {error}")))?
    };
    let url = Url::parse(&format!("ss://{decoded_main}"))?;
    let userinfo = format!(
        "{}{}",
        url.username(),
        url.password()
            .map(|password| format!(":{password}"))
            .unwrap_or_default()
    );
    let decoded_userinfo = if userinfo.contains(':') {
        userinfo
    } else {
        String::from_utf8(decode_base64(&userinfo)?).map_err(|error| {
            VpnError::Import(format!("invalid shadowsocks credentials: {error}"))
        })?
    };
    let (method, password) = decoded_userinfo
        .split_once(':')
        .ok_or_else(|| VpnError::Import("shadowsocks method:password is required".into()))?;

    Ok(VpnProfile {
        id: Uuid::new_v4(),
        name,
        protocol: VpnProtocol::Shadowsocks,
        server: url.host_str().unwrap_or_default().into(),
        port: url.port().unwrap_or(8388),
        auth: AuthOptions {
            uuid: None,
            password: Some(password.into()),
            method: Some(method.into()),
            username: None,
        },
        transport: Transport::default(),
        tls: None,
        reality: None,
        wireguard: None,
        extra: BTreeMap::new(),
    })
}

fn parse_transport(query: &BTreeMap<String, String>) -> Transport {
    let kind = match query
        .get("type")
        .or_else(|| query.get("security"))
        .map(String::as_str)
    {
        Some("ws") | Some("websocket") => TransportKind::WebSocket,
        Some("grpc") => TransportKind::Grpc,
        Some("httpupgrade") => TransportKind::HttpUpgrade,
        Some("xhttp") => TransportKind::Xhttp,
        Some("quic") => TransportKind::Quic,
        _ => TransportKind::Tcp,
    };

    Transport {
        kind,
        path: query.get("path").cloned(),
        host: query.get("host").cloned(),
        service_name: query
            .get("serviceName")
            .or_else(|| query.get("service_name"))
            .cloned(),
        headers: BTreeMap::new(),
    }
}

fn parse_tls(query: &BTreeMap<String, String>) -> Option<TlsOptions> {
    let security = query.get("security").map(String::as_str);
    let enabled = matches!(security, Some("tls") | Some("reality")) || query.contains_key("sni");
    enabled.then(|| TlsOptions {
        enabled,
        server_name: query.get("sni").or_else(|| query.get("peer")).cloned(),
        alpn: query
            .get("alpn")
            .map(|value| value.split(',').map(String::from).collect())
            .unwrap_or_default(),
        insecure: query
            .get("allowInsecure")
            .is_some_and(|value| value == "1" || value == "true"),
        fingerprint: query.get("fp").cloned(),
    })
}

fn parse_reality(query: &BTreeMap<String, String>) -> Option<RealityOptions> {
    (query
        .get("security")
        .is_some_and(|value| value == "reality"))
    .then(|| RealityOptions {
        public_key: query.get("pbk").cloned().unwrap_or_default(),
        short_id: query.get("sid").cloned(),
        spider_x: query.get("spx").cloned(),
    })
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn fragment_name(url: &Url) -> Option<String> {
    url.fragment()
        .map(percent_decode)
        .filter(|value| !value.trim().is_empty())
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let normalized = input.replace('-', "+").replace('_', "/");
    let padded = match normalized.len() % 4 {
        0 => normalized,
        missing => format!("{}{}", normalized, "=".repeat(4 - missing)),
    };
    general_purpose::STANDARD
        .decode(padded)
        .map_err(|error| VpnError::Import(format!("invalid base64: {error}")))
}

fn percent_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .map(|(key, value)| format!("{key}{value}"))
        .next()
        .unwrap_or_else(|| value.into())
}

fn protocol_name(protocol: VpnProtocol) -> &'static str {
    match protocol {
        VpnProtocol::Vless => "VLESS",
        VpnProtocol::Vmess => "VMess",
        VpnProtocol::Trojan => "Trojan",
        VpnProtocol::Shadowsocks => "Shadowsocks",
        VpnProtocol::WireGuard => "WireGuard",
        VpnProtocol::Hysteria => "Hysteria",
        VpnProtocol::Hysteria2 => "Hysteria2",
        VpnProtocol::Tuic => "TUIC",
        VpnProtocol::Tun => "TUN",
        VpnProtocol::Mixed => "Mixed",
        VpnProtocol::Socks => "SOCKS",
        VpnProtocol::Http => "HTTP",
        VpnProtocol::OlcRtc => "OLC RTC",
    }
}

fn default_port(protocol: VpnProtocol) -> u16 {
    match protocol {
        VpnProtocol::Shadowsocks => 8388,
        VpnProtocol::Socks => 1080,
        VpnProtocol::Http => 8080,
        VpnProtocol::OlcRtc => 443,
        _ => 443,
    }
}

fn parse_olcrtc_room_id(url: &Url, query: &BTreeMap<String, String>) -> Result<String> {
    if let Some(room_id) = query.get("roomId").filter(|value| !value.trim().is_empty()) {
        return Ok(room_id.clone());
    }

    let host = url.host_str().unwrap_or_default();
    let path = url.path().trim_start_matches('/');
    let room_id = if matches!(host, "wb_stream" | "wbstream") && !path.is_empty() {
        path
    } else {
        host
    };

    if room_id.trim().is_empty() {
        return Err(VpnError::Import("OLC RTC room id is required".into()));
    }

    Ok(room_id.into())
}
