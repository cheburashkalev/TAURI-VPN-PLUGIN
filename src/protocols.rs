use crate::{
    models::{ProtocolInfo, TransportKind, ValidationResult, VpnProfile, VpnProtocol},
    platform,
};

pub fn list_protocols() -> Vec<ProtocolInfo> {
    let platforms = platform::supported_platforms();
    [
        (VpnProtocol::Vless, "VLESS", vec!["vless"]),
        (VpnProtocol::Vmess, "VMess", vec!["vmess"]),
        (VpnProtocol::Trojan, "Trojan", vec!["trojan"]),
        (VpnProtocol::Shadowsocks, "Shadowsocks", vec!["ss"]),
        (VpnProtocol::WireGuard, "WireGuard", vec!["wireguard", "wg"]),
        (VpnProtocol::Hysteria, "Hysteria", vec!["hysteria"]),
        (
            VpnProtocol::Hysteria2,
            "Hysteria2",
            vec!["hysteria2", "hy2"],
        ),
        (VpnProtocol::Tuic, "TUIC", vec!["tuic"]),
        (VpnProtocol::Tun, "TUN", vec![]),
        (VpnProtocol::Mixed, "Mixed", vec![]),
        (VpnProtocol::Socks, "SOCKS", vec!["socks", "socks5"]),
        (VpnProtocol::Http, "HTTP", vec!["http", "https"]),
        (
            VpnProtocol::OlcRtc,
            "OLC RTC",
            vec!["olcrtc", "olcrtc+wbstream", "wbstream"],
        ),
    ]
    .into_iter()
    .map(|(protocol, display_name, uri_schemes)| ProtocolInfo {
        protocol,
        display_name: display_name.into(),
        supported_on: platforms.clone(),
        uri_schemes: uri_schemes.into_iter().map(String::from).collect(),
    })
    .collect()
}

pub fn validate(profile: &VpnProfile) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if profile.name.trim().is_empty() {
        errors.push("name is required".into());
    }
    if profile.server.trim().is_empty() {
        errors.push("server is required".into());
    }
    if profile.port == 0 {
        errors.push("port must be greater than zero".into());
    }

    match profile.protocol {
        VpnProtocol::Vless | VpnProtocol::Vmess => {
            if profile.auth.uuid.as_deref().unwrap_or_default().is_empty() {
                errors.push("uuid is required".into());
            }
        }
        VpnProtocol::Trojan
        | VpnProtocol::Hysteria
        | VpnProtocol::Hysteria2
        | VpnProtocol::Tuic => {
            if profile
                .auth
                .password
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                errors.push("password is required".into());
            }
        }
        VpnProtocol::Shadowsocks => {
            if profile
                .auth
                .password
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                errors.push("password is required".into());
            }
            if profile
                .auth
                .method
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                errors.push("cipher method is required".into());
            }
        }
        VpnProtocol::WireGuard => {
            if profile.wireguard.is_none() {
                errors.push("wireGuard options are required".into());
            }
        }
        VpnProtocol::Tun | VpnProtocol::Mixed => {
            errors.push("local inbound modes cannot be used as remote server protocols".into());
        }
        VpnProtocol::Socks | VpnProtocol::Http => {
            warnings.push(
                "SOCKS/HTTP are proxy protocols and may not provide full VPN semantics".into(),
            );
        }
        VpnProtocol::OlcRtc => {
            if profile
                .auth
                .password
                .as_deref()
                .unwrap_or_default()
                .is_empty()
            {
                errors.push("OLC RTC shared key is required".into());
            }
            if let Some(key) = profile.auth.password.as_deref() {
                if key.len() != 64 || !key.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    errors.push("OLC RTC shared key must be a 32-byte hex string".into());
                }
            }
            let provider = profile
                .extra
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("wb_stream");
            if provider != "wb_stream" {
                errors.push("only OLC RTC wb_stream provider is supported".into());
            }
        }
    }

    if profile.reality.is_some() && !matches!(profile.protocol, VpnProtocol::Vless) {
        errors.push("REALITY options are only supported for VLESS".into());
    }
    if matches!(profile.transport.kind, TransportKind::Xhttp) {
        warnings.push("XHTTP compatibility depends on the bundled sing-box version".into());
    }
    if matches!(profile.protocol, VpnProtocol::OlcRtc) {
        warnings.push(
            "OLC RTC starts a local SOCKS5 client and routes sing-box through stream.wb.ru".into(),
        );
    }

    ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}
