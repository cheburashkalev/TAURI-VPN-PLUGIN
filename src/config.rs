use crate::{
    models::{ConnectOptions, RouteMode, TransportKind, VpnProfile, VpnProtocol},
    olcrtc, protocols, Result, VpnError,
};
use serde_json::{json, Value};

pub const CLASH_API_ADDR: &str = "127.0.0.1:19090";
const LOCAL_NETWORK_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub fn generate_sing_box_config(options: &ConnectOptions) -> Result<Value> {
    let validation = protocols::validate(&options.profile);
    if !validation.valid {
        return Err(VpnError::InvalidProfile(validation.errors.join("; ")));
    }

    let outbound = outbound_for_profile(&options.profile)?;
    let route_final = match options.route_mode {
        RouteMode::Global | RouteMode::Rule => "proxy",
    };
    let route_rules = route_rules_for_profile(&options.profile);
    let tun_stack = if cfg!(any(target_os = "android", target_os = "ios")) {
        "gvisor"
    } else {
        "mixed"
    };
    let dns_servers = dns_servers_for_options(options);

    Ok(json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": dns_servers,
            "final": "dns-0"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["198.18.0.1/30"],
                "route_exclude_address": LOCAL_NETWORK_CIDRS,
                "auto_route": true,
                "strict_route": options.kill_switch,
                "stack": tun_stack
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            }
        ],
        "outbounds": [
            outbound,
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rules": route_rules,
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-bootstrap",
            "final": route_final
        },
        "experimental": {
            "clash_api": {
                "external_controller": CLASH_API_ADDR
            }
        }
    }))
}

fn dns_servers_for_options(options: &ConnectOptions) -> Vec<Value> {
    let upstreams = if options.dns.servers.is_empty() {
        vec!["1.1.1.1".to_string()]
    } else {
        options.dns.servers.clone()
    };
    let bootstrap = upstreams
        .first()
        .cloned()
        .unwrap_or_else(|| "1.1.1.1".to_string());

    let mut servers = vec![json!({
        "type": "tcp",
        "tag": "dns-bootstrap",
        "server": bootstrap,
        "server_port": 53
    })];

    servers.extend(upstreams.iter().enumerate().map(|(index, server)| {
        json!({
            "type": "tcp",
            "tag": format!("dns-{index}"),
            "server": server,
            "server_port": 53,
            "detour": "proxy"
        })
    }));

    servers
}

fn route_rules_for_profile(profile: &VpnProfile) -> Vec<Value> {
    let mut rules = vec![
        json!({
            "action": "sniff"
        }),
        json!({
            "protocol": "dns",
            "action": "hijack-dns"
        }),
        json!({
            "network": "udp",
            "port": 53,
            "action": "hijack-dns"
        }),
        json!({
            "ip_cidr": LOCAL_NETWORK_CIDRS,
            "action": "route",
            "outbound": "direct"
        }),
    ];

    if matches!(profile.protocol, VpnProtocol::OlcRtc) {
        rules.extend([
            json!({
                "domain": [
                    "stream.wb.ru",
                    "wbstream01-el.wb.ru"
                ],
                "action": "route",
                "outbound": "direct"
            }),
            json!({
                "network": ["tcp", "udp"],
                "port": [3478, 5349],
                "action": "route",
                "outbound": "direct"
            }),
            json!({
                "network": "tcp",
                "port": 7880,
                "action": "route",
                "outbound": "direct"
            }),
            json!({
                "network": "udp",
                "action": "reject",
                "method": "default"
            }),
        ]);
    }

    rules
}

fn outbound_for_profile(profile: &VpnProfile) -> Result<Value> {
    let mut base = match profile.protocol {
        VpnProtocol::Vless => json!({
            "type": "vless",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "uuid": required(profile.auth.uuid.as_deref(), "uuid")?,
            "flow": profile.extra.get("flow").and_then(Value::as_str).unwrap_or("")
        }),
        VpnProtocol::Vmess => json!({
            "type": "vmess",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "uuid": required(profile.auth.uuid.as_deref(), "uuid")?,
            "security": profile.extra.get("security").and_then(Value::as_str).unwrap_or("auto")
        }),
        VpnProtocol::Trojan => json!({
            "type": "trojan",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "password": required(profile.auth.password.as_deref(), "password")?
        }),
        VpnProtocol::Shadowsocks => json!({
            "type": "shadowsocks",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "method": required(profile.auth.method.as_deref(), "method")?,
            "password": required(profile.auth.password.as_deref(), "password")?
        }),
        VpnProtocol::WireGuard => {
            let wg = profile
                .wireguard
                .as_ref()
                .ok_or_else(|| VpnError::InvalidProfile("wireGuard options are required".into()))?;
            json!({
                "type": "wireguard",
                "tag": "proxy",
                "server": profile.server,
                "server_port": profile.port,
                "private_key": wg.private_key,
                "peer_public_key": wg.peer_public_key,
                "pre_shared_key": wg.pre_shared_key,
                "local_address": wg.local_address,
                "reserved": wg.reserved
            })
        }
        VpnProtocol::Hysteria => json!({
            "type": "hysteria",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "auth_str": required(profile.auth.password.as_deref(), "password")?
        }),
        VpnProtocol::Hysteria2 => json!({
            "type": "hysteria2",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "password": required(profile.auth.password.as_deref(), "password")?
        }),
        VpnProtocol::Tuic => json!({
            "type": "tuic",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "uuid": profile.auth.uuid,
            "password": required(profile.auth.password.as_deref(), "password")?
        }),
        VpnProtocol::Socks => json!({
            "type": "socks",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "username": profile.auth.username,
            "password": profile.auth.password
        }),
        VpnProtocol::Http => json!({
            "type": "http",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "username": profile.auth.username,
            "password": profile.auth.password
        }),
        VpnProtocol::OlcRtc => {
            let (server, port) = olcrtc::local_socks_endpoint(profile)?;
            json!({
                "type": "socks",
                "tag": "proxy",
                "server": server,
                "server_port": port
            })
        }
        VpnProtocol::Tun | VpnProtocol::Mixed => {
            return Err(VpnError::Unsupported(
                "local inbound mode cannot be used as outbound".into(),
            ));
        }
    };

    add_tls(profile, &mut base);
    add_transport(profile, &mut base);
    Ok(base)
}

fn add_tls(profile: &VpnProfile, outbound: &mut Value) {
    if let Some(tls) = &profile.tls {
        if tls.enabled {
            outbound["tls"] = json!({
                "enabled": true,
                "server_name": tls.server_name,
                "alpn": tls.alpn,
                "insecure": tls.insecure,
                "utls": tls.fingerprint.as_ref().map(|fingerprint| json!({
                    "enabled": true,
                    "fingerprint": fingerprint
                }))
            });
        }
    }

    if let Some(reality) = &profile.reality {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": profile.tls.as_ref().and_then(|tls| tls.server_name.clone()),
            "reality": {
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id
            },
            "utls": profile.tls.as_ref().and_then(|tls| tls.fingerprint.as_ref()).map(|fingerprint| json!({
                "enabled": true,
                "fingerprint": fingerprint
            }))
        });
    }
}

fn add_transport(profile: &VpnProfile, outbound: &mut Value) {
    match profile.transport.kind {
        TransportKind::Tcp => {}
        TransportKind::WebSocket => {
            outbound["transport"] = json!({
                "type": "ws",
                "path": profile.transport.path,
                "headers": profile.transport.headers
            });
        }
        TransportKind::Grpc => {
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": profile.transport.service_name
            });
        }
        TransportKind::HttpUpgrade => {
            outbound["transport"] = json!({
                "type": "httpupgrade",
                "path": profile.transport.path,
                "host": profile.transport.host
            });
        }
        TransportKind::Xhttp => {
            outbound["transport"] = json!({
                "type": "xhttp",
                "path": profile.transport.path,
                "host": profile.transport.host
            });
        }
        TransportKind::Quic => {
            outbound["transport"] = json!({ "type": "quic" });
        }
    }
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| VpnError::InvalidProfile(format!("{field} is required")))
}
