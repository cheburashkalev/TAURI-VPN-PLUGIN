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
    let route_rules = route_rules_for_profile(&options.profile, &options.route_bypass_cidrs);
    let tun_stack = tun_stack_for_profile(&options.profile);
    let tun_mtu = tun_mtu_for_profile(&options.profile);
    let dns_servers = dns_servers_for_options(options);
    let inbounds = vec![json!({
        "type": "tun",
        "tag": "tun-in",
        "address": ["198.18.0.1/30"],
        "mtu": tun_mtu,
        "route_exclude_address": LOCAL_NETWORK_CIDRS,
        "auto_route": true,
        "strict_route": options.kill_switch,
        "endpoint_independent_nat": true,
        "udp_timeout": "5m",
        "stack": tun_stack
    })];

    #[cfg(not(target_os = "macos"))]
    let mut inbounds = inbounds;

    #[cfg(not(target_os = "macos"))]
    inbounds.push(json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": 2080
    }));

    let mut route = json!({
        "rules": route_rules,
        "default_domain_resolver": "dns-bootstrap",
        "final": route_final
    });

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        route["auto_detect_interface"] = json!(true);
    }

    Ok(json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": dns_servers,
            "strategy": "ipv4_only",
            "final": "dns-0"
        },
        "inbounds": inbounds,
        "outbounds": [
            outbound,
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": route,
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
        options
            .dns
            .servers
            .iter()
            .map(|server| server.trim().to_string())
            .filter(|server| !server.is_empty() && !server.contains(':'))
            .collect()
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

    servers.extend(
        upstreams
            .iter()
            .enumerate()
            .map(|(index, server)| dns_server_for_upstream(index, server)),
    );

    servers
}

fn dns_server_for_upstream(index: usize, server: &str) -> Value {
    if let Some(server_name) = public_doh_server_name(server) {
        return json!({
            "type": "https",
            "tag": format!("dns-{index}"),
            "server": server,
            "server_port": 443,
            "path": "/dns-query",
            "detour": "proxy",
            "connect_timeout": "5s",
            "tls": {
                "enabled": true,
                "server_name": server_name
            }
        });
    }

    json!({
        "type": "tcp",
        "tag": format!("dns-{index}"),
        "server": server,
        "server_port": 53,
        "detour": "proxy",
        "connect_timeout": "5s"
    })
}

fn public_doh_server_name(server: &str) -> Option<&'static str> {
    match server {
        "1.1.1.1" | "1.0.0.1" => Some("cloudflare-dns.com"),
        "8.8.8.8" | "8.8.4.4" => Some("dns.google"),
        "9.9.9.9" | "149.112.112.112" => Some("dns.quad9.net"),
        _ => None,
    }
}

fn route_rules_for_profile(profile: &VpnProfile, route_bypass_cidrs: &[String]) -> Vec<Value> {
    let mut rules = vec![
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

    let route_bypass_cidrs: Vec<&str> = route_bypass_cidrs
        .iter()
        .map(|cidr| cidr.trim())
        .filter(|cidr| !cidr.is_empty())
        .collect();
    if !route_bypass_cidrs.is_empty() {
        rules.push(json!({
            "ip_cidr": route_bypass_cidrs,
            "action": "route",
            "outbound": "direct"
        }));
    }

    rules.extend([
        json!({
            "network": "icmp",
            "action": "reject",
            "method": "default"
        }),
        json!({
            "network": ["tcp", "udp"],
            "action": "route",
            "outbound": "proxy"
        }),
    ]);

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

fn tun_stack_for_profile(profile: &VpnProfile) -> &'static str {
    if cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos"
    )) {
        return "gvisor";
    }

    if cfg!(target_os = "windows")
        && matches!(
            profile.protocol,
            VpnProtocol::Hysteria | VpnProtocol::Hysteria2 | VpnProtocol::Tuic
        )
    {
        return "gvisor";
    }

    "mixed"
}

fn tun_mtu_for_profile(profile: &VpnProfile) -> u16 {
    if matches!(
        profile.protocol,
        VpnProtocol::Hysteria | VpnProtocol::Hysteria2 | VpnProtocol::Tuic
    ) {
        return 1500;
    }

    1400
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
            let local_address = ipv4_only_cidrs(&wg.local_address);
            if local_address.is_empty() {
                return Err(VpnError::InvalidProfile(
                    "wireGuard local_address must contain an IPv4 address".into(),
                ));
            }
            json!({
                "type": "wireguard",
                "tag": "proxy",
                "server": profile.server,
                "server_port": profile.port,
                "private_key": wg.private_key,
                "peer_public_key": wg.peer_public_key,
                "pre_shared_key": wg.pre_shared_key,
                "local_address": local_address,
                "reserved": wg.reserved
            })
        }
        VpnProtocol::Hysteria => json!(strip_nulls(json!({
            "type": "hysteria",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "auth_str": required(profile.auth.password.as_deref(), "password")?,
            "up_mbps": 10000,
            "down_mbps": 10000,
            "obfs": profile.extra.get("obfs").and_then(Value::as_str)
        }))),
        VpnProtocol::Hysteria2 => json!(strip_nulls(json!({
            "type": "hysteria2",
            "tag": "proxy",
            "server": profile.server,
            "server_port": profile.port,
            "password": required(profile.auth.password.as_deref(), "password")?,
            "obfs": hysteria2_obfs(profile)
        }))),
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
            let utls = if supports_utls(profile.protocol) {
                tls.fingerprint.as_ref().map(|fingerprint| {
                    json!({
                        "enabled": true,
                        "fingerprint": fingerprint
                    })
                })
            } else {
                None
            };
            outbound["tls"] = json!({
                "enabled": true,
                "server_name": tls.server_name,
                "alpn": tls.alpn,
                "insecure": tls.insecure,
                "utls": utls
            });
        }
    }

    if let Some(reality) = &profile.reality {
        let utls = if supports_utls(profile.protocol) {
            profile
                .tls
                .as_ref()
                .and_then(|tls| tls.fingerprint.as_ref())
                .map(|fingerprint| {
                    json!({
                        "enabled": true,
                        "fingerprint": fingerprint
                    })
                })
        } else {
            None
        };
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": profile.tls.as_ref().and_then(|tls| tls.server_name.clone()),
            "reality": {
                "enabled": true,
                "public_key": reality.public_key,
                "short_id": reality.short_id
            },
            "utls": utls
        });
    }
}

fn supports_utls(protocol: VpnProtocol) -> bool {
    !matches!(
        protocol,
        VpnProtocol::Hysteria | VpnProtocol::Hysteria2 | VpnProtocol::Tuic
    )
}

fn hysteria2_obfs(profile: &VpnProfile) -> Option<Value> {
    let obfs_type = profile.extra.get("obfs").and_then(Value::as_str)?;
    let password = profile
        .extra
        .get("obfs-password")
        .or_else(|| profile.extra.get("obfsPassword"))
        .and_then(Value::as_str)?;
    Some(json!({
        "type": obfs_type,
        "password": password
    }))
}

fn strip_nulls(mut value: Value) -> Value {
    if let Value::Object(map) = &mut value {
        map.retain(|_, item| !item.is_null());
    }
    value
}

fn ipv4_only_cidrs(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && !value.contains(':'))
        .map(str::to_string)
        .collect()
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
