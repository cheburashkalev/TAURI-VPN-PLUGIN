use tauri_plugin_vpn::{
    config::generate_sing_box_config,
    import::import_server,
    models::{ConnectOptions, DnsOptions, DnsStrategy, RouteMode},
};

fn options(input: &str) -> ConnectOptions {
    ConnectOptions {
        profile: import_server(input).unwrap().profile,
        route_mode: RouteMode::Global,
        route_bypass_cidrs: Vec::new(),
        dns: DnsOptions::default(),
        kill_switch: true,
    }
}

#[test]
fn imports_vless_reality_uri() {
    let imported = import_server("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=grpc&sni=www.microsoft.com&pbk=abc&sid=01&fp=chrome#Amsterdam").unwrap();
    assert_eq!(imported.profile.name, "Amsterdam");
    assert_eq!(imported.profile.server, "example.com");
    assert!(imported.profile.reality.is_some());
}

#[test]
fn imports_3x_ui_vless_reality_grpc_uri() {
    let imported = import_server("vless://22222222-2222-4222-8222-222222222222@example.com:13979?type=grpc&encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=TEST_PUBLIC_KEY&sid=01020304&spx=%2F#Reality%20gRPC").unwrap();
    assert_eq!(imported.profile.name, "Reality gRPC");
    assert_eq!(imported.profile.server, "example.com");
    assert_eq!(imported.profile.port, 13979);
    assert_eq!(
        imported.profile.auth.uuid.as_deref(),
        Some("22222222-2222-4222-8222-222222222222")
    );
    assert!(imported.profile.reality.is_some());
}

#[test]
fn imports_trojan_uri() {
    let imported =
        import_server("trojan://test-password@example.com:443?security=tls&sni=example.com#Trojan")
            .unwrap();
    assert_eq!(
        imported.profile.auth.password.as_deref(),
        Some("test-password")
    );
}

#[test]
fn imports_shadowsocks_uri() {
    let imported = import_server("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#SS").unwrap();
    assert_eq!(imported.profile.auth.method.as_deref(), Some("aes-256-gcm"));
}

#[test]
fn generates_sing_box_config() {
    let config = generate_sing_box_config(&options("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#Node")).unwrap();
    assert_eq!(config["outbounds"][0]["type"], "vless");
    assert_eq!(config["inbounds"][0]["type"], "tun");
    assert_eq!(config["route"]["auto_detect_interface"], true);
}

#[test]
fn generates_doh_dns_for_public_resolvers() {
    let config = generate_sing_box_config(&options("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#Node")).unwrap();
    let servers = config["dns"]["servers"].as_array().unwrap();
    let cloudflare = servers
        .iter()
        .find(|server| server["tag"] == "dns-0")
        .unwrap();
    let google = servers
        .iter()
        .find(|server| server["tag"] == "dns-1")
        .unwrap();

    assert_eq!(cloudflare["type"], "https");
    assert_eq!(cloudflare["server"], "1.1.1.1");
    assert_eq!(cloudflare["detour"], "proxy");
    assert_eq!(cloudflare["tls"]["server_name"], "cloudflare-dns.com");
    assert_eq!(google["type"], "https");
    assert_eq!(google["tls"]["server_name"], "dns.google");
}

#[test]
fn keeps_bootstrap_dns_direct() {
    let config = generate_sing_box_config(&options("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#Node")).unwrap();
    let servers = config["dns"]["servers"].as_array().unwrap();
    let bootstrap = servers
        .iter()
        .find(|server| server["tag"] == "dns-bootstrap")
        .unwrap();

    assert_eq!(bootstrap["type"], "udp");
    assert_eq!(bootstrap["server"], "1.1.1.1");
    assert!(bootstrap.get("detour").is_none());
}

#[test]
fn falls_back_to_ipv4_dns_when_configured_servers_are_ipv6_only() {
    let mut options = options("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#Node");
    options.dns = DnsOptions {
        strategy: DnsStrategy::Ipv6Only,
        servers: vec!["2606:4700:4700::1111".into()],
    };

    let config = generate_sing_box_config(&options).unwrap();
    let servers = config["dns"]["servers"].as_array().unwrap();

    assert_eq!(config["dns"]["strategy"], "ipv4_only");
    assert!(servers.iter().any(|server| server["tag"] == "dns-0"));
    assert!(servers.iter().any(|server| server["server"] == "1.1.1.1"));
}

#[test]
fn imports_olcrtc_wbstream_uri() {
    let imported = import_server("olcrtc://room-123?key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&localPort=18080#WB").unwrap();
    assert_eq!(
        imported.profile.protocol,
        tauri_plugin_vpn::models::VpnProtocol::OlcRtc
    );
    assert_eq!(imported.profile.name, "WB");
    assert_eq!(imported.profile.server, "room-123");
    assert_eq!(
        imported.profile.auth.password.as_deref(),
        Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    );
}

#[test]
fn generates_olcrtc_sing_box_socks_outbound() {
    let config = generate_sing_box_config(&options("olcrtc://room-123?key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&localPort=18080#WB")).unwrap();
    assert_eq!(config["outbounds"][0]["type"], "socks");
    assert_eq!(config["outbounds"][0]["server"], "127.0.0.1");
    assert_eq!(config["outbounds"][0]["server_port"], 18080);
}

#[test]
fn generates_olcrtc_transport_bypass_rules() {
    let config = generate_sing_box_config(&options("olcrtc://room-123?key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f&localPort=18080#WB")).unwrap();
    let rules = config["route"]["rules"].as_array().unwrap();

    assert!(rules.iter().any(|rule| {
        rule["outbound"] == "direct"
            && rule["domain"]
                .as_array()
                .is_some_and(|domains| domains.iter().any(|domain| domain == "stream.wb.ru"))
    }));
    assert!(rules.iter().any(|rule| {
        rule["outbound"] == "direct"
            && rule["port"]
                .as_array()
                .is_some_and(|ports| ports.iter().any(|port| port == 3478))
    }));
    assert!(rules
        .iter()
        .any(|rule| rule["network"] == "udp" && rule["action"] == "reject"));
}
