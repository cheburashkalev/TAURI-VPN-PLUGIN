use tauri_plugin_vpn::{
    config::generate_sing_box_config,
    import::import_server,
    models::{ConnectOptions, DnsOptions, RouteMode},
};

fn options(input: &str) -> ConnectOptions {
    ConnectOptions {
        profile: import_server(input).unwrap().profile,
        route_mode: RouteMode::Global,
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
fn imports_real_3x_ui_vless_reality_grpc_uri() {
    let imported = import_server("vless://4f3d5e71-cca2-40f2-a64a-b81ced26db3a@80.76.43.249:13979?type=grpc&encryption=none&security=reality&sni=www.oracle.com&fp=chrome&pbk=9WSPT5_GkOSL_A0G_HLQCcF0XbBTjvznLMefmpNsUWs&sid=2708a83155a0d13b&spx=%2F#-user_Cheburashka_lev_192c7").unwrap();
    assert_eq!(imported.profile.name, "-user_Cheburashka_lev_192c7");
    assert_eq!(imported.profile.server, "80.76.43.249");
    assert_eq!(imported.profile.port, 13979);
    assert_eq!(
        imported.profile.auth.uuid.as_deref(),
        Some("4f3d5e71-cca2-40f2-a64a-b81ced26db3a")
    );
    assert!(imported.profile.reality.is_some());
}

#[test]
fn imports_trojan_uri() {
    let imported =
        import_server("trojan://secret@example.com:443?security=tls&sni=example.com#Trojan")
            .unwrap();
    assert_eq!(imported.profile.auth.password.as_deref(), Some("secret"));
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
