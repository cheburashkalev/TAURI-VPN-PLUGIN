mod client;
mod crypto;
mod mux;
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
mod wbstream;

use crate::{models::VpnProfile, Result, VpnError};
use serde_json::Value;

pub use client::OlcRtcRuntime;

const DEFAULT_PROVIDER: &str = "wb_stream";
const DEFAULT_LOCAL_HOST: &str = "127.0.0.1";
const DEFAULT_LOCAL_PORT: u16 = 10808;

#[derive(Debug, Clone)]
pub struct OlcRtcConfig {
    pub provider: String,
    pub room_id: String,
    pub key_hex: String,
    pub local_host: String,
    pub local_port: u16,
    pub display_name: String,
}

impl OlcRtcConfig {
    pub fn from_profile(profile: &VpnProfile) -> Result<Self> {
        let provider = string_extra(profile, "provider").unwrap_or_else(|| DEFAULT_PROVIDER.into());
        if provider != DEFAULT_PROVIDER {
            return Err(VpnError::Unsupported(format!(
                "unsupported OLC RTC provider {provider}"
            )));
        }

        let room_id = string_extra(profile, "roomId").unwrap_or_else(|| profile.server.clone());
        if room_id.trim().is_empty() {
            return Err(VpnError::InvalidProfile(
                "OLC RTC room id is required".into(),
            ));
        }

        let key_hex = string_extra(profile, "key")
            .or_else(|| profile.auth.password.clone())
            .ok_or_else(|| VpnError::InvalidProfile("OLC RTC shared key is required".into()))?;
        if key_hex.len() != 64 || !key_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(VpnError::InvalidProfile(
                "OLC RTC shared key must be a 32-byte hex string".into(),
            ));
        }

        Ok(Self {
            provider,
            room_id,
            key_hex,
            local_host: string_extra(profile, "localHost")
                .unwrap_or_else(|| DEFAULT_LOCAL_HOST.into()),
            local_port: u16_extra(profile, "localPort").unwrap_or(DEFAULT_LOCAL_PORT),
            display_name: profile.name.clone(),
        })
    }
}

pub fn local_socks_endpoint(profile: &VpnProfile) -> Result<(String, u16)> {
    let config = OlcRtcConfig::from_profile(profile)?;
    Ok((config.local_host, config.local_port))
}

fn string_extra(profile: &VpnProfile, key: &str) -> Option<String> {
    profile
        .extra
        .get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .filter(|value| !value.trim().is_empty())
}

fn u16_extra(profile: &VpnProfile, key: &str) -> Option<u16> {
    match profile.extra.get(key) {
        Some(Value::Number(number)) => number.as_u64().and_then(|value| u16::try_from(value).ok()),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}
