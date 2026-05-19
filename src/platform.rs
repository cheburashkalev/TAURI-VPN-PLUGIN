#![cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]

use crate::{Result, VpnError};

pub fn supported_platforms() -> Vec<String> {
    ["windows", "macos", "linux", "android", "ios"]
        .into_iter()
        .map(String::from)
        .collect()
}

pub fn default_core_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "sing-box.exe"
    } else {
        "sing-box"
    }
}

pub fn check_platform_requirements() -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if cfg!(target_os = "windows") && !is_elevated() {
        return Err(VpnError::Platform(
            "Windows TUN mode requires running KOSTRA VPN as Administrator".into(),
        ));
    }
    if cfg!(target_os = "linux") {
        warnings.push("Linux TUN mode may require CAP_NET_ADMIN or root privileges".into());
    }
    if cfg!(target_os = "macos") {
        warnings.push(
            "macOS system tunnel requires administrator approval to configure the TUN interface"
                .into(),
        );
    }
    if cfg!(target_os = "ios") {
        warnings.push("iOS requires NetworkExtension entitlements and an app group".into());
    }
    if cfg!(target_os = "android") {
        warnings.push("Android requires VpnService consent before connecting".into());
    }
    Ok(warnings)
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned_len = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        result && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    true
}
