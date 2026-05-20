use crate::{Result, VpnError};
use block2::RcBlock;
use objc2::{
    rc::Retained,
    runtime::{AnyObject, ProtocolObject},
    ClassType,
};
use objc2_foundation::{NSArray, NSCopying, NSDictionary, NSError, NSObjectProtocol, NSString};
use objc2_network_extension::{
    NETunnelProviderManager, NETunnelProviderProtocol, NETunnelProviderSession, NEVPNStatus,
};
use std::sync::mpsc;
use std::time::Duration;

const TUNNEL_DESCRIPTION: &str = "KOSTRA VPN";
const PROVIDER_BUNDLE_IDENTIFIER: &str = "com.kostravpn.macos.PacketTunnel";

pub fn install_vpn_profile() -> Result<()> {
    save_vpn_profile(None, None)
}

pub fn start_vpn_profile(config_json: &str, profile_id: Option<&str>) -> Result<()> {
    save_vpn_profile(Some(config_json), profile_id)?;

    let manager = load_manager()?;
    let connection = unsafe { manager.connection() };
    let key = NSString::from_str("configContent");
    let value = NSString::from_str(config_json);
    let key_object: &NSString = key.as_ref();
    let value_object: &AnyObject = value.as_super();
    let options = unsafe {
        NSDictionary::<NSString, AnyObject>::dictionaryWithObject_forKey(
            value_object,
            ProtocolObject::<dyn NSCopying>::from_ref(key_object),
        )
    };

    if !connection.isKindOfClass(NETunnelProviderSession::class()) {
        return Err(VpnError::Platform(
            "macOS VPN connection is not a NETunnelProviderSession".into(),
        ));
    }
    let session: Retained<NETunnelProviderSession> =
        unsafe { Retained::cast_unchecked(connection) };

    unsafe {
        session
            .startTunnelWithOptions_andReturnError(Some(&options))
            .map_err(|error| {
                VpnError::Platform(format!(
                    "failed to start macOS system VPN tunnel: {}",
                    error.localizedDescription()
                ))
            })?;
    }

    Ok(())
}

pub fn stop_vpn_profile() -> Result<()> {
    let manager = load_manager()?;
    unsafe {
        manager.connection().stopVPNTunnel();
    }
    Ok(())
}

pub fn vpn_profile_status() -> Result<NEVPNStatus> {
    let manager = load_manager()?;
    Ok(unsafe { manager.connection().status() })
}

pub fn is_vpn_profile_connected() -> Result<bool> {
    Ok(matches!(
        vpn_profile_status()?,
        NEVPNStatus::Connected | NEVPNStatus::Reasserting
    ))
}

fn save_vpn_profile(_config_json: Option<&str>, profile_id: Option<&str>) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let description = TUNNEL_DESCRIPTION.to_string();
    let provider_bundle_identifier = PROVIDER_BUNDLE_IDENTIFIER.to_string();
    let profile_id = profile_id.unwrap_or_default().to_string();

    let load_block = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            if !error.is_null() {
                let _ = tx.send(Err(format!(
                    "failed to load macOS VPN preferences: {}",
                    ns_error_description(error)
                )));
                return;
            }

            let manager = unsafe {
                find_manager(managers, &description)
                    .unwrap_or_else(|| NETunnelProviderManager::new())
            };
            let protocol = unsafe { NETunnelProviderProtocol::new() };
            let provider = NSString::from_str(&provider_bundle_identifier);
            let server_address = NSString::from_str(TUNNEL_DESCRIPTION);
            let localized_description = NSString::from_str(TUNNEL_DESCRIPTION);

            unsafe {
                protocol.setProviderBundleIdentifier(Some(&provider));
                protocol.setServerAddress(Some(&server_address));
                if !profile_id.is_empty() {
                    let key = NSString::from_str("activeProfileId");
                    let value = NSString::from_str(&profile_id);
                    let key_object: &NSString = key.as_ref();
                    let value_object: &objc2::runtime::AnyObject = value.as_super();
                    let provider_configuration =
                        NSDictionary::<NSString, objc2::runtime::AnyObject>::dictionaryWithObject_forKey(
                            value_object,
                            ProtocolObject::<dyn NSCopying>::from_ref(key_object),
                        );
                    protocol.setProviderConfiguration(Some(&provider_configuration));
                }
                manager.setProtocolConfiguration(Some(protocol.as_super()));
                manager.setLocalizedDescription(Some(&localized_description));
                manager.setEnabled(true);
            }

            let save_tx = tx.clone();
            let save_block = RcBlock::new(move |error: *mut NSError| {
                if error.is_null() {
                    let _ = save_tx.send(Ok(()));
                } else {
                    let _ = save_tx.send(Err(format!(
                        "failed to save macOS VPN preferences: {}",
                        ns_error_description(error)
                    )));
                }
            });

            unsafe {
                manager.saveToPreferencesWithCompletionHandler(Some(&save_block));
            }
        },
    );

    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&load_block);
    }

    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| VpnError::Platform("timed out while adding KOSTRA VPN to macOS VPN settings".into()))?
        .map_err(|error| VpnError::Platform(format!("{error}. Check the app signature, NetworkExtension entitlement, provisioning profile, and embedded PacketTunnel extension.")))
}

fn load_manager() -> Result<Retained<NETunnelProviderManager>> {
    let (tx, rx) = mpsc::channel();
    let description = TUNNEL_DESCRIPTION.to_string();

    let load_block = RcBlock::new(
        move |managers: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
            if !error.is_null() {
                let _ = tx.send(Err(format!(
                    "failed to reload macOS VPN preferences: {}",
                    ns_error_description(error)
                )));
                return;
            }

            let manager = unsafe { find_manager(managers, &description) };
            let _ = tx.send(manager.ok_or_else(|| {
                "KOSTRA VPN profile was not found in macOS VPN settings".to_string()
            }));
        },
    );

    unsafe {
        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&load_block);
    }

    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| {
            VpnError::Platform("timed out while loading KOSTRA VPN from macOS VPN settings".into())
        })?
        .map_err(VpnError::Platform)
}

unsafe fn find_manager(
    managers: *mut NSArray<NETunnelProviderManager>,
    description: &str,
) -> Option<Retained<NETunnelProviderManager>> {
    let managers = unsafe { Retained::retain(managers)? };
    for manager in managers.iter() {
        let current = unsafe { manager.localizedDescription() };
        if current.as_deref().map(|value| value.to_string()) == Some(description.to_string()) {
            return Some(manager.clone());
        }
    }
    None
}

fn ns_error_description(error: *mut NSError) -> String {
    unsafe {
        Retained::retain(error)
            .map(|error| error.localizedDescription().to_string())
            .unwrap_or_else(|| "unknown NSError".into())
    }
}
