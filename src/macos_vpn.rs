use crate::{Result, VpnError};
use block2::RcBlock;
use objc2::{rc::Retained, ClassType};
use objc2_foundation::{NSArray, NSError, NSString};
use objc2_network_extension::{NETunnelProviderManager, NETunnelProviderProtocol};
use std::sync::mpsc;
use std::time::Duration;

const TUNNEL_DESCRIPTION: &str = "KOSTRA VPN";
const PROVIDER_BUNDLE_IDENTIFIER: &str = "com.kostravpn.app.PacketTunnel";

pub fn install_vpn_profile() -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let description = TUNNEL_DESCRIPTION.to_string();
    let provider_bundle_identifier = PROVIDER_BUNDLE_IDENTIFIER.to_string();

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
