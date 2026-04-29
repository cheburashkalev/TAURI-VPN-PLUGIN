import Foundation
import NetworkExtension
import Tauri

struct ConnectArgs: Decodable {
  let configJson: String
}

@objc public class VpnPlugin: Plugin {
  private let tunnelDescription = "KOSTRA VPN"

  @objc public func requestVpnPermission(_ invoke: Invoke) throws {
    // iOS shows the VPN consent dialog when the tunnel preferences are saved.
    invoke.resolve(["granted": true])
  }

  @objc public func startNativeVpn(_ invoke: Invoke) throws {
    _ = try invoke.parseArgs(ConnectArgs.self)
    invoke.reject(
      "iOS VPN packet runtime is not wired yet. The scaffold will not start a dummy PacketTunnel because it would route traffic into a blackhole. Integrate sing-box mobile/libbox in PacketTunnelProvider before enabling iOS connect.",
      code: "MOBILE_RUNTIME_NOT_IMPLEMENTED"
    )
  }

  @objc public func stopNativeVpn(_ invoke: Invoke) throws {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
      guard let self = self else { return }
      if let error = error {
        invoke.reject("failed to load iOS VPN preferences: \(error.localizedDescription)", code: "IOS_VPN_LOAD")
        return
      }

      let manager = managers?.first(where: { $0.localizedDescription == self.tunnelDescription })
      manager?.connection.stopVPNTunnel()
      invoke.resolve(["stopped": true])
    }
  }

  private func packetTunnelBundleIdentifier() -> String {
    if let configured = Bundle.main.object(forInfoDictionaryKey: "KostraVpnPacketTunnelBundleId") as? String,
       !configured.isEmpty {
      return configured
    }
    return "\(Bundle.main.bundleIdentifier ?? "com.kostra.vpn").PacketTunnel"
  }
}

@_cdecl("init_plugin_vpn")
public func initPluginVpn() -> UnsafeMutableRawPointer {
  return Unmanaged.passRetained(VpnPlugin()).toOpaque()
}
