import Foundation
import NetworkExtension
import Tauri

struct ConnectArgs: Decodable {
  let configJson: String
  let profileId: String?
}

struct StatusPayload: Encodable {
  let established: Bool
  let activeProfileId: String?
  let uploadedBytes: Int64?
  let downloadedBytes: Int64?
}

@objc public class VpnPlugin: Plugin {
  private let tunnelDescription = "KOSTRA VPN"

  @objc public func requestVpnPermission(_ invoke: Invoke) throws {
    loadOrCreateManager { result in
      switch result {
      case .success(let manager):
        manager.saveToPreferences { error in
          if let error {
            invoke.reject("failed to save VPN preferences: \(error.localizedDescription)", code: "IOS_VPN_SAVE")
          } else {
            invoke.resolve(["granted": true])
          }
        }
      case .failure(let error):
        invoke.reject(error.localizedDescription, code: "IOS_VPN_LOAD")
      }
    }
  }

  @objc public func startNativeVpn(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ConnectArgs.self)
    loadOrCreateManager { result in
      switch result {
      case .success(let manager):
        manager.isEnabled = true
        let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol
        protocolConfiguration?.providerConfiguration = [
          "activeProfileId": args.profileId ?? ""
        ]
        manager.saveToPreferences { error in
          if let error {
            invoke.reject("failed to save VPN preferences: \(error.localizedDescription)", code: "IOS_VPN_SAVE")
            return
          }
          manager.loadFromPreferences { error in
            if let error {
              invoke.reject("failed to reload VPN preferences: \(error.localizedDescription)", code: "IOS_VPN_RELOAD")
              return
            }
            do {
              try manager.connection.startVPNTunnel(options: [
                "configContent": args.configJson as NSString,
                "activeProfileId": (args.profileId ?? "") as NSString
              ])
              invoke.resolve(["started": true])
            } catch {
              invoke.reject("failed to start VPN tunnel: \(error.localizedDescription)", code: "IOS_VPN_START")
            }
          }
        }
      case .failure(let error):
        invoke.reject(error.localizedDescription, code: "IOS_VPN_LOAD")
      }
    }
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

  @objc public func getNativeVpnStatus(_ invoke: Invoke) throws {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] (managers: [NETunnelProviderManager]?, error: Error?) in
      guard let self = self else { return }
      if let error = error {
        invoke.reject("failed to load iOS VPN preferences: \(error.localizedDescription)", code: "IOS_VPN_LOAD")
        return
      }
      let manager = managers?.first(where: { $0.localizedDescription == self.tunnelDescription })
      let status = manager?.connection.status
      let established = status == .connected || status == .reasserting
      let protocolConfiguration = manager?.protocolConfiguration as? NETunnelProviderProtocol
      let activeProfileId = protocolConfiguration?.providerConfiguration?["activeProfileId"] as? String
      invoke.resolve(StatusPayload(
        established: established,
        activeProfileId: activeProfileId?.isEmpty == false ? activeProfileId : nil,
        uploadedBytes: nil,
        downloadedBytes: nil
      ))
    }
  }

  private func packetTunnelBundleIdentifier() -> String {
    if let configured = Bundle.main.object(forInfoDictionaryKey: "KostraVpnPacketTunnelBundleId") as? String,
       !configured.isEmpty {
      return configured
    }
    return "\(Bundle.main.bundleIdentifier ?? "com.kostra.vpn").PacketTunnel"
  }

  private func loadOrCreateManager(completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] (managers: [NETunnelProviderManager]?, error: Error?) in
      guard let self = self else { return }
      if let error = error {
        completion(.failure(error))
        return
      }

      let manager = managers?.first(where: { $0.localizedDescription == self.tunnelDescription })
        ?? NETunnelProviderManager()
      let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol
        ?? NETunnelProviderProtocol()
      protocolConfiguration.providerBundleIdentifier = self.packetTunnelBundleIdentifier()
      protocolConfiguration.serverAddress = "KOSTRA VPN"
      manager.protocolConfiguration = protocolConfiguration
      manager.localizedDescription = self.tunnelDescription
      manager.isEnabled = true
      completion(.success(manager))
    }
  }
}

@_cdecl("init_plugin_vpn")
public func initPluginVpn() -> UnsafeMutableRawPointer {
  return Unmanaged.passRetained(VpnPlugin()).toOpaque()
}
