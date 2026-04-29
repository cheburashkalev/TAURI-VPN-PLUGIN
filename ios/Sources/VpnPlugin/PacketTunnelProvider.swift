import NetworkExtension

public final class PacketTunnelProvider: NEPacketTunnelProvider {
  public override func startTunnel(
    options: [String : NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    completionHandler(NSError(
      domain: "KostraVpnPacketTunnel",
      code: 1,
      userInfo: [
        NSLocalizedDescriptionKey: "sing-box mobile/libbox is not integrated with PacketTunnelProvider"
      ]
    ))
  }

  public override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    completionHandler()
  }
}
