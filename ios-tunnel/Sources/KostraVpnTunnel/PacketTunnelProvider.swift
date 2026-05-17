import Foundation
import Libbox
import Network
import NetworkExtension

public final class PacketTunnelProvider: NEPacketTunnelProvider {
  fileprivate var commandServer: LibboxCommandServer?
  private lazy var platformInterface = TunnelPlatformInterface(tunnel: self)

  public override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    Task {
      do {
        try await startTunnelAsync(options: options)
        completionHandler(nil)
      } catch {
        completionHandler(error)
      }
    }
  }

  public override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    do {
      try commandServer?.closeService()
    } catch {
      commandServer?.writeMessage(2, message: "close service: \(error.localizedDescription)")
    }
    platformInterface.reset()
    commandServer?.close()
    commandServer = nil
    completionHandler()
  }

  private func startTunnelAsync(options: [String: NSObject]?) async throws {
    guard let configContent = options?["configContent"] as? String, !configContent.isEmpty else {
      throw TunnelError("missing configContent")
    }

    let paths = try TunnelPaths()
    var setupError: NSError?
    let setupOptions = LibboxSetupOptions()
    setupOptions.basePath = paths.basePath
    setupOptions.workingPath = paths.workingPath
    setupOptions.tempPath = paths.tempPath
    setupOptions.logMaxLines = 2000
    guard LibboxSetup(setupOptions, &setupError) else {
      throw setupError ?? TunnelError("libbox setup failed")
    }

    var stderrError: NSError?
    LibboxRedirectStderr(paths.stderrPath, &stderrError)
    if let stderrError {
      commandServer?.writeMessage(2, message: "redirect stderr: \(stderrError.localizedDescription)")
    }

    LibboxSetMemoryLimit(true)

    var serverError: NSError?
    guard let server = LibboxNewCommandServer(platformInterface, platformInterface, &serverError) else {
      throw serverError ?? TunnelError("failed to create libbox command server")
    }
    commandServer = server

    try server.start()

    let overrideOptions = LibboxOverrideOptions()
    try server.startOrReloadService(configContent, options: overrideOptions)
  }
}

private struct TunnelPaths {
  let basePath: String
  let workingPath: String
  let tempPath: String
  let stderrPath: String

  init() throws {
    let manager = FileManager.default
    let baseURL = manager.urls(for: .documentDirectory, in: .userDomainMask).first!
    let workingURL = baseURL.appendingPathComponent("Working", isDirectory: true)
    let tempURL = manager.temporaryDirectory.appendingPathComponent("KostraVpn", isDirectory: true)
    try manager.createDirectory(at: workingURL, withIntermediateDirectories: true)
    try manager.createDirectory(at: tempURL, withIntermediateDirectories: true)
    basePath = baseURL.path
    workingPath = workingURL.path
    tempPath = tempURL.path
    stderrPath = tempURL.appendingPathComponent("stderr.log").path
  }
}

private struct TunnelError: LocalizedError {
  let message: String

  init(_ message: String) {
    self.message = message
  }

  var errorDescription: String? {
    message
  }
}

private final class TunnelPlatformInterface: NSObject, LibboxPlatformInterfaceProtocol, LibboxCommandServerHandlerProtocol {
  private weak var tunnel: PacketTunnelProvider?
  private var networkSettings: NEPacketTunnelNetworkSettings?
  private var monitor: Network.NWPathMonitor?

  init(tunnel: PacketTunnelProvider) {
    self.tunnel = tunnel
  }

  func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
    guard let tunnel else {
      throw TunnelError("packet tunnel provider is gone")
    }
    guard let options else {
      throw TunnelError("missing tun options")
    }
    guard let ret0_ else {
      throw TunnelError("missing tun fd return pointer")
    }

    let settings = try makeNetworkSettings(options: options)
    try runBlocking {
      try await tunnel.setTunnelNetworkSettings(settings)
    }
    networkSettings = settings

    if let fd = tunnel.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
      ret0_.pointee = fd
      return
    }

    let fd = LibboxGetTunnelFileDescriptor()
    guard fd >= 0 else {
      throw TunnelError("missing tunnel file descriptor")
    }
    ret0_.pointee = fd
  }

  func usePlatformAutoDetectControl() -> Bool {
    false
  }

  func autoDetectControl(_ fd: Int32) throws {}

  func useProcFS() -> Bool {
    false
  }

  func underNetworkExtension() -> Bool {
    true
  }

  func includeAllNetworks() -> Bool {
    false
  }

  func localDNSTransport() -> LibboxLocalDNSTransportProtocol? {
    nil
  }

  func systemCertificates() -> LibboxStringIteratorProtocol? {
    nil
  }

  func findConnectionOwner(
    _ ipProtocol: Int32,
    sourceAddress: String?,
    sourcePort: Int32,
    destinationAddress: String?,
    destinationPort: Int32
  ) throws -> LibboxConnectionOwner {
    throw TunnelError("connection owner lookup is not available on iOS")
  }

  func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
    guard let listener else {
      return
    }
    let monitor = Network.NWPathMonitor()
    self.monitor = monitor
    let semaphore = DispatchSemaphore(value: 0)
    monitor.pathUpdateHandler = { path in
      Self.updateDefaultInterface(listener: listener, path: path)
      semaphore.signal()
    }
    monitor.start(queue: DispatchQueue.global(qos: .utility))
    semaphore.wait()
  }

  func closeDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
    monitor?.cancel()
    monitor = nil
  }

  func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
    let interfaces: [LibboxNetworkInterface] = monitor?.currentPath.availableInterfaces.map { nwInterface in
      let item = LibboxNetworkInterface()
      item.name = nwInterface.name
      item.index = Int32(nwInterface.index)
      switch nwInterface.type {
      case .wifi:
        item.type = LibboxInterfaceTypeWIFI
      case .cellular:
        item.type = LibboxInterfaceTypeCellular
      case .wiredEthernet:
        item.type = LibboxInterfaceTypeEthernet
      default:
        item.type = LibboxInterfaceTypeOther
      }
      return item
    } ?? []
    return NetworkInterfaceIterator(interfaces)
  }

  func readWIFIState() -> LibboxWIFIState? {
    nil
  }

  func clearDNSCache() {
    guard let tunnel, let networkSettings else {
      return
    }
    runBlocking {
      await withCheckedContinuation { continuation in
        tunnel.setTunnelNetworkSettings(nil) { _ in
          continuation.resume()
        }
      }
      await withCheckedContinuation { continuation in
        tunnel.setTunnelNetworkSettings(networkSettings) { _ in
          continuation.resume()
        }
      }
    }
  }

  func send(_ notification: LibboxNotification?) throws {}

  func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
    let status = LibboxSystemProxyStatus()
    guard let proxySettings = networkSettings?.proxySettings, proxySettings.httpServer != nil else {
      return status
    }
    status.available = true
    status.enabled = proxySettings.httpEnabled
    return status
  }

  func setSystemProxyEnabled(_ enabled: Bool) throws {
    guard let tunnel, let networkSettings, let proxySettings = networkSettings.proxySettings else {
      return
    }
    proxySettings.httpEnabled = enabled
    proxySettings.httpsEnabled = enabled
    networkSettings.proxySettings = proxySettings
    try runBlocking {
      try await tunnel.setTunnelNetworkSettings(networkSettings)
    }
  }

  func serviceReload() throws {}

  func serviceStop() throws {
    try tunnel?.commandServer?.closeService()
  }

  func writeDebugMessage(_ message: String?) {
    writeLog(message)
  }

  func writeLog(_ message: String?) {
    guard let message else {
      return
    }
    tunnel?.commandServer?.writeMessage(2, message: message)
  }

  func reset() {
    networkSettings = nil
    monitor?.cancel()
    monitor = nil
  }

  private func makeNetworkSettings(options: LibboxTunOptionsProtocol) throws -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

    if options.getAutoRoute() {
      settings.mtu = NSNumber(value: options.getMTU())
      let dnsServer = try options.getDNSServerAddress().value
      let dnsSettings = NEDNSSettings(servers: [dnsServer])
      dnsSettings.matchDomains = [""]
      settings.dnsSettings = dnsSettings

      var ipv4Addresses: [String] = []
      var ipv4Masks: [String] = []
      if let ipv4AddressIterator = options.getInet4Address() {
        while ipv4AddressIterator.hasNext() {
          guard let prefix = ipv4AddressIterator.next() else {
            continue
          }
          ipv4Addresses.append(prefix.address())
          ipv4Masks.append(prefix.mask())
        }
      }
      if !ipv4Addresses.isEmpty {
        let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Masks)
        ipv4Settings.includedRoutes = routes(iterator: options.getInet4RouteAddress(), defaultRoute: NEIPv4Route.default())
        ipv4Settings.excludedRoutes = routes(iterator: options.getInet4RouteExcludeAddress())
        settings.ipv4Settings = ipv4Settings
      }

      var ipv6Addresses: [String] = []
      var ipv6Prefixes: [NSNumber] = []
      if let ipv6AddressIterator = options.getInet6Address() {
        while ipv6AddressIterator.hasNext() {
          guard let prefix = ipv6AddressIterator.next() else {
            continue
          }
          ipv6Addresses.append(prefix.address())
          ipv6Prefixes.append(NSNumber(value: prefix.prefix()))
        }
      }
      if !ipv6Addresses.isEmpty {
        let ipv6Settings = NEIPv6Settings(addresses: ipv6Addresses, networkPrefixLengths: ipv6Prefixes)
        ipv6Settings.includedRoutes = routes6(iterator: options.getInet6RouteAddress(), defaultRoute: NEIPv6Route.default())
        ipv6Settings.excludedRoutes = routes6(iterator: options.getInet6RouteExcludeAddress())
        settings.ipv6Settings = ipv6Settings
      }
    }

    if options.isHTTPProxyEnabled() {
      let proxyServer = NEProxyServer(address: options.getHTTPProxyServer(), port: Int(options.getHTTPProxyServerPort()))
      let proxySettings = NEProxySettings()
      proxySettings.httpEnabled = true
      proxySettings.httpsEnabled = true
      proxySettings.httpServer = proxyServer
      proxySettings.httpsServer = proxyServer
      proxySettings.exceptionList = strings(iterator: options.getHTTPProxyBypassDomain())
      let matchDomains = strings(iterator: options.getHTTPProxyMatchDomain())
      if !matchDomains.isEmpty {
        proxySettings.matchDomains = matchDomains
      }
      settings.proxySettings = proxySettings
    }

    return settings
  }

  private func routes(iterator: LibboxRoutePrefixIteratorProtocol?, defaultRoute: NEIPv4Route? = nil) -> [NEIPv4Route] {
    var values: [NEIPv4Route] = []
    while iterator?.hasNext() == true {
      guard let prefix = iterator?.next() else {
        continue
      }
      values.append(NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
    }
    if values.isEmpty, let defaultRoute {
      values.append(defaultRoute)
    }
    return values
  }

  private func routes6(iterator: LibboxRoutePrefixIteratorProtocol?, defaultRoute: NEIPv6Route? = nil) -> [NEIPv6Route] {
    var values: [NEIPv6Route] = []
    while iterator?.hasNext() == true {
      guard let prefix = iterator?.next() else {
        continue
      }
      values.append(NEIPv6Route(destinationAddress: prefix.address(), networkPrefixLength: NSNumber(value: prefix.prefix())))
    }
    if values.isEmpty, let defaultRoute {
      values.append(defaultRoute)
    }
    return values
  }

  private func strings(iterator: LibboxStringIteratorProtocol?) -> [String] {
    var values: [String] = []
    while iterator?.hasNext() == true {
      if let value = iterator?.next() {
        values.append(value)
      }
    }
    return values
  }

  private static func updateDefaultInterface(listener: LibboxInterfaceUpdateListenerProtocol, path: Network.NWPath) {
    guard path.status != Network.NWPath.Status.unsatisfied, let defaultInterface = path.availableInterfaces.first else {
      listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false)
      return
    }
    listener.updateDefaultInterface(
      defaultInterface.name,
      interfaceIndex: Int32(defaultInterface.index),
      isExpensive: path.isExpensive,
      isConstrained: path.isConstrained
    )
  }
}

private final class NetworkInterfaceIterator: NSObject, LibboxNetworkInterfaceIteratorProtocol {
  private var iterator: IndexingIterator<[LibboxNetworkInterface]>
  private var nextValue: LibboxNetworkInterface?

  init(_ interfaces: [LibboxNetworkInterface]) {
    iterator = interfaces.makeIterator()
  }

  func hasNext() -> Bool {
    nextValue = iterator.next()
    return nextValue != nil
  }

  func next() -> LibboxNetworkInterface? {
    nextValue
  }
}

private func runBlocking<T>(_ operation: @escaping () async throws -> T) throws -> T {
  let semaphore = DispatchSemaphore(value: 0)
  var result: Result<T, Error>!
  Task {
    do {
      result = .success(try await operation())
    } catch {
      result = .failure(error)
    }
    semaphore.signal()
  }
  semaphore.wait()
  return try result.get()
}

private func runBlocking(_ operation: @escaping () async -> Void) {
  let semaphore = DispatchSemaphore(value: 0)
  Task {
    await operation()
    semaphore.signal()
  }
  semaphore.wait()
}
