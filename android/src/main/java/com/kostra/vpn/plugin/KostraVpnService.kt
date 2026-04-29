package com.kostra.vpn.plugin

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.NeighborEntryIterator
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.OutboundGroupItemIterator
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.io.File
import java.net.Inet6Address
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.security.KeyStore
import java.util.Base64
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface

class KostraVpnService : VpnService(), PlatformInterface, CommandServerHandler {
    private var commandServer: CommandServer? = null
    private var statsClient: CommandClient? = null
    private var tunnel: ParcelFileDescriptor? = null
    private var defaultInterfaceListener: InterfaceUpdateListener? = null
    private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null

    private val connectivity: ConnectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    override fun onCreate() {
        super.onCreate()
        ensureLibboxSetup()
        ensureForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> start(intent.getStringExtra(EXTRA_CONFIG).orEmpty())
            ACTION_STOP -> stop()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    override fun onRevoke() {
        stop()
        super.onRevoke()
    }

    private fun start(configJson: String) {
        if (configJson.isBlank()) {
            lastStartError = "empty sing-box config"
            Log.e(TAG, "empty sing-box config")
            stopSelf()
            return
        }
        if (commandServer != null) {
            return
        }

        try {
            val server = CommandServer(this, this)
            server.start()
            server.startOrReloadService(configJson, OverrideOptions())
            commandServer = server
            startStatsClient()
            Log.i(TAG, "sing-box libbox service started")
        } catch (error: Exception) {
            lastStartError = error.message ?: error.toString()
            Log.e(TAG, "failed to start sing-box libbox service", error)
            stop()
        }
    }

    private fun stop() {
        stopStatsClient()
        runCatching { commandServer?.closeService() }
        runCatching { commandServer?.close() }
        commandServer = null
        runCatching { tunnel?.close() }
        tunnel = null
        tunEstablished = false
        resetTrafficStats()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startStatsClient() {
        stopStatsClient()
        resetTrafficStats()

        val options = CommandClientOptions().apply {
            addCommand(Libbox.CommandStatus)
            statusInterval = 1_000_000_000
        }
        val client = CommandClient(object : CommandClientHandler {
            override fun connected() {
                Log.i(TAG, "traffic stats client connected")
            }

            override fun disconnected(message: String?) {
                Log.i(TAG, "traffic stats client disconnected: ${message.orEmpty()}")
            }

            override fun setDefaultLogLevel(level: Int) {}

            override fun clearLogs() {}

            override fun writeLogs(messageList: LogIterator?) {}

            override fun writeStatus(message: StatusMessage?) {
                if (message == null || !message.trafficAvailable) {
                    return
                }
                uploadTotalBytes = message.uplinkTotal.coerceAtLeast(0)
                downloadTotalBytes = message.downlinkTotal.coerceAtLeast(0)
            }

            override fun writeGroups(message: OutboundGroupIterator?) {}

            override fun writeOutbounds(message: OutboundGroupItemIterator?) {}

            override fun initializeClashMode(modeList: StringIterator, currentMode: String) {}

            override fun updateClashMode(newMode: String) {}

            override fun writeConnectionEvents(events: ConnectionEvents?) {}
        }, options)
        statsClient = client

        Thread {
            try {
                client.connect()
            } catch (error: Exception) {
                Log.e(TAG, "traffic stats client failed", error)
            }
        }.start()
    }

    private fun stopStatsClient() {
        runCatching { statsClient?.disconnect() }
        statsClient = null
    }

    override fun openTun(options: TunOptions): Int {
        try {
            return openTunInner(options)
        } catch (error: Exception) {
            lastStartError = error.message ?: error.toString()
            Log.e(TAG, "failed to open Android TUN", error)
            throw error
        }
    }

    private fun openTunInner(options: TunOptions): Int {
        if (prepare(this) != null) error("android: missing vpn permission")
        val inet4Addresses = collectPrefixes(options.inet4Address)
        val inet6Addresses = collectPrefixes(options.inet6Address)
        val inet4Routes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            collectPrefixes(options.inet4RouteAddress)
        } else {
            collectPrefixes(options.inet4RouteRange)
        }
        val inet6Routes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            collectPrefixes(options.inet6RouteAddress)
        } else {
            collectPrefixes(options.inet6RouteRange)
        }

        val builder = Builder()
            .setSession("KOSTRA VPN")
            .setMtu(options.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        addAddresses(builder, inet4Addresses)
        addAddresses(builder, inet6Addresses)

        if (options.autoRoute) {
            builder.addDnsServer(options.dnsServerAddress.value)
            addRoutes(builder, inet4Routes, "0.0.0.0", inet4Addresses.isNotEmpty())
            addRoutes(builder, inet6Routes, "::", inet6Addresses.isNotEmpty())
        }

        val pfd = builder.establish() ?: error("android: failed to establish vpn service")
        tunnel = pfd
        tunEstablished = true
        lastStartError = null
        Log.i(
            TAG,
            "TUN established mtu=${options.mtu} v4=${inet4Addresses.size} v6=${inet6Addresses.size} routes4=${inet4Routes.size} routes6=${inet6Routes.size} autoRoute=${options.autoRoute}"
        )
        return pfd.fd
    }

    private fun collectPrefixes(iterator: RoutePrefixIterator): List<IpPrefix> {
        val prefixes = mutableListOf<IpPrefix>()
        while (iterator.hasNext()) {
            val prefix = iterator.next()
            prefixes.add(IpPrefix(prefix.address(), prefix.prefix().toInt()))
        }
        return prefixes
    }

    private fun addAddresses(builder: Builder, prefixes: List<IpPrefix>) {
        for (prefix in prefixes) {
            builder.addAddress(prefix.address, prefix.prefix)
        }
    }

    private fun addRoutes(builder: Builder, prefixes: List<IpPrefix>, fallbackAddress: String, hasAddress: Boolean) {
        for (prefix in prefixes) {
            builder.addRoute(prefix.address, prefix.prefix)
        }
        if (prefixes.isEmpty() && hasAddress) {
            builder.addRoute(fallbackAddress, 0)
        }
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        protect(fd)
    }

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int
    ): ConnectionOwner {
        error("connection owner lookup is not implemented")
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        defaultInterfaceListener = listener
        if (defaultNetworkCallback == null) {
            defaultNetworkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    updateDefaultInterface(network)
                }

                override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                    updateDefaultInterface(network)
                }

                override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                    updateDefaultInterface(network)
                }

                override fun onLost(network: Network) {
                    if (connectivity.activeNetwork == network) {
                        listener.updateDefaultInterface("", -1, false, false)
                    } else {
                        updateDefaultInterface(connectivity.activeNetwork)
                    }
                }
            }
            runCatching {
                connectivity.registerNetworkCallback(
                    NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build(),
                    defaultNetworkCallback!!
                )
            }.onFailure {
                Log.e(TAG, "failed to register default network monitor", it)
            }
        }
        updateDefaultInterface(connectivity.activeNetwork)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        defaultInterfaceListener = null
        val callback = defaultNetworkCallback ?: return
        defaultNetworkCallback = null
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val networkInterfaces = NetworkInterface.getNetworkInterfaces().toList()
        val items = connectivity.allNetworks.mapNotNull { network ->
            runCatching {
                val linkProperties = connectivity.getLinkProperties(network) ?: return@runCatching null
                val capabilities = connectivity.getNetworkCapabilities(network) ?: return@runCatching null
                val name = linkProperties.interfaceName ?: return@runCatching null
                val iface = networkInterfaces.find { it.name == name } ?: return@runCatching null
                BoxNetworkInterface().apply {
                    index = iface.index
                    this.name = name
                    mtu = iface.mtu
                    flags = interfaceFlags(iface)
                    type = when {
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                        else -> Libbox.InterfaceTypeOther
                    }
                    addresses = StringArray(iface.interfaceAddresses.map { it.toPrefix() }.iterator())
                    dnsServer = StringArray(linkProperties.dnsServers.mapNotNull { it.hostAddress }.iterator())
                    metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                }
            }.getOrNull()
        }
        return NetworkInterfaceArray(items.iterator())
    }

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun systemCertificates(): StringIterator {
        val certificates = mutableListOf<String>()
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val cert = keyStore.getCertificate(aliases.nextElement())
                certificates.add("-----BEGIN CERTIFICATE-----\n${Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded)}\n-----END CERTIFICATE-----")
            }
        }
        return StringArray(certificates.iterator())
    }

    override fun clearDNSCache() {}

    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun sendNotification(notification: Notification) {
        Log.i(TAG, "${notification.title}: ${notification.body}")
    }

    override fun startNeighborMonitor(listener: NeighborUpdateListener) {}

    override fun closeNeighborMonitor(listener: NeighborUpdateListener) {}

    override fun registerMyInterface(name: String?) {}

    private fun updateDefaultInterface(network: Network?) {
        val listener = defaultInterfaceListener ?: return
        if (network == null) {
            listener.updateDefaultInterface("", -1, false, false)
            return
        }

        for (attempt in 0 until 10) {
            val linkProperties = connectivity.getLinkProperties(network)
            val name = linkProperties?.interfaceName
            if (name.isNullOrBlank()) {
                Thread.sleep(100)
                continue
            }

            val networkInterface = runCatching { NetworkInterface.getByName(name) }.getOrNull()
            if (networkInterface == null) {
                Thread.sleep(100)
                continue
            }

            val capabilities = connectivity.getNetworkCapabilities(network)
            val expensive = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
            val constrained = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED) == false
            } else {
                false
            }
            listener.updateDefaultInterface(name, networkInterface.index, expensive, constrained)
            Log.i(TAG, "default network interface: $name index=${networkInterface.index}")
            return
        }

        listener.updateDefaultInterface("", -1, false, false)
    }

    override fun serviceStop() {
        stop()
    }

    override fun serviceReload() {}

    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus().apply {
        available = false
        enabled = false
    }

    override fun setSystemProxyEnabled(enabled: Boolean) {}

    override fun triggerNativeCrash() {
        throw RuntimeException("requested native crash")
    }

    override fun writeDebugMessage(message: String?) {
        Log.d("sing-box", message.orEmpty())
    }

    private fun ensureLibboxSetup() {
        val baseDir = filesDir.apply { mkdirs() }
        val workingDir = (getExternalFilesDir(null) ?: File(filesDir, "working")).apply { mkdirs() }
        val tempDir = cacheDir.apply { mkdirs() }
        Libbox.setup(SetupOptions().apply {
            basePath = baseDir.path
            workingPath = workingDir.path
            tempPath = tempDir.path
            logMaxLines = 3000
            crashReportSource = "KostraVpnService"
            debug = false
        })
    }

    private fun ensureForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "KOSTRA VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("KOSTRA VPN")
            .setContentText("VPN is running")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun InterfaceAddress.toPrefix(): String =
        if (address is Inet6Address) {
            "${Inet6Address.getByAddress(address.address).hostAddress}/$networkPrefixLength"
        } else {
            "${address.hostAddress}/$networkPrefixLength"
        }

    private fun interfaceFlags(iface: NetworkInterface): Int {
        var flags = 0
        if (iface.isUp) flags = flags or OsConstants.IFF_UP
        if (iface.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
        if (iface.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
        if (iface.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
        return flags
    }

    private class StringArray(private val iterator: Iterator<String>) : StringIterator {
        override fun len(): Int = 0
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): String = iterator.next()
    }

    private class NetworkInterfaceArray(
        private val iterator: Iterator<BoxNetworkInterface>
    ) : NetworkInterfaceIterator {
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): BoxNetworkInterface = iterator.next()
    }

    private data class IpPrefix(val address: String, val prefix: Int)

    companion object {
        private const val TAG = "KostraVpnService"
        private const val CHANNEL_ID = "kostra-vpn"
        private const val NOTIFICATION_ID = 1001
        const val ACTION_START = "com.kostra.vpn.plugin.START"
        const val ACTION_STOP = "com.kostra.vpn.plugin.STOP"
        const val EXTRA_CONFIG = "configJson"

        @Volatile
        private var tunEstablished = false

        @Volatile
        private var lastStartError: String? = null

        @Volatile
        private var uploadTotalBytes: Long = 0

        @Volatile
        private var downloadTotalBytes: Long = 0

        fun resetStartState() {
            tunEstablished = false
            lastStartError = null
        }

        fun isTunEstablished(): Boolean = tunEstablished

        fun getLastStartError(): String? = lastStartError

        fun resetTrafficStats() {
            uploadTotalBytes = 0
            downloadTotalBytes = 0
        }

        fun getTrafficStats(): Pair<Long, Long> =
            Pair(uploadTotalBytes.coerceAtLeast(0), downloadTotalBytes.coerceAtLeast(0))
    }
}
