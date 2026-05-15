package com.kostra.vpn.plugin

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.AlarmManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
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
import java.net.HttpURLConnection
import java.net.Inet6Address
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.net.URL
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface

class KostraVpnService : VpnService(), PlatformInterface, CommandServerHandler {
    private var commandServer: CommandServer? = null
    private var statsClient: CommandClient? = null
    private var tunnel: ParcelFileDescriptor? = null
    private var defaultInterfaceListener: InterfaceUpdateListener? = null
    private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var healthCheckThread: Thread? = null
    private val healthCheckStop = AtomicBoolean(false)
    private val lifecycleLock = Any()
    private var consecutiveHealthFailures = 0

    private val connectivity: ConnectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    private val preferences: SharedPreferences by lazy {
        getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    }

    override fun onCreate() {
        super.onCreate()
        ensureLibboxSetup()
        ensureForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG).orEmpty()
                if (configJson.isNotBlank()) {
                    preferences.edit().putString(PREF_LAST_CONFIG, configJson).apply()
                }
                start(configJson)
            }
            ACTION_STOP -> {
                preferences.edit().remove(PREF_LAST_CONFIG).apply()
                stop()
            }
            ACTION_RESTART -> {
                val configJson = preferences.getString(PREF_LAST_CONFIG, null)
                if (configJson.isNullOrBlank()) {
                    stopSelf()
                } else {
                    Log.i(TAG, "starting scheduled VPN recovery")
                    start(configJson)
                }
            }
            else -> {
                val configJson = preferences.getString(PREF_LAST_CONFIG, null)
                if (configJson.isNullOrBlank()) {
                    stopSelf()
                } else {
                    Log.i(TAG, "restarting sticky VPN service")
                    start(configJson)
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    override fun onRevoke() {
        preferences.edit().remove(PREF_LAST_CONFIG).apply()
        stop()
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(TAG, "app task removed, keeping foreground VPN service running")
    }

    private fun start(configJson: String) {
        synchronized(lifecycleLock) {
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
                startCoreLocked(configJson)
                startHealthWatchdog()
                Log.i(TAG, "sing-box libbox service started")
            } catch (error: Exception) {
                lastStartError = error.message ?: error.toString()
                Log.e(TAG, "failed to start sing-box libbox service", error)
                stop()
            }
        }
    }

    private fun stop() {
        synchronized(lifecycleLock) {
            stopHealthWatchdog()
            stopCoreLocked()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun startCoreLocked(configJson: String) {
        val server = CommandServer(this, this)
        server.start()
        server.startOrReloadService(configJson, OverrideOptions())
        commandServer = server
        consecutiveHealthFailures = 0
        startStatsClient()
    }

    private fun stopCoreLocked() {
        stopStatsClient()
        runCatching { commandServer?.closeService() }
        runCatching { commandServer?.close() }
        commandServer = null
        runCatching { tunnel?.close() }
        tunnel = null
        tunEstablished = false
        resetTrafficStats()
    }

    private fun restartCoreFromWatchdog(reason: String) {
        val configJson = preferences.getString(PREF_LAST_CONFIG, null)
        if (configJson.isNullOrBlank()) {
            return
        }

        Log.w(TAG, "restarting VPN process after health failure: $reason")
        scheduleServiceRestart()
        Thread.sleep(PROCESS_RESTART_DELAY_MS)
        Process.killProcess(Process.myPid())
    }

    private fun scheduleServiceRestart() {
        val intent = Intent(this, KostraVpnService::class.java).apply {
            action = ACTION_RESTART
            setPackage(packageName)
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0
        val pendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(this, SERVICE_RESTART_REQUEST_CODE, intent, flags)
        } else {
            PendingIntent.getService(this, SERVICE_RESTART_REQUEST_CODE, intent, flags)
        }
        val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val triggerAt = SystemClock.elapsedRealtime() + SERVICE_RESTART_DELAY_MS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            alarmManager.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pendingIntent)
        } else {
            alarmManager.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pendingIntent)
        }
    }

    private fun startStatsClient() {
        stopStatsClient()
        resetTrafficStats()

        val options = CommandClientOptions().apply {
            addCommand(Libbox.CommandLog)
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

            override fun writeLogs(messageList: LogIterator?) {
                if (messageList == null) {
                    return
                }
                while (messageList.hasNext()) {
                    val entry = messageList.next()
                    Log.i("sing-box", entry.message)
                }
            }

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

    private fun startHealthWatchdog() {
        if (healthCheckThread?.isAlive == true) {
            return
        }

        healthCheckStop.set(false)
        healthCheckThread = Thread {
            while (!healthCheckStop.get()) {
                try {
                    Thread.sleep(HEALTH_CHECK_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    continue
                }

                if (healthCheckStop.get() || !tunEstablished || commandServer == null) {
                    continue
                }

                if (probeVpnConnectivity()) {
                    consecutiveHealthFailures = 0
                    continue
                }

                consecutiveHealthFailures += 1
                Log.w(TAG, "VPN health check failed ($consecutiveHealthFailures/$HEALTH_CHECK_FAILURES_BEFORE_RESTART)")
                if (consecutiveHealthFailures >= HEALTH_CHECK_FAILURES_BEFORE_RESTART) {
                    restartCoreFromWatchdog("HTTPS probe timed out")
                }
            }
        }.apply {
            name = "KostraVpnHealthWatchdog"
            isDaemon = true
            start()
        }
    }

    private fun stopHealthWatchdog() {
        healthCheckStop.set(true)
        val thread = healthCheckThread
        if (thread != null && thread != Thread.currentThread()) {
            thread.interrupt()
        }
        healthCheckThread = null
        consecutiveHealthFailures = 0
    }

    private fun probeVpnConnectivity(): Boolean =
        HEALTH_CHECK_URLS.any { url -> probeVpnUrl(url) }

    private fun probeVpnUrl(url: String): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            connection = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = HEALTH_CHECK_TIMEOUT_MS
                readTimeout = HEALTH_CHECK_TIMEOUT_MS
                requestMethod = "GET"
                instanceFollowRedirects = false
                useCaches = false
                setRequestProperty("User-Agent", "KOSTRA-VPN-HealthCheck/1.0")
            }
            val status = connection.responseCode
            status in 200..399
        } catch (error: Exception) {
            Log.d(TAG, "VPN health probe failed for $url: ${error.message ?: error}")
            false
        } finally {
            connection?.disconnect()
        }
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
                    if (defaultUnderlyingNetwork() == network) {
                        listener.updateDefaultInterface("", -1, false, false)
                    } else {
                        updateDefaultInterface(defaultUnderlyingNetwork())
                    }
                }
            }
            runCatching {
                connectivity.registerNetworkCallback(
                    NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        .build(),
                    defaultNetworkCallback!!
                )
            }.onFailure {
                Log.e(TAG, "failed to register default network monitor", it)
            }
        }
        updateDefaultInterface(defaultUnderlyingNetwork())
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
                if (!isUnderlyingNetwork(capabilities)) return@runCatching null
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
            if (capabilities == null || !isUnderlyingNetwork(capabilities)) {
                updateDefaultInterface(defaultUnderlyingNetwork(excluding = network))
                return
            }
            val expensive = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            val constrained = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED)
            } else {
                false
            }
            listener.updateDefaultInterface(name, networkInterface.index, expensive, constrained)
            Log.i(TAG, "default network interface: $name index=${networkInterface.index}")
            return
        }

        listener.updateDefaultInterface("", -1, false, false)
    }

    private fun defaultUnderlyingNetwork(excluding: Network? = null): Network? {
        val active = connectivity.activeNetwork
        if (active != null && active != excluding) {
            val capabilities = connectivity.getNetworkCapabilities(active)
            if (capabilities != null && isUnderlyingNetwork(capabilities)) {
                return active
            }
        }

        return connectivity.allNetworks.firstOrNull { network ->
            if (network == excluding) return@firstOrNull false
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@firstOrNull false
            isUnderlyingNetwork(capabilities)
        }
    }

    private fun isUnderlyingNetwork(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

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
        private const val PREFERENCES_NAME = "kostra-vpn-service"
        private const val PREF_LAST_CONFIG = "lastConfigJson"
        private const val HEALTH_CHECK_INTERVAL_MS = 15_000L
        private const val HEALTH_CHECK_TIMEOUT_MS = 5_000
        private const val HEALTH_CHECK_FAILURES_BEFORE_RESTART = 2
        private const val SERVICE_RESTART_REQUEST_CODE = 1002
        private const val SERVICE_RESTART_DELAY_MS = 1_000L
        private const val PROCESS_RESTART_DELAY_MS = 250L
        private val HEALTH_CHECK_URLS = arrayOf(
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204"
        )
        const val ACTION_START = "com.kostra.vpn.plugin.START"
        const val ACTION_STOP = "com.kostra.vpn.plugin.STOP"
        const val ACTION_RESTART = "com.kostra.vpn.plugin.RESTART"
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
