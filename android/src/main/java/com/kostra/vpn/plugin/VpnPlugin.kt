package com.kostra.vpn.plugin

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import android.util.Log
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
internal class ConnectArgs {
    lateinit var configJson: String
    var profileId: String? = null
}

@TauriPlugin(
    permissions = [
        Permission(strings = ["android.permission.POST_NOTIFICATIONS"], alias = "notifications")
    ]
)
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun requestVpnPermission(invoke: Invoke) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            invoke.resolve(JSObject().put("granted", true))
        } else {
            startActivityForResult(invoke, intent, "vpnPermissionResult")
        }
    }

    @Command
    fun startNativeVpn(invoke: Invoke) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        requestNotificationPermissionIfNeeded()
        val permissionIntent = VpnService.prepare(activity)
        if (permissionIntent != null) {
            startActivityForResult(invoke, permissionIntent, "startVpnAfterPermission")
            return
        }

        val args = invoke.parseArgs(ConnectArgs::class.java)
        startVpn(invoke, args.configJson, args.profileId)
    }

    @ActivityCallback
    fun vpnPermissionResult(invoke: Invoke, _result: ActivityResult) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        if (VpnService.prepare(activity) == null) {
            invoke.resolve(JSObject().put("granted", true))
        } else {
            invoke.reject("Android VPN permission was not granted.", "VPN_PERMISSION_DENIED")
        }
    }

    @ActivityCallback
    fun startVpnAfterPermission(invoke: Invoke, _result: ActivityResult) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        if (VpnService.prepare(activity) != null) {
            invoke.reject("Android VPN permission was not granted.", "VPN_PERMISSION_DENIED")
            return
        }

        val args = invoke.parseArgs(ConnectArgs::class.java)
        startVpn(invoke, args.configJson, args.profileId)
    }

    private fun startVpn(invoke: Invoke, configJson: String, profileId: String?) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        if (KostraVpnService.isTunEstablished()) {
            invoke.resolve(JSObject().put("started", true))
            return
        }

        val intent = Intent(activity, KostraVpnService::class.java)
        intent.action = KostraVpnService.ACTION_START
        intent.putExtra(KostraVpnService.EXTRA_CONFIG, configJson)
        if (profileId != null) {
            intent.putExtra(KostraVpnService.EXTRA_PROFILE_ID, profileId)
        }
        try {
            KostraVpnService.resetStartState()
            ContextCompat.startForegroundService(activity, intent)
        } catch (error: Exception) {
            invoke.reject("Android VPN service failed to start: ${error.message ?: error}", "VPN_SERVICE_START_FAILED")
            return
        }

        invoke.resolve(JSObject().put("started", true))
    }

    private fun requestNotificationPermissionIfNeeded() {
        val activity = this.activity ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return
        }
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            return
        }
        ActivityCompat.requestPermissions(
            activity,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            NOTIFICATION_PERMISSION_REQUEST_CODE
        )
    }

    @Command
    fun stopNativeVpn(invoke: Invoke) {
        val activity = this.activity ?: run {
            invoke.reject("Activity is not available")
            return
        }
        val intent = Intent(activity, KostraVpnService::class.java)
        intent.action = KostraVpnService.ACTION_STOP
        activity.startService(intent)
        invoke.resolve(JSObject().put("stopped", true))
    }

    @Command
    fun getNativeTrafficStats(invoke: Invoke) {
        val stats = KostraVpnService.getTrafficStats()
        invoke.resolve(
            JSObject()
                .put("uploadedBytes", stats.first)
                .put("downloadedBytes", stats.second)
        )
    }

    @Command
    fun getNativeVpnStatus(invoke: Invoke) {
        val stats = KostraVpnService.getTrafficStats()
        val activity = this.activity ?: run {
            // If activity is not available, we can't get preferences, but we might still know if TUN is up
            invoke.resolve(
                JSObject()
                    .put("established", KostraVpnService.isTunEstablished())
                    .put("lastError", KostraVpnService.getLastStartError())
                    .put("activeProfileId", null)
                    .put("uploadedBytes", stats.first)
                    .put("downloadedBytes", stats.second)
            )
            return
        }
        invoke.resolve(
            JSObject()
                .put("established", KostraVpnService.isTunEstablished())
                .put("lastError", KostraVpnService.getLastStartError())
                .put("activeProfileId", KostraVpnService.getLastProfileId(activity))
                .put("uploadedBytes", stats.first)
                .put("downloadedBytes", stats.second)
        )
    }

    private companion object {
        const val NOTIFICATION_PERMISSION_REQUEST_CODE = 2001
    }
}
