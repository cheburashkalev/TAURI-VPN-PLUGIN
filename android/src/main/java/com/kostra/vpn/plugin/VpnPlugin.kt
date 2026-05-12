package com.kostra.vpn.plugin

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
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
}

@TauriPlugin(
    permissions = [
        Permission(strings = ["android.permission.POST_NOTIFICATIONS"], alias = "notifications")
    ]
)
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun requestVpnPermission(invoke: Invoke) {
        val intent = VpnService.prepare(activity)
        if (intent == null) {
            invoke.resolve(JSObject().put("granted", true))
        } else {
            startActivityForResult(invoke, intent, "vpnPermissionResult")
        }
    }

    @Command
    fun startNativeVpn(invoke: Invoke) {
        val permissionIntent = VpnService.prepare(activity)
        if (permissionIntent != null) {
            startActivityForResult(invoke, permissionIntent, "startVpnAfterPermission")
            return
        }

        val args = invoke.parseArgs(ConnectArgs::class.java)
        startVpnAndAwaitTun(invoke, args.configJson)
    }

    @ActivityCallback
    fun vpnPermissionResult(invoke: Invoke, _result: ActivityResult) {
        if (VpnService.prepare(activity) == null) {
            invoke.resolve(JSObject().put("granted", true))
        } else {
            invoke.reject("Android VPN permission was not granted.", "VPN_PERMISSION_DENIED")
        }
    }

    @ActivityCallback
    fun startVpnAfterPermission(invoke: Invoke, _result: ActivityResult) {
        if (VpnService.prepare(activity) != null) {
            invoke.reject("Android VPN permission was not granted.", "VPN_PERMISSION_DENIED")
            return
        }

        val args = invoke.parseArgs(ConnectArgs::class.java)
        startVpnAndAwaitTun(invoke, args.configJson)
    }

    private fun startVpnAndAwaitTun(invoke: Invoke, configJson: String) {
        val intent = Intent(activity, KostraVpnService::class.java)
        intent.action = KostraVpnService.ACTION_START
        intent.putExtra(KostraVpnService.EXTRA_CONFIG, configJson)
        try {
            KostraVpnService.resetStartState()
            ContextCompat.startForegroundService(activity, intent)
        } catch (error: Exception) {
            invoke.reject("Android VPN service failed to start: ${error.message ?: error}", "VPN_SERVICE_START_FAILED")
            return
        }

        Thread {
            val deadline = SystemClock.elapsedRealtime() + 10_000
            while (SystemClock.elapsedRealtime() < deadline) {
                val error = KostraVpnService.getLastStartError()
                if (error != null) {
                    activity.runOnUiThread {
                        invoke.reject("Android VPN failed to start: $error", "VPN_START_FAILED")
                    }
                    return@Thread
                }

                if (KostraVpnService.isTunEstablished()) {
                    activity.runOnUiThread {
                        invoke.resolve(JSObject().put("started", true))
                    }
                    return@Thread
                }

                Thread.sleep(100)
            }

            val stopIntent = Intent(activity, KostraVpnService::class.java)
            stopIntent.action = KostraVpnService.ACTION_STOP
            activity.startService(stopIntent)
            activity.runOnUiThread {
                invoke.reject(
                    "Android VPN TUN was not established within 10 seconds. Check Android logcat for KostraVpnService and sing-box logs.",
                    "VPN_TUN_NOT_ESTABLISHED"
                )
            }
        }.start()
    }

    @Command
    fun stopNativeVpn(invoke: Invoke) {
        val intent = Intent(activity, KostraVpnService::class.java)
        intent.action = KostraVpnService.ACTION_STOP
        activity.startService(intent)

        Thread {
            val deadline = SystemClock.elapsedRealtime() + 5_000
            while (SystemClock.elapsedRealtime() < deadline) {
                if (!KostraVpnService.isTunEstablished()) {
                    activity.runOnUiThread {
                        invoke.resolve(JSObject().put("stopped", true))
                    }
                    return@Thread
                }

                Thread.sleep(100)
            }

            activity.runOnUiThread {
                invoke.resolve(JSObject().put("stopped", true))
            }
        }.start()
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
}
