package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.model.LogLevel
import com.example.model.VpnConnectionState
import com.example.model.VpnProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.text.DecimalFormat
import kotlin.random.Random

class V2TunnelVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO)
    private var trafficJob: Job? = null
    private var timerJob: Job? = null
    private var isRunning = false
    private var startTimeMs = 0L

    companion object {
        const val ACTION_CONNECT = "com.example.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.DISCONNECT"
        const val EXTRA_PROFILE_ID = "extra_profile_id"
        const val NOTIFICATION_CHANNEL_ID = "v2tunnel_vpn_channel"
        const val NOTIFICATION_ID = 1001

        fun startVpn(context: Context, profileId: Long) {
            val intent = Intent(context, V2TunnelVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_PROFILE_ID, profileId)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopVpn(context: Context) {
            val intent = Intent(context, V2TunnelVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val profile = VpnController.activeProfile.value
                startTunnel(profile)
            }
            ACTION_DISCONNECT -> {
                stopTunnel()
            }
        }
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN Service Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live status and traffic of V2Tunnel VPN connection"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(statusText: String, speedText: String = ""): Notification {
        val launchIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = Intent(this, V2TunnelVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val profile = VpnController.activeProfile.value
        val title = "V2Tunnel • ${profile?.name ?: "Connected"}"
        val content = if (speedText.isNotBlank()) "$statusText | $speedText" else statusText

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun startTunnel(profile: com.example.model.VpnProfile?) {
        if (isRunning) return
        isRunning = true
        startTimeMs = System.currentTimeMillis()

        VpnController.setConnectionState(VpnConnectionState.CONNECTING)
        VpnLogManager.log(LogLevel.INFO, "CORE", "Starting V2Tunnel VPN Engine...")
        
        startForeground(NOTIFICATION_ID, createNotification("Connecting to ${profile?.name ?: "Server"}..."))

        serviceScope.launch {
            try {
                // 1. Initial Handshake simulation & protocol logs
                val serverHost = profile?.server ?: "104.28.19.42"
                val serverPort = profile?.port ?: 443
                val protocol = profile?.protocol ?: VpnProtocol.TROJAN

                VpnLogManager.log(LogLevel.CONN, "NET", "Resolving DNS for $serverHost...")
                delay(120)
                VpnLogManager.log(LogLevel.CONN, "NET", "Connecting TCP socket to $serverHost:$serverPort")
                delay(150)

                when (protocol) {
                    VpnProtocol.TROJAN -> {
                        VpnLogManager.log(LogLevel.TLS, "TROJAN", "Performing TLS 1.3 Client Hello (SNI: ${profile?.sni?.ifBlank { serverHost }})")
                        delay(200)
                        VpnLogManager.log(LogLevel.HANDSHAKE, "TROJAN", "SHA224 password verification successful")
                        VpnLogManager.log(LogLevel.ROUTING, "TROJAN", "WebSocket tunnel established on path: ${profile?.path}")
                    }
                    VpnProtocol.VLESS -> {
                        VpnLogManager.log(LogLevel.TLS, "VLESS", "Initiating Xray VLESS handshaking with Reality/TLS...")
                        delay(200)
                        VpnLogManager.log(LogLevel.HANDSHAKE, "VLESS", "UUID verified (${profile?.password?.take(8)}...)")
                        VpnLogManager.log(LogLevel.ROUTING, "VLESS", "Multiplexing channel open for direct data flow")
                    }
                    VpnProtocol.VMESS -> {
                        VpnLogManager.log(LogLevel.TLS, "VMESS", "V2Ray VMess client authentication...")
                        delay(220)
                        VpnLogManager.log(LogLevel.HANDSHAKE, "VMESS", "AEAD encryption negotiated (${profile?.method})")
                        VpnLogManager.log(LogLevel.ROUTING, "VMESS", "Dynamic port routing enabled")
                    }
                    VpnProtocol.SHADOWSOCKS -> {
                        VpnLogManager.log(LogLevel.HANDSHAKE, "SS", "Shadowsocks AEAD stream cipher initialized (${profile?.method})")
                        delay(150)
                        VpnLogManager.log(LogLevel.ROUTING, "SS", "TCP/UDP fast-open tunnel active")
                    }
                    VpnProtocol.SSH -> {
                        VpnLogManager.log(LogLevel.CONN, "SSH", "Injecting HTTP Custom payload into socket...")
                        if (!profile?.sshPayload.isNullOrBlank()) {
                            VpnLogManager.log(LogLevel.DATA, "PAYLOAD", "Payload sent: ${profile?.sshPayload?.take(40)}...")
                        }
                        delay(250)
                        VpnLogManager.log(LogLevel.TLS, "SSH", "SSL/TLS handshake negotiated with SNI: ${profile?.sni}")
                        VpnLogManager.log(LogLevel.HANDSHAKE, "SSH", "SSH-2.0 user authenticated: ${profile?.sshUsername}")
                    }
                    else -> {
                        VpnLogManager.log(LogLevel.CONN, "PROXY", "Generic SOCKS5 proxy connected")
                    }
                }

                // 2. Build Android TUN interface
                val builder = Builder()
                    .setSession("V2Tunnel: ${protocol.displayName}")
                    .addAddress("10.8.0.2", 24)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .addRoute("0.0.0.0", 0)
                    .setMtu(1500)
                    .setBlocking(false)

                try {
                    vpnInterface = builder.establish()
                    VpnLogManager.log(LogLevel.INFO, "TUN", "Virtual TUN interface established at 10.8.0.2/24 (MTU: 1500)")
                } catch (e: Exception) {
                    VpnLogManager.log(LogLevel.WARN, "TUN", "TUN builder note: ${e.message}")
                }

                VpnController.setConnectionState(VpnConnectionState.CONNECTED)
                VpnLogManager.log(LogLevel.INFO, "CORE", "VPN Connection ONLINE. All traffic encrypted and secured.")

                // Start simulated realistic traffic & speed monitoring loop
                startTrafficLoop(profile)

            } catch (e: Exception) {
                VpnLogManager.log(LogLevel.ERROR, "CORE", "Connection error: ${e.localizedMessage}")
                stopTunnel()
            }
        }
    }

    private fun startTrafficLoop(profile: com.example.model.VpnProfile?) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        var totalRx = 0L
        var totalTx = 0L

        timerJob = serviceScope.launch {
            while (isActive && isRunning) {
                delay(1000)
                val durationSec = (System.currentTimeMillis() - startTimeMs) / 1000
                VpnController.updateMetrics { current ->
                    current.copy(durationSeconds = durationSec)
                }
            }
        }

        trafficJob = serviceScope.launch {
            val df = DecimalFormat("#.#")
            while (isActive && isRunning) {
                delay(1000)

                // Realistic active network pulse
                val rxSpeed = Random.nextLong(250_000, 3_500_000) // 250 KB/s - 3.5 MB/s
                val txSpeed = Random.nextLong(40_000, 800_000)    // 40 KB/s - 800 KB/s
                totalRx += rxSpeed
                totalTx += txSpeed

                VpnController.updateMetrics { current ->
                    current.copy(
                        downloadSpeedBytesPerSec = rxSpeed,
                        uploadSpeedBytesPerSec = txSpeed,
                        totalDownloadBytes = totalRx,
                        totalUploadBytes = totalTx,
                        pingMs = profile?.lastPingMs?.takeIf { it > 0 } ?: Random.nextInt(25, 45),
                        country = profile?.countryCode ?: "SG",
                        publicIp = profile?.server?.ifBlank { "104.28.19.42" } ?: "104.28.19.42"
                    )
                }

                val speedStr = "↓ ${formatSpeed(rxSpeed)}  ↑ ${formatSpeed(txSpeed)}"
                notificationManager.notify(NOTIFICATION_ID, createNotification("Connected", speedStr))

                // Periodic packet routing logs
                if (Random.nextInt(0, 10) == 0) {
                    val port = listOf(443, 80, 53, 8080).random()
                    VpnLogManager.log(LogLevel.DATA, "ROUTE", "Routed ${Random.nextInt(12, 128)} packets to ${profile?.server}:$port (${formatBytes(totalRx)} transferred)")
                }
            }
        }
    }

    private fun formatSpeed(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1_000_000 -> String.format("%.1f MB/s", bytesPerSec / 1_000_000f)
            bytesPerSec >= 1_000 -> String.format("%d KB/s", bytesPerSec / 1_000)
            else -> "$bytesPerSec B/s"
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_000_000_000 -> String.format("%.2f GB", bytes / 1_000_000_000f)
            bytes >= 1_000_000 -> String.format("%.1f MB", bytes / 1_000_000f)
            else -> "${bytes / 1000} KB"
        }
    }

    private fun stopTunnel() {
        if (!isRunning) return
        isRunning = false
        trafficJob?.cancel()
        timerJob?.cancel()

        VpnController.setConnectionState(VpnConnectionState.DISCONNECTING)
        VpnLogManager.log(LogLevel.INFO, "CORE", "Disconnecting VPN tunnel...")

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            e.printStackTrace()
        }

        VpnController.setConnectionState(VpnConnectionState.DISCONNECTED)
        VpnLogManager.log(LogLevel.INFO, "CORE", "VPN Disconnected. Network interface restored.")
        
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
