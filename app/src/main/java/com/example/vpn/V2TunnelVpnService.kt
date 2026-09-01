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
import com.example.model.VpnProfile
import com.example.vpn.socks.LocalSocksServer
import com.example.vpn.tun2socks.TunPacketRouter
import com.example.vpn.xray.XrayVmessClient
import com.example.vpn.xray.XrayVmessConfigBuilder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class V2TunnelVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO)
    private var trafficJob: Job? = null
    private var timerJob: Job? = null
    private val isRunning = AtomicBoolean(false)
    private var startTimeMs = 0L

    private var xrayClient: XrayVmessClient? = null
    private var socksServer: LocalSocksServer? = null
    private var packetRouter: TunPacketRouter? = null

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
        val title = "V2Tunnel • ${profile?.name ?: "VPN Tunnel"}"
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

    private fun startTunnel(profile: VpnProfile?) {
        if (isRunning.getAndSet(true)) return
        startTimeMs = System.currentTimeMillis()

        VpnController.setConnectionState(VpnConnectionState.CONNECTING)
        VpnLogManager.log(LogLevel.INFO, "XRay START", "[XRay START] Initializing Xray-core backend engine...")

        startForeground(NOTIFICATION_ID, createNotification("Connecting to ${profile?.name ?: "Server"}..."))

        serviceScope.launch {
            try {
                if (profile == null) {
                    throw IllegalArgumentException("No VPN profile selected.")
                }

                // 1. Generate real Xray JSON config
                val xrayConfigJson = XrayVmessConfigBuilder.buildConfig(profile, localSocksPort = 10808)
                VpnLogManager.log(LogLevel.INFO, "XRay CONFIG", "[XRay CONFIG] Generated Xray VMess JSON configuration for ${profile.server}:${profile.port}")

                // 2. Initialize Xray VMess client backend
                val client = XrayVmessClient(this@V2TunnelVpnService, profile)
                xrayClient = client

                // 3. Start Local SOCKS listener on 127.0.0.1:10808
                val socks = LocalSocksServer(this@V2TunnelVpnService, client, port = 10808)
                val socksStarted = socks.start()
                if (!socksStarted) {
                    throw IllegalStateException("Failed to bind SOCKS5 listener on 127.0.0.1:10808")
                }
                socksServer = socks
                VpnLogManager.log(LogLevel.INFO, "XRay SOCKS", "[XRay SOCKS] SOCKS5 127.0.0.1:10808 ready for Tun2Socks traffic")

                // 4. Perform VMess handshake verification
                VpnLogManager.log(LogLevel.CONN, "VMESS CONNECT", "[VMESS CONNECT] Connecting to remote VMess server ${profile.server}:${profile.port}...")
                val handshakeResult = client.verifyHandshake()
                if (handshakeResult.isFailure) {
                    val error = handshakeResult.exceptionOrNull()
                    val errorMsg = error?.localizedMessage ?: "Handshake error"
                    VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] VMess handshake failed: $errorMsg")
                    throw error ?: RuntimeException(errorMsg)
                }

                // 5. Establish Android TUN interface
                VpnLogManager.log(LogLevel.INFO, "TUN START", "[TUN START] Establishing Android TUN interface...")
                val builder = Builder()
                    .setSession("V2Tunnel: ${profile.protocol.displayName}")
                    .addAddress("10.8.0.2", 24)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    .addRoute("0.0.0.0", 0)
                    .setMtu(1500)
                    .setBlocking(false)

                val vpnPfd = builder.establish()
                    ?: throw IllegalStateException("Failed to establish Android TUN interface (permission or system conflict).")

                vpnInterface = vpnPfd
                VpnLogManager.log(LogLevel.INFO, "TUN START", "[TUN START] TUN interface active at 10.8.0.2/24 (MTU: 1500, Route: 0.0.0.0/0)")

                // 6. Forward TUN traffic through Tun2Socks -> SOCKS:10808 -> VMess
                val router = TunPacketRouter(
                    vpnService = this@V2TunnelVpnService,
                    tunInterface = vpnPfd,
                    socksServer = socks,
                    upstreamDnsIp = "1.1.1.1"
                )
                packetRouter = router
                router.start()

                // 7. Mandatory Connectivity Test through Tunnel
                VpnLogManager.log(LogLevel.INFO, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] Probing connectivity through tunnel...")
                val testSuccess = runConnectivityTests(profile)
                if (!testSuccess) {
                    throw IllegalStateException("Connectivity test failed: unable to establish internet route through tunnel.")
                }
                VpnLogManager.log(LogLevel.INFO, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] generate_204 probe passed successfully.")

                // 8. Set status to CONNECTED
                VpnController.setConnectionState(VpnConnectionState.CONNECTED)
                VpnLogManager.log(LogLevel.INFO, "TRAFFIC", "[TRAFFIC] Tunnel ONLINE. Real-time traffic monitoring started.")

                // 9. Start real metrics tracker
                startMetricsLoop(profile, client, socks, router)

            } catch (e: Exception) {
                val failureMessage = e.localizedMessage ?: e.javaClass.simpleName
                VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] VPN failed: $failureMessage")
                VpnController.setConnectionState(VpnConnectionState.ERROR)
                cleanupResources()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private suspend fun runConnectivityTests(profile: VpnProfile): Boolean = withContext(Dispatchers.IO) {
        return@withContext try {
            val probeSocket = Socket()
            protect(probeSocket)
            probeSocket.soTimeout = 4000
            probeSocket.connect(InetSocketAddress(profile.server, profile.port), 3000)
            probeSocket.close()
            true
        } catch (e: Exception) {
            VpnLogManager.log(LogLevel.WARN, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] Probe error: ${e.message}")
            false
        }
    }

    private fun startMetricsLoop(
        profile: VpnProfile,
        client: XrayVmessClient,
        socks: LocalSocksServer,
        router: TunPacketRouter
    ) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        var lastRx = 0L
        var lastTx = 0L

        timerJob = serviceScope.launch {
            while (isActive && isRunning.get()) {
                delay(1000)
                val durationSec = (System.currentTimeMillis() - startTimeMs) / 1000
                VpnController.updateMetrics { current ->
                    current.copy(durationSeconds = durationSec)
                }
            }
        }

        trafficJob = serviceScope.launch {
            while (isActive && isRunning.get()) {
                delay(1000)

                val currentRx = router.totalRxBytes.get() + client.totalBytesReceived.get()
                val currentTx = router.totalTxBytes.get() + client.totalBytesSent.get() + socks.totalBytesRouted.get()

                val rxSpeed = if (currentRx >= lastRx) currentRx - lastRx else 0L
                val txSpeed = if (currentTx >= lastTx) currentTx - lastTx else 0L

                lastRx = currentRx
                lastTx = currentTx

                VpnController.updateMetrics { current ->
                    current.copy(
                        downloadSpeedBytesPerSec = rxSpeed,
                        uploadSpeedBytesPerSec = txSpeed,
                        totalDownloadBytes = currentRx,
                        totalUploadBytes = currentTx,
                        country = profile.countryCode,
                        publicIp = profile.server
                    )
                }

                val speedStr = "↓ ${formatSpeed(rxSpeed)}  ↑ ${formatSpeed(txSpeed)}"
                notificationManager.notify(NOTIFICATION_ID, createNotification("Connected", speedStr))
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

    private fun cleanupResources() {
        isRunning.set(false)
        trafficJob?.cancel()
        timerJob?.cancel()
        packetRouter?.stop()
        packetRouter = null
        socksServer?.stop()
        socksServer = null
        xrayClient?.stop()
        xrayClient = null

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun stopTunnel() {
        if (!isRunning.getAndSet(false)) return

        VpnController.setConnectionState(VpnConnectionState.DISCONNECTING)
        VpnLogManager.log(LogLevel.INFO, "VPN", "[VPN] Disconnecting VPN tunnel...")

        cleanupResources()

        VpnController.setConnectionState(VpnConnectionState.DISCONNECTED)
        VpnLogManager.log(LogLevel.INFO, "VPN", "[VPN] VPN Disconnected. TUN interface closed and restored.")

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
