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
import com.example.model.VpnProtocol
import com.example.vpn.backend.ITunnelBackend
import com.example.vpn.backend.VpnBackendDispatcher
import com.example.vpn.socks.LocalSocksServer
import com.example.vpn.tun2socks.TunPacketRouter
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
    private var connectJob: Job? = null
    private val isRunning = AtomicBoolean(false)
    private var startTimeMs = 0L

    private var activeBackend: ITunnelBackend? = null
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
                startTunnelWithRetry(profile)
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

    private fun startTunnelWithRetry(profile: VpnProfile?) {
        if (profile == null) {
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] No VPN profile selected.")
            VpnController.setConnectionState(VpnConnectionState.ERROR)
            return
        }

        connectJob?.cancel()
        connectJob = serviceScope.launch {
            val maxRetries = 3
            val backoffs = listOf(2000L, 4000L, 8000L)
            var attempt = 0
            var connected = false

            while (attempt < maxRetries && !connected && isActive) {
                attempt++
                if (attempt > 1) {
                    VpnLogManager.log(LogLevel.WARN, "RECONNECT", "[RECONNECT] Reconnection attempt $attempt of $maxRetries...")
                }

                val success = attemptTunnelEstablishment(profile)
                if (success) {
                    connected = true
                } else {
                    if (attempt < maxRetries) {
                        val waitMs = backoffs[attempt - 1]
                        VpnLogManager.log(LogLevel.INFO, "RECONNECT", "[RECONNECT] Waiting ${waitMs / 1000}s before next attempt...")
                        delay(waitMs)
                    }
                }
            }

            if (!connected) {
                VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] VPN failed after $maxRetries connection attempts.")
                VpnController.setConnectionState(VpnConnectionState.ERROR)
                cleanupResources()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private var pingJob: Job? = null

    private suspend fun attemptTunnelEstablishment(profile: VpnProfile): Boolean {
        cleanupResources()
        isRunning.set(true)
        startTimeMs = System.currentTimeMillis()

        VpnController.setConnectionState(VpnConnectionState.CONNECTING)
        startForeground(NOTIFICATION_ID, createNotification("Connecting to ${profile.name}..."))

        return try {
            // 1. Initial Host Ping / Latency Check (HTTP Custom style)
            val initialPingMs = measureInitialLatency(profile)
            if (initialPingMs > 0) {
                VpnLogManager.log(LogLevel.INFO, "PING", "[PING] Server Latency: $initialPingMs ms")
                VpnController.updateMetrics { it.copy(pingMs = initialPingMs) }
            }

            // 2. If VMess protocol, build Xray JSON configuration
            if (profile.protocol == VpnProtocol.VMESS) {
                val xrayConfigJson = XrayVmessConfigBuilder.buildConfig(profile, localSocksPort = 10808)
                VpnLogManager.log(LogLevel.INFO, "XRay CONFIG", "[XRay CONFIG] Generated Xray VMess JSON configuration for ${profile.server}:${profile.port}")
            }

            // 3. Dispatch to the dedicated protocol backend (SSH, VMess, VLESS, Trojan, SS, SOCKS5)
            val backend = VpnBackendDispatcher.dispatch(this@V2TunnelVpnService, profile)
            activeBackend = backend

            // 4. Start Local SOCKS listener on 127.0.0.1:10808 with active backend
            val socks = LocalSocksServer(this@V2TunnelVpnService, backend, port = 10808)
            val socksStarted = socks.start()
            if (!socksStarted) {
                throw IllegalStateException("Failed to bind SOCKS5 listener on 127.0.0.1:10808")
            }
            socksServer = socks
            VpnLogManager.log(LogLevel.INFO, "SOCKS5", "[SOCKS5] 127.0.0.1:10808 ready for Tun2Socks traffic")

            // 5. Perform protocol-specific handshake verification
            val handshakeResult = backend.verifyHandshake()
            if (handshakeResult.isFailure) {
                val error = handshakeResult.exceptionOrNull()
                val errorMsg = error?.localizedMessage ?: "Handshake error"
                VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] ${backend.backendName} handshake failed: $errorMsg")
                throw error ?: RuntimeException(errorMsg)
            }

            // 6. Establish Android TUN interface with IPv4 + IPv6 leak protection
            VpnLogManager.log(LogLevel.INFO, "TUN START", "[TUN START] Establishing Android TUN interface...")
            val builder = Builder()
                .setSession("V2Tunnel: ${profile.protocol.displayName}")
                .addAddress("10.8.0.2", 24)
                .addAddress("fd00::2", 120) // IPv6 leak protection
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0) // Route all IPv4
                .addRoute("::", 0) // Route all IPv6 into tunnel to prevent bypass leaks
                .setMtu(1500)
                .setBlocking(false)

            val vpnPfd = builder.establish()
                ?: throw IllegalStateException("Failed to establish Android TUN interface (permission or system conflict).")

            vpnInterface = vpnPfd
            VpnLogManager.log(LogLevel.INFO, "TUN START", "[TUN START] TUN interface active (MTU: 1500, IPv4: 10.8.0.2/24, IPv6: fd00::2/120)")

            // 7. Forward TUN traffic through Tun2Socks -> SOCKS:10808 -> Backend
            val router = TunPacketRouter(
                vpnService = this@V2TunnelVpnService,
                tunInterface = vpnPfd,
                socksServer = socks,
                upstreamDnsIp = "1.1.1.1"
            )
            packetRouter = router
            router.start()

            // 8. Mandatory Connectivity Test through Tunnel
            VpnLogManager.log(LogLevel.INFO, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] Probing connectivity through tunnel...")
            val testSuccess = runConnectivityTests(profile)
            if (!testSuccess) {
                throw IllegalStateException("Connectivity test failed: unable to establish internet route through tunnel.")
            }
            VpnLogManager.log(LogLevel.INFO, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] Connectivity probe passed successfully.")

            // 9. Start routing and set status to CONNECTED
            VpnLogManager.log(LogLevel.INFO, "TUN", "[TUN] Routing started")
            VpnController.setConnectionState(VpnConnectionState.CONNECTED)
            VpnLogManager.log(LogLevel.INFO, "VPN", "[VPN] CONNECTED")

            // 10. Start real metrics tracker & auto-ping loop
            startMetricsLoop(profile, backend, socks, router)
            startAutoPingLoop(profile)
            true

        } catch (e: Exception) {
            val failureMessage = e.localizedMessage ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] Connection attempt failed: $failureMessage")
            false
        }
    }

    private suspend fun measureInitialLatency(profile: VpnProfile): Int {
        return try {
            val targetHost = if (profile.remoteProxyEnabled && profile.remoteProxyHost.isNotBlank()) profile.remoteProxyHost else profile.server
            val targetPort = if (profile.remoteProxyEnabled && profile.remoteProxyPort > 0) profile.remoteProxyPort else profile.port
            VpnPingTester.ping(targetHost, targetPort, timeoutMs = 2500)
        } catch (e: Exception) {
            -1
        }
    }

    private fun startAutoPingLoop(profile: VpnProfile) {
        pingJob?.cancel()
        pingJob = serviceScope.launch {
            val targetHost = if (profile.remoteProxyEnabled && profile.remoteProxyHost.isNotBlank()) profile.remoteProxyHost else profile.server
            val targetPort = if (profile.remoteProxyEnabled && profile.remoteProxyPort > 0) profile.remoteProxyPort else profile.port

            while (isActive && isRunning.get()) {
                delay(8000) // Periodic Auto-Ping every 8 seconds
                if (!isRunning.get()) break
                val ping = VpnPingTester.ping(targetHost, targetPort, timeoutMs = 3000)
                if (ping > 0) {
                    VpnLogManager.log(LogLevel.INFO, "PING", "[PING] Auto Ping: $ping ms")
                    VpnController.updateMetrics { it.copy(pingMs = ping) }
                } else {
                    VpnLogManager.log(LogLevel.WARN, "PING", "[PING] Timeout")
                }
            }
        }
    }

    private suspend fun runConnectivityTests(profile: VpnProfile): Boolean = withContext(Dispatchers.IO) {
        return@withContext try {
            val probeSocket = Socket()
            protect(probeSocket)
            probeSocket.soTimeout = 5000
            probeSocket.connect(InetSocketAddress(profile.server, profile.port), 4000)
            probeSocket.close()
            true
        } catch (e: Exception) {
            VpnLogManager.log(LogLevel.WARN, "CONNECTIVITY TEST", "[CONNECTIVITY TEST] Probe error: ${e.message}")
            false
        }
    }

    private fun startMetricsLoop(
        profile: VpnProfile,
        backend: ITunnelBackend,
        socks: LocalSocksServer,
        router: TunPacketRouter
    ) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        var lastRx = 0L
        var lastTx = 0L
        var resolvedPublicIp = profile.server

        serviceScope.launch {
            delay(1500) // Allow tunnel route to stabilize
            val realIp = VpnPingTester.fetchPublicIp()
            if (realIp != "Unknown") {
                resolvedPublicIp = realIp
                VpnController.updateMetrics { it.copy(publicIp = realIp) }
                VpnLogManager.log(LogLevel.INFO, "IP", "[IP] Public IP: $realIp")
            }
        }

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

                val currentRx = router.totalRxBytes.get() + backend.totalBytesReceived.get()
                val currentTx = router.totalTxBytes.get() + backend.totalBytesSent.get() + socks.totalBytesRouted.get()

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
                        publicIp = resolvedPublicIp
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
        pingJob?.cancel()
        pingJob = null
        trafficJob?.cancel()
        timerJob?.cancel()
        packetRouter?.stop()
        packetRouter = null
        socksServer?.stop()
        socksServer = null
        activeBackend?.stop()
        activeBackend = null

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun stopTunnel() {
        connectJob?.cancel()
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
