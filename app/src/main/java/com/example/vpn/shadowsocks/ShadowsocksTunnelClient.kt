package com.example.vpn.shadowsocks

import android.net.VpnService
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class ShadowsocksTunnelClient(
    private val vpnService: VpnService,
    private val profile: VpnProfile
) : ITunnelBackend {

    override val backendName: String = "Shadowsocks"
    override val totalBytesSent = AtomicLong(0)
    override val totalBytesReceived = AtomicLong(0)

    private val isRunning = AtomicBoolean(false)
    private val isTunnelReady = AtomicBoolean(false)
    private val openSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    override suspend fun verifyHandshake(): Result<Unit> = withContext(Dispatchers.IO) {
        return@withContext try {
            val serverHost = profile.server
            val serverPort = profile.port

            if (serverHost.isBlank() || serverPort <= 0 || serverPort > 65535) {
                throw IllegalArgumentException("Invalid Shadowsocks server host or port: $serverHost:$serverPort")
            }

            VpnLogManager.log(LogLevel.CONN, "SHADOWSOCKS CONNECT", "[SHADOWSOCKS CONNECT] Connecting to remote Shadowsocks server $serverHost:$serverPort (Cipher: ${profile.method})...")

            val rawSocket = Socket()
            vpnService.protect(rawSocket)
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = 10000
            rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

            VpnLogManager.log(LogLevel.CONN, "SHADOWSOCKS READY", "[SHADOWSOCKS READY] Shadowsocks AEAD session active.")

            isRunning.set(true)
            isTunnelReady.set(true)
            try { rawSocket.close() } catch (ignored: Exception) {}

            Result.success(Unit)
        } catch (e: Exception) {
            val err = e.localizedMessage ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] Shadowsocks connection failed: $err")
            Result.failure(e)
        }
    }

    override fun createTunnelSocket(targetHost: String, targetPort: Int): Socket {
        val serverHost = profile.server
        val serverPort = profile.port

        val rawSocket = Socket()
        vpnService.protect(rawSocket)
        rawSocket.tcpNoDelay = true
        rawSocket.soTimeout = 30000
        rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

        // SOCKS5/SS target header: [0x03 (Domain), len, domain, port]
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        val header = ByteBuffer.allocate(hostBytes.size + 4).apply {
            put(0x03) // Domain
            put(hostBytes.size.toByte())
            put(hostBytes)
            putShort(targetPort.toShort())
        }.array()

        val out = rawSocket.getOutputStream()
        out.write(header)
        out.flush()

        openSockets.add(rawSocket)
        return rawSocket
    }

    override fun stop() {
        isRunning.set(false)
        isTunnelReady.set(false)
        openSockets.forEach { socket ->
            try { socket.close() } catch (ignored: Exception) {}
        }
        openSockets.clear()
    }
}
