package com.example.vpn.xray

import android.net.VpnService
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import com.example.vpn.util.SniUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class VlessTunnelClient(
    private val vpnService: VpnService,
    private val profile: VpnProfile
) : ITunnelBackend {

    override val backendName: String = "VLESS"
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
                throw IllegalArgumentException("Invalid VLESS server host or port: $serverHost:$serverPort")
            }

            val rawSni = profile.sni.ifBlank { profile.host.ifBlank { serverHost } }
            val cleanSni = SniUtils.sanitizeSni(rawSni, serverHost)

            VpnLogManager.log(LogLevel.CONN, "VLESS CONNECT", "[VLESS CONNECT] Connecting to remote VLESS server $serverHost:$serverPort...")

            val rawSocket = Socket()
            vpnService.protect(rawSocket)
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = 10000
            rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

            var activeSocket: Socket = rawSocket

            if (profile.isTls) {
                VpnLogManager.log(LogLevel.CONN, "VLESS TLS", "[VLESS TLS] Initiating TLS handshake with SNI: $cleanSni")
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val sslSocket = sslFactory.createSocket(rawSocket, serverHost, serverPort, true) as SSLSocket
                vpnService.protect(sslSocket)

                if (cleanSni.isNotBlank()) {
                    val sslParams = SSLParameters().apply {
                        serverNames = listOf(SNIHostName(cleanSni))
                    }
                    sslSocket.sslParameters = sslParams
                }
                sslSocket.startHandshake()
                activeSocket = sslSocket
                VpnLogManager.log(LogLevel.CONN, "VLESS TLS", "[VLESS TLS] TLS handshake established successfully (Cipher: ${sslSocket.session.cipherSuite})")
            }

            VpnLogManager.log(LogLevel.CONN, "VLESS AUTH", "[VLESS AUTH] Preparing VLESS request header for UUID: ${profile.password}")
            val uuid = try {
                UUID.fromString(profile.password.trim())
            } catch (e: Exception) {
                UUID.nameUUIDFromBytes(profile.password.toByteArray())
            }

            val header = buildVlessHeader(uuid, "1.1.1.1", 80)
            val out = activeSocket.getOutputStream()
            out.write(header)
            out.flush()

            VpnLogManager.log(LogLevel.CONN, "VLESS READY", "[VLESS READY] VLESS tunnel active and ready.")

            isRunning.set(true)
            isTunnelReady.set(true)
            try { activeSocket.close() } catch (ignored: Exception) {}

            Result.success(Unit)
        } catch (e: Exception) {
            val err = e.localizedMessage ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] VLESS connection failed: $err")
            Result.failure(e)
        }
    }

    override fun createTunnelSocket(targetHost: String, targetPort: Int): Socket {
        val serverHost = profile.server
        val serverPort = profile.port
        val rawSni = profile.sni.ifBlank { profile.host.ifBlank { serverHost } }
        val cleanSni = SniUtils.sanitizeSni(rawSni, serverHost)

        val rawSocket = Socket()
        vpnService.protect(rawSocket)
        rawSocket.tcpNoDelay = true
        rawSocket.soTimeout = 30000
        rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

        var activeSocket: Socket = rawSocket

        if (profile.isTls) {
            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val sslSocket = sslFactory.createSocket(rawSocket, serverHost, serverPort, true) as SSLSocket
            vpnService.protect(sslSocket)

            if (cleanSni.isNotBlank()) {
                val sslParams = SSLParameters().apply {
                    serverNames = listOf(SNIHostName(cleanSni))
                }
                sslSocket.sslParameters = sslParams
            }
            sslSocket.startHandshake()
            activeSocket = sslSocket
        }

        val uuid = try {
            UUID.fromString(profile.password.trim())
        } catch (e: Exception) {
            UUID.nameUUIDFromBytes(profile.password.toByteArray())
        }

        val header = buildVlessHeader(uuid, targetHost, targetPort)
        val out = activeSocket.getOutputStream()
        out.write(header)
        out.flush()

        openSockets.add(activeSocket)
        return activeSocket
    }

    override fun stop() {
        isRunning.set(false)
        isTunnelReady.set(false)
        openSockets.forEach { socket ->
            try { socket.close() } catch (ignored: Exception) {}
        }
        openSockets.clear()
    }

    private fun buildVlessHeader(uuid: UUID, targetHost: String, targetPort: Int): ByteArray {
        val buffer = ByteBuffer.allocate(256)
        buffer.put(0x00) // VLESS version 0
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        buffer.putLong(msb)
        buffer.putLong(lsb)
        buffer.put(0x00) // Addons length = 0
        buffer.put(0x01) // Command: 1 = TCP
        buffer.putShort(targetPort.toShort())
        buffer.put(0x02) // Address type: 2 = Domain
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        buffer.put(hostBytes.size.toByte())
        buffer.put(hostBytes)

        val result = ByteArray(buffer.position())
        buffer.flip()
        buffer.get(result)
        return result
    }
}
