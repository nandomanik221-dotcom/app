package com.example.vpn.trojan

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
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class TrojanTunnelClient(
    private val vpnService: VpnService,
    private val profile: VpnProfile
) : ITunnelBackend {

    override val backendName: String = "Trojan"
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
                throw IllegalArgumentException("Invalid Trojan server host or port: $serverHost:$serverPort")
            }

            val rawSni = profile.sni.ifBlank { profile.host.ifBlank { serverHost } }
            val cleanSni = SniUtils.sanitizeSni(rawSni, serverHost)

            VpnLogManager.log(LogLevel.CONN, "TROJAN CONNECT", "[TROJAN CONNECT] Connecting to remote Trojan server $serverHost:$serverPort...")

            val socketChannel = java.nio.channels.SocketChannel.open()
            val rawSocket = socketChannel.socket()
            vpnService.protect(rawSocket)
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = 10000
            rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

            var activeSocket: Socket = rawSocket

            if (profile.isTls) {
                VpnLogManager.log(LogLevel.CONN, "TROJAN TLS", "[TROJAN TLS] Initiating TLS handshake with SNI: $cleanSni")
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
                VpnLogManager.log(LogLevel.CONN, "TROJAN TLS", "[TROJAN TLS] TLS handshake established successfully (Cipher: ${sslSocket.session.cipherSuite})")
            }

            VpnLogManager.log(LogLevel.CONN, "TROJAN AUTH", "[TROJAN AUTH] Verifying Trojan SHA-224 password hash...")
            val passwordHash = sha224Hex(profile.password)
            val out = activeSocket.getOutputStream()
            out.write("$passwordHash\r\n".toByteArray(Charsets.US_ASCII))
            out.flush()

            VpnLogManager.log(LogLevel.CONN, "TROJAN READY", "[TROJAN READY] Trojan proxy tunnel ready.")

            isRunning.set(true)
            isTunnelReady.set(true)
            try { activeSocket.close() } catch (ignored: Exception) {}

            Result.success(Unit)
        } catch (e: Exception) {
            val err = e.localizedMessage ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] Trojan connection failed: $err")
            Result.failure(e)
        }
    }

    override fun createTunnelSocket(targetHost: String, targetPort: Int): Socket {
        val serverHost = profile.server
        val serverPort = profile.port
        val rawSni = profile.sni.ifBlank { profile.host.ifBlank { serverHost } }
        val cleanSni = SniUtils.sanitizeSni(rawSni, serverHost)

        val socketChannel = java.nio.channels.SocketChannel.open()
        val rawSocket = socketChannel.socket()
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

        val passwordHash = sha224Hex(profile.password)
        val out = activeSocket.getOutputStream()
        out.write("$passwordHash\r\n".toByteArray(Charsets.US_ASCII))
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

    private fun sha224Hex(input: String): String {
        val md = MessageDigest.getInstance("SHA-224")
        val digest = md.digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
