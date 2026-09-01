package com.example.vpn.socks

import android.net.VpnService
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class Socks5TunnelClient(
    private val vpnService: VpnService,
    private val profile: VpnProfile
) : ITunnelBackend {

    override val backendName: String = "SOCKS5"
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
                throw IllegalArgumentException("Invalid SOCKS5 server host or port: $serverHost:$serverPort")
            }

            VpnLogManager.log(LogLevel.CONN, "SOCKS5 CONNECT", "[SOCKS5 CONNECT] Connecting to remote SOCKS5 server $serverHost:$serverPort...")

            val rawSocket = Socket()
            vpnService.protect(rawSocket)
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = 10000
            rawSocket.connect(InetSocketAddress(serverHost, serverPort), 8000)

            // Greeting
            val out = rawSocket.getOutputStream()
            val inStream = rawSocket.getInputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x00)) // NO_AUTH
            out.flush()

            val ver = inStream.read()
            val method = inStream.read()
            if (ver != 0x05) {
                throw IllegalStateException("Upstream server is not a valid SOCKS5 proxy (ver: $ver)")
            }

            VpnLogManager.log(LogLevel.CONN, "SOCKS5 READY", "[SOCKS5 READY] Upstream SOCKS5 proxy connected.")

            isRunning.set(true)
            isTunnelReady.set(true)
            try { rawSocket.close() } catch (ignored: Exception) {}

            Result.success(Unit)
        } catch (e: Exception) {
            val err = e.localizedMessage ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] SOCKS5 connection failed: $err")
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

        val out = rawSocket.getOutputStream()
        val inStream = rawSocket.getInputStream()

        // Greeting
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
        inStream.read() // ver
        inStream.read() // method

        // Connect request
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        val req = ByteArray(4 + 1 + hostBytes.size + 2)
        req[0] = 0x05 // SOCKS5
        req[1] = 0x01 // CONNECT
        req[2] = 0x00 // RSV
        req[3] = 0x03 // DOMAIN
        req[4] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
        val portOffset = 5 + hostBytes.size
        req[portOffset] = ((targetPort ushr 8) and 0xFF).toByte()
        req[portOffset + 1] = (targetPort and 0xFF).toByte()

        out.write(req)
        out.flush()

        // Read response
        val respHeader = ByteArray(4)
        var read = 0
        while (read < 4) {
            val r = inStream.read(respHeader, read, 4 - read)
            if (r == -1) break
            read += r
        }

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
