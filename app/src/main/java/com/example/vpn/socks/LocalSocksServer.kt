package com.example.vpn.socks

import android.net.VpnService
import com.example.model.LogLevel
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Production-ready local SOCKS5 Proxy Server (127.0.0.1:10808).
 * 
 * Intercepts SOCKS5 CONNECT requests from the Tun2Socks engine and bridges them
 * bidirectionally to the active outbound protocol backend with protected sockets.
 */
class LocalSocksServer(
    private val vpnService: VpnService,
    private val backend: ITunnelBackend,
    val port: Int = 10808
) {
    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val serverScope = CoroutineScope(Dispatchers.IO)
    private var acceptJob: Job? = null

    val totalBytesRouted = AtomicLong(0)
    private val activeSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    fun start(): Boolean {
        if (isRunning.getAndSet(true)) return true

        return try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress("127.0.0.1", port))
            serverSocket = server

            VpnLogManager.log(LogLevel.INFO, "SOCKS5", "[SOCKS5] Local SOCKS5 listener bound successfully to 127.0.0.1:$port")

            acceptJob = serverScope.launch {
                while (isActive && isRunning.get()) {
                    try {
                        val clientSocket = server.accept()
                        clientSocket.tcpNoDelay = true
                        clientSocket.soTimeout = 30000
                        activeSockets.add(clientSocket)

                        serverScope.launch {
                            handleSocksClient(clientSocket)
                        }
                    } catch (e: Exception) {
                        if (isRunning.get()) {
                            VpnLogManager.log(LogLevel.WARN, "SOCKS5", "[SOCKS5] Accept error: ${e.message}")
                        }
                        break
                    }
                }
            }
            true
        } catch (e: Exception) {
            isRunning.set(false)
            VpnLogManager.log(LogLevel.ERROR, "SOCKS5", "[SOCKS5] Failed to bind port $port: ${e.message}")
            false
        }
    }

    private suspend fun handleSocksClient(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            val cIn = clientSocket.getInputStream()
            val cOut = clientSocket.getOutputStream()

            // 1. SOCKS5 Method Negotiation Greeting
            val ver = cIn.read()
            if (ver != 0x05) {
                return // Not SOCKS5
            }
            val nMethods = cIn.read()
            val methods = ByteArray(nMethods)
            readFully(cIn, methods)

            // Reply NO_AUTH (0x05, 0x00)
            cOut.write(byteArrayOf(0x05, 0x00))
            cOut.flush()

            // 2. SOCKS5 Request Details
            val reqHeader = ByteArray(4)
            readFully(cIn, reqHeader)

            val cmd = reqHeader[1].toInt() and 0xFF
            val atyp = reqHeader[3].toInt() and 0xFF

            if (cmd != 0x01) { // 0x01 = CONNECT
                cOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0)) // Command not supported
                cOut.flush()
                return
            }

            val targetHost: String
            when (atyp) {
                0x01 -> { // IPv4
                    val ipBytes = ByteArray(4)
                    readFully(cIn, ipBytes)
                    targetHost = InetAddress.getByAddress(ipBytes).hostAddress ?: "127.0.0.1"
                }
                0x03 -> { // Domain name
                    val domainLen = cIn.read()
                    val domainBytes = ByteArray(domainLen)
                    readFully(cIn, domainBytes)
                    targetHost = String(domainBytes, Charsets.UTF_8)
                }
                0x04 -> { // IPv6
                    val ip6Bytes = ByteArray(16)
                    readFully(cIn, ip6Bytes)
                    targetHost = InetAddress.getByAddress(ip6Bytes).hostAddress ?: "::1"
                }
                else -> {
                    cOut.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    cOut.flush()
                    return
                }
            }

            val portBytes = ByteArray(2)
            readFully(cIn, portBytes)
            val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            // 3. Connect to remote destination via active protocol backend
            try {
                remoteSocket = backend.createTunnelSocket(targetHost, targetPort)
                activeSockets.add(remoteSocket)
            } catch (e: Exception) {
                cOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0)) // Host unreachable
                cOut.flush()
                return
            }

            // SOCKS5 Success Response
            cOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            cOut.flush()

            // 4. Bidirectional Relay
            val rIn = remoteSocket.getInputStream()
            val rOut = remoteSocket.getOutputStream()

            val job1 = serverScope.launch {
                relayStream(cIn, rOut)
            }
            val job2 = serverScope.launch {
                relayStream(rIn, cOut)
            }

            job1.join()
            job2.join()

        } catch (e: Exception) {
            // Connection closed
        } finally {
            activeSockets.remove(clientSocket)
            try { clientSocket.close() } catch (ignored: Exception) {}
            remoteSocket?.let { sock ->
                activeSockets.remove(sock)
                try { sock.close() } catch (ignored: Exception) {}
            }
        }
    }

    private fun relayStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(16384)
        try {
            while (isRunning.get()) {
                val bytesRead = input.read(buffer)
                if (bytesRead <= 0) break
                output.write(buffer, 0, bytesRead)
                output.flush()
                totalBytesRouted.addAndGet(bytesRead.toLong())
            }
        } catch (ignored: Exception) {
        } finally {
            try { output.close() } catch (ignored: Exception) {}
        }
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var total = 0
        while (total < buffer.size) {
            val n = input.read(buffer, total, buffer.size - total)
            if (n == -1) throw IllegalStateException("Unexpected EOF in SOCKS5 stream")
            total += n
        }
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        acceptJob?.cancel()

        try {
            serverSocket?.close()
        } catch (ignored: Exception) {}
        serverSocket = null

        activeSockets.forEach { sock ->
            try { sock.close() } catch (ignored: Exception) {}
        }
        activeSockets.clear()

        VpnLogManager.log(LogLevel.INFO, "SOCKS5", "[SOCKS5] Local SOCKS5 listener closed cleanly.")
    }
}
