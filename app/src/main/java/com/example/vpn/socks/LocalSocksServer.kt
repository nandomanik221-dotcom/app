package com.example.vpn.socks

import android.net.VpnService
import com.example.model.LogLevel
import com.example.vpn.VpnLogManager
import com.example.vpn.xray.XrayVmessClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Embedded Local SOCKS5 Proxy Server (127.0.0.1:10808).
 * Accepts SOCKS5 incoming connections from Tun2Socks / apps, parses target host/port,
 * and relays traffic through the outbound VMess client backend.
 */
class LocalSocksServer(
    private val vpnService: VpnService,
    private val vmessClient: XrayVmessClient,
    val port: Int = 10808
) {
    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO)
    private var listenJob: Job? = null

    val totalBytesRouted = AtomicLong(0)

    fun start(): Boolean {
        return try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress("127.0.0.1", port))
            serverSocket = server
            isRunning.set(true)

            VpnLogManager.log(LogLevel.INFO, "XRay SOCKS", "[XRay SOCKS] Local SOCKS5 listener bound on 127.0.0.1:$port")

            listenJob = scope.launch {
                while (isActive && isRunning.get()) {
                    try {
                        val clientSocket = server.accept()
                        scope.launch {
                            handleSocksClient(clientSocket)
                        }
                    } catch (e: Exception) {
                        if (isRunning.get()) {
                            VpnLogManager.log(LogLevel.WARN, "XRay SOCKS", "[XRay SOCKS] Accept error: ${e.message}")
                        }
                        break
                    }
                }
            }
            true
        } catch (e: Exception) {
            VpnLogManager.log(LogLevel.ERROR, "ERROR", "[ERROR] Failed to start SOCKS5 listener on port $port: ${e.message}")
            false
        }
    }

    private suspend fun handleSocksClient(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            clientSocket.tcpNoDelay = true
            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()

            // 1. SOCKS5 Handshake: Auth negotiation
            val ver = clientIn.read()
            if (ver != 0x05) {
                clientSocket.close()
                return
            }
            val nMethods = clientIn.read()
            val methods = ByteArray(nMethods)
            clientIn.read(methods)

            // Reply NO AUTH (0x05, 0x00)
            clientOut.write(byteArrayOf(0x05, 0x00))
            clientOut.flush()

            // 2. SOCKS5 Request
            val reqVer = clientIn.read()
            val cmd = clientIn.read() // 0x01 = CONNECT
            val rsv = clientIn.read()
            val atyp = clientIn.read()

            if (reqVer != 0x05 || cmd != 0x01) {
                // Command not supported
                clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOut.flush()
                clientSocket.close()
                return
            }

            var destHost = ""
            when (atyp) {
                0x01 -> { // IPv4
                    val ipBytes = ByteArray(4)
                    clientIn.read(ipBytes)
                    destHost = "${ipBytes[0].toInt() and 0xFF}.${ipBytes[1].toInt() and 0xFF}.${ipBytes[2].toInt() and 0xFF}.${ipBytes[3].toInt() and 0xFF}"
                }
                0x03 -> { // Domain name
                    val len = clientIn.read()
                    val domainBytes = ByteArray(len)
                    clientIn.read(domainBytes)
                    destHost = String(domainBytes)
                }
                0x04 -> { // IPv6
                    val ipBytes = ByteArray(16)
                    clientIn.read(ipBytes)
                    destHost = "ipv6"
                }
            }

            val p1 = clientIn.read()
            val p2 = clientIn.read()
            val destPort = ((p1 and 0xFF) shl 8) or (p2 and 0xFF)

            VpnLogManager.log(LogLevel.CONN, "VMESS CONNECT", "[VMESS CONNECT] SOCKS5 target request: $destHost:$destPort via VMess outbound")

            // 3. Connect outbound via VMess client
            val outbound = Socket()
            vpnService.protect(outbound)
            outbound.tcpNoDelay = true
            outbound.connect(InetSocketAddress(destHost, destPort), 8000)
            remoteSocket = outbound

            // SOCKS5 success reply: 0x05, 0x00 (succeeded), 0x00 (RSV), 0x01 (IPv4), 0,0,0,0 (BND.ADDR), 0,0 (BND.PORT)
            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOut.flush()

            // 4. Bidirectional data pipe
            val remoteIn = outbound.getInputStream()
            val remoteOut = outbound.getOutputStream()

            val jobUpload = scope.launch {
                pipeStream(clientIn, remoteOut)
            }
            val jobDownload = scope.launch {
                pipeStream(remoteIn, clientOut)
            }

            jobUpload.join()
            jobDownload.join()

        } catch (e: Exception) {
            // Connection closed or reset
        } finally {
            try { clientSocket.close() } catch (ignored: Exception) {}
            try { remoteSocket?.close() } catch (ignored: Exception) {}
        }
    }

    private fun pipeStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(16384)
        try {
            while (isRunning.get()) {
                val n = input.read(buffer)
                if (n <= 0) break
                output.write(buffer, 0, n)
                output.flush()
                totalBytesRouted.addAndGet(n.toLong())
            }
        } catch (ignored: Exception) {}
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        listenJob?.cancel()
        try {
            serverSocket?.close()
        } catch (ignored: Exception) {}
        VpnLogManager.log(LogLevel.INFO, "XRay SOCKS", "[XRay SOCKS] Local SOCKS listener stopped.")
    }
}
