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
 * Local SOCKS5 proxy server used as the bridge between the TUN router
 * and the currently selected VPN protocol backend.
 *
 * Listener:
 *   127.0.0.1:10808
 *
 * Flow:
 *
 * Android application
 *       |
 *       v
 * Android TUN
 *       |
 *       v
 * TunPacketRouter
 *       |
 *       v
 * SOCKS5 127.0.0.1:10808
 *       |
 *       v
 * ITunnelBackend.createTunnelSocket()
 *       |
 *       v
 * SSH / VMESS / VLESS / TROJAN / SHADOWSOCKS / SOCKS5
 *
 * This class is intentionally protocol-agnostic.
 */
class LocalSocksServer(
    private val vpnService: VpnService,
    private val backend: ITunnelBackend,
    val port: Int = 10808
) {
    private val isRunning = AtomicBoolean(false)

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    private val serverScope = CoroutineScope(Dispatchers.IO)

    val totalBytesRouted = AtomicLong(0)

    /**
     * All sockets currently owned by this SOCKS server.
     *
     * Both client-side and backend tunnel sockets are tracked so stop()
     * can immediately close every active connection.
     */
    private val activeSockets =
        Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    /**
     * Start the local SOCKS5 listener.
     */
    fun start(): Boolean {
        if (isRunning.getAndSet(true)) {
            return true
        }

        return try {
            val server = ServerSocket()

            server.reuseAddress = true

            // Bind only to loopback.
            // The SOCKS server must never be exposed on the public interface.
            server.bind(
                InetSocketAddress(
                    InetAddress.getLoopbackAddress(),
                    port
                )
            )

            serverSocket = server

            VpnLogManager.log(
                LogLevel.INFO,
                "SOCKS5",
                "[SOCKS5] Local SOCKS5 listener bound successfully to 127.0.0.1:$port"
            )

            acceptJob = serverScope.launch {
                acceptLoop(server)
            }

            true
        } catch (e: Exception) {
            isRunning.set(false)

            VpnLogManager.log(
                LogLevel.ERROR,
                "SOCKS5",
                "[SOCKS5] Failed to bind port $port: ${e.message}"
            )

            false
        }
    }

    /**
     * Accept incoming local SOCKS5 connections.
     */
    private suspend fun acceptLoop(server: ServerSocket) {
        while (isActive && isRunning.get()) {
            var clientSocket: Socket? = null

            try {
                clientSocket = server.accept()

                if (!isRunning.get()) {
                    try {
                        clientSocket.close()
                    } catch (_: Exception) {
                    }
                    break
                }

                clientSocket.tcpNoDelay = true

                /*
                 * IMPORTANT:
                 *
                 * Do not set a short SO_TIMEOUT here.
                 *
                 * A VPN connection can legitimately remain idle for more
                 * than 30 seconds. The previous 30000 ms timeout could cause
                 * an otherwise healthy tunnel to be disconnected simply
                 * because no packet arrived during that interval.
                 */
                clientSocket.soTimeout = 0

                activeSockets.add(clientSocket)

                val acceptedSocket = clientSocket

                serverScope.launch {
                    handleSocksClient(acceptedSocket)
                }
            } catch (e: Exception) {
                clientSocket?.let {
                    activeSockets.remove(it)
                    try {
                        it.close()
                    } catch (_: Exception) {
                    }
                }

                if (isRunning.get()) {
                    VpnLogManager.log(
                        LogLevel.WARN,
                        "SOCKS5",
                        "[SOCKS5] Accept error: ${e.message}"
                    )
                }

                break
            }
        }
    }

    /**
     * Handle one SOCKS5 client connection.
     */
    private suspend fun handleSocksClient(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        var relayJob1: Job? = null
        var relayJob2: Job? = null

        try {
            val cIn = clientSocket.getInputStream()
            val cOut = clientSocket.getOutputStream()

            /*
             * -------------------------------------------------------------
             * 1. SOCKS5 METHOD NEGOTIATION
             * -------------------------------------------------------------
             */

            val version = cIn.read()

            if (version != 0x05) {
                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Invalid SOCKS version: $version"
                )
                return
            }

            val nMethods = cIn.read()

            if (nMethods <= 0 || nMethods > 255) {
                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Invalid method count: $nMethods"
                )
                return
            }

            val methods = ByteArray(nMethods)
            readFully(cIn, methods)

            /*
             * This server intentionally supports only NO_AUTH.
             *
             * Do not blindly reply 0x00 if the client did not offer it.
             */
            var noAuthSupported = false

            for (method in methods) {
                if ((method.toInt() and 0xFF) == 0x00) {
                    noAuthSupported = true
                    break
                }
            }

            if (!noAuthSupported) {
                cOut.write(
                    byteArrayOf(
                        0x05,
                        0xFF.toByte()
                    )
                )
                cOut.flush()

                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Client does not support NO_AUTH"
                )

                return
            }

            // SOCKS5 server selects NO_AUTH.
            cOut.write(
                byteArrayOf(
                    0x05,
                    0x00
                )
            )
            cOut.flush()

            /*
             * -------------------------------------------------------------
             * 2. SOCKS5 REQUEST
             * -------------------------------------------------------------
             */

            val reqHeader = ByteArray(4)
            readFully(cIn, reqHeader)

            if ((reqHeader[0].toInt() and 0xFF) != 0x05) {
                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Invalid request version"
                )
                return
            }

            val command = reqHeader[1].toInt() and 0xFF
            val atyp = reqHeader[3].toInt() and 0xFF

            /*
             * Only CONNECT is supported.
             */
            if (command != 0x01) {
                sendSocksError(
                    cOut,
                    replyCode = 0x07
                )

                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Unsupported command: $command"
                )

                return
            }

            /*
             * -------------------------------------------------------------
             * 3. TARGET ADDRESS
             * -------------------------------------------------------------
             */

            val targetHost: String

            when (atyp) {
                0x01 -> {
                    // IPv4
                    val ipBytes = ByteArray(4)
                    readFully(cIn, ipBytes)

                    targetHost =
                        InetAddress.getByAddress(ipBytes).hostAddress
                            ?: "0.0.0.0"
                }

                0x03 -> {
                    // DOMAIN
                    val domainLength = cIn.read()

                    if (domainLength <= 0 || domainLength > 255) {
                        sendSocksError(
                            cOut,
                            replyCode = 0x08
                        )

                        VpnLogManager.log(
                            LogLevel.WARN,
                            "SOCKS5",
                            "[SOCKS5] Invalid domain length: $domainLength"
                        )

                        return
                    }

                    val domainBytes = ByteArray(domainLength)
                    readFully(cIn, domainBytes)

                    targetHost =
                        String(
                            domainBytes,
                            Charsets.UTF_8
                        ).trim()

                    if (targetHost.isEmpty()) {
                        sendSocksError(
                            cOut,
                            replyCode = 0x08
                        )
                        return
                    }
                }

                0x04 -> {
                    // IPv6
                    val ip6Bytes = ByteArray(16)
                    readFully(cIn, ip6Bytes)

                    targetHost =
                        InetAddress.getByAddress(ip6Bytes).hostAddress
                            ?: "::"
                }

                else -> {
                    sendSocksError(
                        cOut,
                        replyCode = 0x08
                    )

                    VpnLogManager.log(
                        LogLevel.WARN,
                        "SOCKS5",
                        "[SOCKS5] Unsupported address type: $atyp"
                    )

                    return
                }
            }

            /*
             * -------------------------------------------------------------
             * 4. TARGET PORT
             * -------------------------------------------------------------
             */

            val portBytes = ByteArray(2)
            readFully(cIn, portBytes)

            val targetPort =
                ((portBytes[0].toInt() and 0xFF) shl 8) or
                    (portBytes[1].toInt() and 0xFF)

            if (targetPort !in 1..65535) {
                sendSocksError(
                    cOut,
                    replyCode = 0x01
                )

                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Invalid target port: $targetPort"
                )

                return
            }

            VpnLogManager.log(
                LogLevel.DATA,
                "SOCKS5",
                "[SOCKS5] CONNECT request: $targetHost:$targetPort"
            )

            /*
             * -------------------------------------------------------------
             * 5. CONNECT THROUGH ACTIVE VPN BACKEND
             * -------------------------------------------------------------
             *
             * IMPORTANT:
             *
             * The targetHost/targetPort here are the destination requested
             * by the Android application.
             *
             * They are NOT the SSH server, remote proxy, SNI, or any other
             * transport endpoint.
             *
             * The selected backend decides how to carry this connection.
             */

            try {
                remoteSocket =
                    backend.createTunnelSocket(
                        targetHost,
                        targetPort
                    )

                if (!remoteSocket.isConnected || remoteSocket.isClosed) {
                    throw IllegalStateException(
                        "Backend returned an unusable socket"
                    )
                }

                remoteSocket.tcpNoDelay = true

                /*
                 * The backend socket is already an SSH/Xray/etc. logical
                 * tunnel socket. Do not call vpnService.protect() here.
                 */
                activeSockets.add(remoteSocket)
            } catch (e: Exception) {
                VpnLogManager.log(
                    LogLevel.WARN,
                    "SOCKS5",
                    "[SOCKS5] Backend CONNECT failed for $targetHost:$targetPort: ${e.message}"
                )

                sendSocksError(
                    cOut,
                    replyCode = 0x04
                )

                return
            }

            /*
             * -------------------------------------------------------------
             * 6. SOCKS5 SUCCESS
             * -------------------------------------------------------------
             *
             * We do not expose the backend's real socket address here.
             * The SOCKS protocol only needs a valid BND.ADDR/BND.PORT.
             */

            cOut.write(
                byteArrayOf(
                    0x05,
                    0x00,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00
                )
            )
            cOut.flush()

            /*
             * -------------------------------------------------------------
             * 7. BIDIRECTIONAL RELAY
             * -------------------------------------------------------------
             */

            val remote = remoteSocket
                ?: throw IllegalStateException(
                    "Remote socket unexpectedly null"
                )

            val rIn = remote.getInputStream()
            val rOut = remote.getOutputStream()

            /*
             * Each direction gets its own coroutine.
             *
             * IMPORTANT:
             * relayStream() no longer blindly closes the shared output
             * stream when one direction reaches EOF. Closing one side's
             * output stream here can kill the opposite direction while the
             * connection is still valid.
             *
             * Complete socket cleanup happens in finally below.
             */
            relayJob1 = serverScope.launch {
                relayStream(
                    input = cIn,
                    output = rOut,
                    direction = "CLIENT_TO_BACKEND"
                )
            }

            relayJob2 = serverScope.launch {
                relayStream(
                    input = rIn,
                    output = cOut,
                    direction = "BACKEND_TO_CLIENT"
                )
            }

            /*
             * Wait until either direction finishes.
             *
             * Once one direction reaches EOF/error, the complete connection
             * is cleaned up in finally. This avoids leaving the other relay
             * permanently blocked on a dead connection.
             */
            while (
                isRunning.get() &&
                relayJob1.isActive &&
                relayJob2.isActive
            ) {
                kotlinx.coroutines.delay(100)
            }

        } catch (e: Exception) {
            if (isRunning.get()) {
                VpnLogManager.log(
                    LogLevel.DEBUG,
                    "SOCKS5",
                    "[SOCKS5] Client connection ended: ${e.message}"
                )
            }
        } finally {
            /*
             * Cancel relay coroutines first.
             */
            relayJob1?.cancel()
            relayJob2?.cancel()

            /*
             * Closing both sockets wakes any blocking read() calls.
             */
            try {
                clientSocket.shutdownInput()
            } catch (_: Exception) {
            }

            try {
                clientSocket.shutdownOutput()
            } catch (_: Exception) {
            }

            try {
                clientSocket.close()
            } catch (_: Exception) {
            }

            activeSockets.remove(clientSocket)

            remoteSocket?.let { sock ->
                try {
                    sock.shutdownInput()
                } catch (_: Exception) {
                }

                try {
                    sock.shutdownOutput()
                } catch (_: Exception) {
                }

                try {
                    sock.close()
                } catch (_: Exception) {
                }

                activeSockets.remove(sock)
            }
        }
    }

    /**
     * Relay bytes from one stream to another.
     *
     * This function deliberately does NOT close the output stream when the
     * input reaches EOF. The complete socket pair is closed by the caller.
     */
    private fun relayStream(
        input: InputStream,
        output: OutputStream,
        direction: String
    ) {
        val buffer = ByteArray(16384)

        try {
            while (isRunning.get()) {
                val bytesRead = input.read(buffer)

                if (bytesRead < 0) {
                    break
                }

                if (bytesRead == 0) {
                    continue
                }

                output.write(
                    buffer,
                    0,
                    bytesRead
                )

                output.flush()

                totalBytesRouted.addAndGet(
                    bytesRead.toLong()
                )
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                VpnLogManager.log(
                    LogLevel.DEBUG,
                    "SOCKS5",
                    "[SOCKS5] Relay $direction ended: ${e.message}"
                )
            }
        }
    }

    /**
     * Send a SOCKS5 error reply.
     *
     * Reply format:
     *
     * VER REP RSV ATYP BND.ADDR BND.PORT
     */
    private fun sendSocksError(
        output: OutputStream,
        replyCode: Int
    ) {
        try {
            output.write(
                byteArrayOf(
                    0x05,
                    replyCode.toByte(),
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00
                )
            )
            output.flush()
        } catch (_: Exception) {
        }
    }

    /**
     * Read exactly buffer.size bytes.
     */
    private fun readFully(
        input: InputStream,
        buffer: ByteArray
    ) {
        var total = 0

        while (total < buffer.size) {
            val n =
                input.read(
                    buffer,
                    total,
                    buffer.size - total
                )

            if (n < 0) {
                throw IllegalStateException(
                    "Unexpected EOF in SOCKS5 stream"
                )
            }

            if (n == 0) {
                continue
            }

            total += n
        }
    }

    /**
     * Stop the local SOCKS5 server and close every active connection.
     */
    fun stop() {
        if (!isRunning.getAndSet(false)) {
            return
        }

        /*
         * Cancel accept loop.
         */
        acceptJob?.cancel()
        acceptJob = null

        /*
         * Close listener first. This immediately wakes ServerSocket.accept().
         */
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }

        serverSocket = null

        /*
         * Close every client/backend socket.
         *
         * This also wakes blocking InputStream.read() calls inside relay
         * coroutines.
         */
        activeSockets.forEach { sock ->
            try {
                sock.shutdownInput()
            } catch (_: Exception) {
            }

            try {
                sock.shutdownOutput()
            } catch (_: Exception) {
            }

            try {
                sock.close()
            } catch (_: Exception) {
            }
        }

        activeSockets.clear()

        VpnLogManager.log(
            LogLevel.INFO,
            "SOCKS5",
            "[SOCKS5] Local SOCKS5 listener closed cleanly."
        )
    }
}
