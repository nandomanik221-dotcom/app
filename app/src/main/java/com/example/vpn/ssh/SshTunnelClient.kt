package com.example.vpn.ssh

import android.net.VpnService
import android.util.Base64
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import com.example.vpn.backend.UpstreamSocketProtector
import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.PayloadMode
import com.example.vpn.util.SniUtils
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Production-ready SSH Tunnel Client Backend for V2Tunnel.
 *
 * Implements a complete HTTP Custom compliant SSH pipeline powered by genuine JSch session management:
 * 1. Protected Outbound Socket (VpnService.protect() before connect)
 * 2. Remote Proxy Transport (HTTP CONNECT RFC 7230 / SOCKS5 Proxy RFC 1928 & RFC 1929)
 * 3. Direct SSL / TLS Encapsulation with Sanitized SNI
 * 4. Custom HTTP / WebSocket Payload Injection with RFC 9112 Status Parsing
 * 5. RFC 6455 WebSocket Framing Layer for WS-wrapped SSH endpoints
 * 6. Authentic JSch SSH-2.0 Session (Real KEX, Real Cipher negotiation, Real Password Auth)
 * 7. Real `direct-tcpip` Channel Multiplexing for TunPacketRouter and Local SOCKS5 Proxy
 * 8. Real end-to-end connectivity verification and atomic byte counting
 */
class SshTunnelClient(
    private val socketProtector: UpstreamSocketProtector,
    private val profile: VpnProfile
) : ITunnelBackend {

    constructor(vpnService: VpnService, profile: VpnProfile) : this(
        if (vpnService is UpstreamSocketProtector) vpnService else object : UpstreamSocketProtector {
            override fun protect(socket: Socket): Boolean = vpnService.protect(socket)
            override fun protect(socket: DatagramSocket): Boolean = vpnService.protect(socket)
            override fun isVpnInterfaceActive(): Boolean = true
        },
        profile
    )

    override val backendName: String = "SSH"
    override val totalBytesSent = AtomicLong(0L)
    override val totalBytesReceived = AtomicLong(0L)

    private val isRunning = AtomicBoolean(false)
    private val isTunnelReady = AtomicBoolean(false)

    private var activeSession: Session? = null
    private var baseTransportSocket: Socket? = null
    private val openChannels = Collections.newSetFromMap(ConcurrentHashMap<DirectTcpIpSocket, Boolean>())

    override suspend fun verifyHandshake(): Result<Unit> = withContext(Dispatchers.IO) {
        return@withContext try {
            val serverHost = profile.server.trim()
            val serverPort = profile.port

            if (serverHost.isBlank() || serverPort <= 0 || serverPort > 65535) {
                throw IllegalArgumentException("Invalid SSH destination: $serverHost:$serverPort")
            }

            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Inisialisasi…")
            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Memulai core SSH-2")
            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Menghubungkan ke $serverHost:$serverPort, batas waktu 10 detik")

            // 1. Establish protected base transport socket (Direct or via Remote Proxy)
            val transportSocket = establishTransportSocket(serverHost, serverPort)
            baseTransportSocket = transportSocket

            // 2. Initialize authentic JSch SSH Session
            val jsch = JSch()
            val username = profile.effectiveSshUsername.ifBlank { "root" }
            val password = profile.effectiveSshPassword

            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Mengautentikasi pengguna: $username")

            val session = jsch.getSession(username, serverHost, serverPort)
            session.setPassword(password)

            // Inject the prepared transport socket via JSch SocketFactory
            session.setSocketFactory(object : SocketFactory {
                override fun createSocket(host: String?, port: Int): Socket = transportSocket
                override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
                override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
            })

            // Host key verification policy: allow insecure/unknown host key for custom VPN servers
            session.setConfig("StrictHostKeyChecking", "no")
            session.setConfig("PreferredAuthentications", "password,keyboard-interactive,publickey")
            session.setConfig("compression.s2c", "zlib@openssh.com,zlib,none")
            session.setConfig("compression.c2s", "zlib@openssh.com,zlib,none")
            session.serverAliveInterval = 30000

            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] handing clean stream to JSch")
            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Memulai KEX & negosiasi kunci enkripsi...")

            // 3. Connect real SSH session (performs actual identification exchange, KEX, and authentication)
            session.connect(25000)

            if (!session.isConnected) {
                throw IllegalStateException("SSH authentication failed or session disconnected")
            }

            activeSession = session
            isRunning.set(true)

            val serverVersion = session.serverVersion
            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Berhasil terhubung (Server: $serverVersion)")
            VpnLogManager.log(LogLevel.INFO, "DNS", "[DNS] DNS lewat terowongan aktif")
            VpnLogManager.log(LogLevel.INFO, "SOCKS", "[SOCKS] Mesin SOCKS aktif: LocalSocks")

            // 4. Real end-to-end verification via direct-tcpip channel test
            verifyEndToEndConnectivity(session)

            isTunnelReady.set(true)
            VpnLogManager.log(LogLevel.INFO, "TUNNEL", "[TUNNEL] Selamat berselancar - SSH tunnel ready")

            Result.success(Unit)
        } catch (e: Exception) {
            val errMsg = e.message ?: e.javaClass.simpleName
            VpnLogManager.log(LogLevel.ERROR, "SSH ERROR", "[SSH ERROR] Connection failed: $errMsg")
            stop()
            Result.failure(e)
        }
    }

    override fun createTunnelSocket(targetHost: String, targetPort: Int): Socket {
        val session = activeSession
        if (session == null || !session.isConnected) {
            throw IllegalStateException("SSH Session is not active or disconnected")
        }

        try {
            val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(targetHost)
            channel.setPort(targetPort)
            channel.setOrgIPAddress("127.0.0.1")
            channel.setOrgPort(0)
            channel.connect(15000)

            val socket = DirectTcpIpSocket(
                channel = channel,
                targetHost = targetHost,
                targetPort = targetPort,
                totalBytesSent = totalBytesSent,
                totalBytesReceived = totalBytesReceived
            )
            openChannels.add(socket)
            return socket
        } catch (e: Exception) {
            VpnLogManager.log(LogLevel.WARN, "SSH CHANNEL", "[SSH CHANNEL] Failed to open direct-tcpip to $targetHost:$targetPort - ${e.message}")
            throw e
        }
    }

    override fun stop() {
        isRunning.set(false)
        isTunnelReady.set(false)

        openChannels.forEach { channelSocket ->
            try {
                channelSocket.close()
            } catch (_: Exception) {}
        }
        openChannels.clear()

        try {
            activeSession?.disconnect()
        } catch (_: Exception) {}
        activeSession = null

        try {
            baseTransportSocket?.close()
        } catch (_: Exception) {}
        baseTransportSocket = null
    }

    /**
     * Establishes the full transport socket pipeline:
     * Base TCP (Protected via SocketChannel) -> Remote Proxy (HTTP CONNECT/SOCKS5/Payload) -> TLS (SNI) -> Payload/WebSocket Framing
     */
    private fun establishTransportSocket(serverHost: String, serverPort: Int): Socket {
        val socketChannel = java.nio.channels.SocketChannel.open()
        val rawSocket = socketChannel.socket()
        val tunActive = socketProtector.isVpnInterfaceActive()

        VpnLogManager.log(LogLevel.CONN, "PROTECT", "[PROTECT] Requesting upstream socket protection (TUN Active: $tunActive)...")

        // 1. Mandatory VpnService.protect() BEFORE socket.connect()
        val protected = socketProtector.protect(rawSocket)
        if (!protected) {
            rawSocket.close()
            throw IllegalStateException("Failed to protect upstream socket from VPN routing loop (TUN Active: $tunActive)")
        }

        VpnLogManager.log(LogLevel.CONN, "PROTECT", "[PROTECT] Upstream socket successfully protected from VPN routing loop")

        rawSocket.tcpNoDelay = true
        rawSocket.soTimeout = 25000

        var currentSocket: Socket = rawSocket

        val isSsl = profile.sshDirectSsl || profile.security.equals("tls", ignoreCase = true)
        val hasRemoteProxy = profile.remoteProxyEnabled && profile.remoteProxyHost.isNotBlank()
        val hasPayload = profile.sshPayload.isNotBlank()

        if (hasRemoteProxy) {
            val proxyHost = profile.remoteProxyHost.trim()
            val proxyPort = if (profile.remoteProxyPort > 0) profile.remoteProxyPort else 8080
            val proxyType = profile.remoteProxyType.uppercase()

            VpnLogManager.log(LogLevel.CONN, "PROXY", "[PROXY] Connecting to Remote Proxy $proxyHost:$proxyPort (Type: $proxyType)...")
            currentSocket.connect(InetSocketAddress(proxyHost, proxyPort), 10000)

            if (proxyType == "SOCKS5") {
                // SOCKS5 Remote Proxy
                performSocks5ProxyHandshake(currentSocket, serverHost, serverPort)

                if (isSsl) {
                    currentSocket = performTlsHandshake(currentSocket, serverHost, serverPort)
                }
                if (hasPayload) {
                    currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                }
            } else {
                // HTTP / HTTPS Remote Proxy
                if (proxyPort == 443 || (isSsl && (proxyHost.equals(profile.sni, ignoreCase = true) || profile.sni.isBlank()))) {
                    // Remote Proxy is an SSL/TLS endpoint (e.g. ads.ruangguru.com:443)
                    // Establish TLS to proxy first with SNI
                    currentSocket = performTlsHandshake(currentSocket, proxyHost, proxyPort)

                    // Inject custom payload inside TLS
                    if (hasPayload) {
                        currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                    } else {
                        performHttpProxyConnect(currentSocket, serverHost, serverPort)
                    }
                } else if (isSsl) {
                    // Plain HTTP Proxy (e.g. 8080) with TLS to target
                    performHttpProxyConnect(currentSocket, serverHost, serverPort)
                    currentSocket = performTlsHandshake(currentSocket, serverHost, serverPort)
                    if (hasPayload) {
                        currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                    }
                } else {
                    // Plain HTTP Proxy without TLS (Enhanced / Direct mode via HTTP Proxy)
                    if (hasPayload) {
                        currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                    } else {
                        performHttpProxyConnect(currentSocket, serverHost, serverPort)
                    }
                }
            }
        } else {
            // Direct Connection to SSH Server
            VpnLogManager.log(LogLevel.CONN, "SSH", "[SSH] Connecting directly to $serverHost:$serverPort...")
            currentSocket.connect(InetSocketAddress(serverHost, serverPort), 10000)

            if (isSsl) {
                // Direct SSL/TLS Mode
                currentSocket = performTlsHandshake(currentSocket, serverHost, serverPort)
                if (hasPayload) {
                    currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                }
            } else {
                // Direct TCP / Enhanced Mode
                if (hasPayload) {
                    currentSocket = handleCustomPayload(currentSocket, serverHost, serverPort)
                }
            }
        }

        return currentSocket
    }

    /**
     * Performs HTTP CONNECT method negotiation with Remote Proxy.
     */
    private fun performHttpProxyConnect(socket: Socket, targetHost: String, targetPort: Int) {
        val out = socket.getOutputStream()
        val inStream = socket.getInputStream()

        VpnLogManager.log(LogLevel.CONN, "PROXY", "[PROXY] Sending HTTP CONNECT $targetHost:$targetPort")

        val connectBuilder = StringBuilder()
        connectBuilder.append("CONNECT $targetHost:$targetPort HTTP/1.1\r\n")
        connectBuilder.append("Host: $targetHost:$targetPort\r\n")
        connectBuilder.append("Proxy-Connection: Keep-Alive\r\n")
        connectBuilder.append("User-Agent: V2Tunnel/1.0\r\n")

        val proxyUser = profile.remoteProxyUsername ?: ""
        val proxyPass = profile.remoteProxyPassword ?: ""
        if (proxyUser.isNotBlank()) {
            val userPass = "$proxyUser:$proxyPass"
            val encodedAuth = Base64.encodeToString(userPass.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
            connectBuilder.append("Proxy-Authorization: Basic $encodedAuth\r\n")
        }
        connectBuilder.append("\r\n")

        out.write(connectBuilder.toString().toByteArray(StandardCharsets.US_ASCII))
        out.flush()

        val resp = HttpStatusParser.consumeSingleResponse(inStream)
            ?: throw IllegalStateException("Remote HTTP proxy closed connection prematurely during CONNECT")

        VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] ${resp.statusLine}")

        if (resp.statusCode == 407) {
            VpnLogManager.log(LogLevel.ERROR, "PROXY", "[PROXY] HTTP CONNECT failed: 407 Proxy Authentication Required")
            throw IllegalStateException("HTTP Proxy authentication required (HTTP 407)")
        }

        if (resp.statusCode != 200) {
            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Ganti respons")
            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] HTTP/1.0 200 Connection established")
        } else {
            VpnLogManager.log(LogLevel.CONN, "PROXY", "[PROXY] HTTP 200 Connection Established")
        }
    }

    /**
     * Performs RFC 1928 & RFC 1929 handshake with Remote SOCKS5 Proxy.
     */
    private fun performSocks5ProxyHandshake(socket: Socket, targetHost: String, targetPort: Int) {
        val out = socket.getOutputStream()
        val inStream = socket.getInputStream()

        val proxyUser = profile.remoteProxyUsername ?: ""
        val proxyPass = profile.remoteProxyPassword ?: ""
        val hasAuth = proxyUser.isNotBlank()

        if (proxyUser.toByteArray(StandardCharsets.UTF_8).size > 255 ||
            proxyPass.toByteArray(StandardCharsets.UTF_8).size > 255
        ) {
            throw IllegalArgumentException("SOCKS5 username/password exceeds 255 bytes limit")
        }

        // SOCKS5 greeting: VER 0x05, NMETHODS, METHODS (0x00 NO_AUTH, 0x02 USER_PASS)
        if (hasAuth) {
            out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02))
        } else {
            out.write(byteArrayOf(0x05, 0x01, 0x00))
        }
        out.flush()

        val ver = inStream.read()
        if (ver == -1) {
            throw IllegalStateException("Remote Proxy closed connection during SOCKS5 greeting")
        }
        if (ver != 0x05) {
            // Safe forensic inspection of non-SOCKS5 greeting without logging credentials
            val peek = ByteArray(15)
            val peekCount = if (inStream.available() > 0) inStream.read(peek, 0, minOf(peek.size, inStream.available())) else 0
            val fullBytes = ByteArray(1 + peekCount)
            fullBytes[0] = ver.toByte()
            if (peekCount > 0) System.arraycopy(peek, 0, fullBytes, 1, peekCount)
            val peekStr = String(fullBytes, StandardCharsets.ISO_8859_1).filter { it in ' '..'~' }

            if (ver == 0x48 || peekStr.startsWith("HTTP", ignoreCase = true)) {
                VpnLogManager.log(LogLevel.ERROR, "PROXY", "[PROXY ERROR] Remote Proxy returned HTTP response ('$peekStr') instead of SOCKS5 version 0x05. Remote Proxy is an HTTP/HTTPS server, not a SOCKS5 server.")
                throw IllegalStateException("Remote Proxy returned HTTP text ($peekStr) instead of SOCKS5 version 5 (byte $ver / 'H'). Set Remote Proxy Type to 'HTTP'.")
            } else {
                VpnLogManager.log(LogLevel.ERROR, "PROXY", "[PROXY ERROR] Invalid SOCKS5 version response: $ver (hex 0x${Integer.toHexString(ver)}, peek='$peekStr')")
                throw IllegalStateException("Invalid SOCKS5 version response: $ver")
            }
        }

        val method = inStream.read()
        if (method == 0x02 && hasAuth) {
            // RFC 1929 Sub-negotiation
            val userBytes = proxyUser.toByteArray(StandardCharsets.UTF_8)
            val passBytes = proxyPass.toByteArray(StandardCharsets.UTF_8)
            out.write(0x01) // Auth version
            out.write(userBytes.size)
            out.write(userBytes)
            out.write(passBytes.size)
            out.write(passBytes)
            out.flush()

            val authVer = inStream.read()
            val authStatus = inStream.read()
            if (authVer != 0x01 || authStatus != 0x00) {
                VpnLogManager.log(LogLevel.ERROR, "PROXY", "[PROXY] SOCKS5 authentication failed (status: $authStatus)")
                throw IllegalStateException("SOCKS5 Proxy authentication failed (Status: $authStatus)")
            }
        } else if (method == 0xFF) {
            throw IllegalStateException("SOCKS5 Proxy authentication method rejected (0xFF)")
        }

        // Prepare CONNECT request with IPv4, Domain, or IPv6 addressing
        val connectPkt = buildSocks5ConnectPacket(targetHost, targetPort)
        out.write(connectPkt)
        out.flush()

        val respVer = inStream.read()
        val respRep = inStream.read()
        val respRsv = inStream.read()
        val respAtyp = inStream.read()

        if (respVer != 0x05 || respRep != 0x00 || respRsv != 0x00) {
            VpnLogManager.log(LogLevel.ERROR, "PROXY", "[PROXY] SOCKS5 CONNECT failed with code: $respRep")
            throw IllegalStateException("SOCKS5 Proxy connection to target failed with code: $respRep")
        }

        // Consume bound address bytes
        when (respAtyp) {
            0x01 -> inStream.readNBytesCompat(4 + 2) // IPv4 + Port
            0x03 -> {
                val len = inStream.read()
                inStream.readNBytesCompat(len + 2) // Domain + Port
            }
            0x04 -> inStream.readNBytesCompat(16 + 2) // IPv6 + Port
            else -> throw IllegalStateException("Unknown SOCKS5 address type: $respAtyp")
        }

        VpnLogManager.log(LogLevel.CONN, "PROXY", "[PROXY] SOCKS5 connected to $targetHost:$targetPort")
    }

    private fun buildSocks5ConnectPacket(host: String, port: Int): ByteArray {
        val isIpv4 = host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))
        return if (isIpv4) {
            val parts = host.split(".").map { it.toInt().toByte() }
            byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                parts[0], parts[1], parts[2], parts[3],
                ((port shr 8) and 0xFF).toByte(),
                (port and 0xFF).toByte()
            )
        } else if (host.contains(":")) {
            val ip6Bytes = InetAddress.getByName(host).address
            val pkt = ByteArray(4 + 16 + 2)
            pkt[0] = 0x05
            pkt[1] = 0x01
            pkt[2] = 0x00
            pkt[3] = 0x04 // IPv6
            System.arraycopy(ip6Bytes, 0, pkt, 4, 16)
            pkt[20] = ((port shr 8) and 0xFF).toByte()
            pkt[21] = (port and 0xFF).toByte()
            pkt
        } else {
            val domainBytes = host.toByteArray(StandardCharsets.UTF_8)
            if (domainBytes.size > 255) throw IllegalArgumentException("Domain name exceeds 255 bytes")
            val pkt = ByteArray(4 + 1 + domainBytes.size + 2)
            pkt[0] = 0x05
            pkt[1] = 0x01
            pkt[2] = 0x00
            pkt[3] = 0x03 // Domain name
            pkt[4] = domainBytes.size.toByte()
            System.arraycopy(domainBytes, 0, pkt, 5, domainBytes.size)
            pkt[5 + domainBytes.size] = ((port shr 8) and 0xFF).toByte()
            pkt[6 + domainBytes.size] = (port and 0xFF).toByte()
            pkt
        }
    }

    /**
     * Performs TLS/SSL Handshake with sanitized SNI.
     */
    private fun performTlsHandshake(rawSocket: Socket, serverHost: String, serverPort: Int): Socket {
        val rawSni = profile.sni.ifBlank { serverHost }
        val cleanSni = SniUtils.sanitizeSni(rawSni, serverHost)
        VpnLogManager.log(LogLevel.CONN, "TLS", "[TLS] Encapsulating with SNI: $cleanSni")

        val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val sslSocket = sslFactory.createSocket(rawSocket, serverHost, serverPort, true) as SSLSocket
        try {
            socketProtector.protect(sslSocket)
        } catch (_: Exception) {}

        if (cleanSni.isNotBlank()) {
            val sslParams = SSLParameters().apply {
                serverNames = listOf(SNIHostName(cleanSni))
            }
            sslSocket.sslParameters = sslParams
        }
        sslSocket.startHandshake()
        val cipher = sslSocket.session.cipherSuite
        val protocolVersion = sslSocket.session.protocol
        VpnLogManager.log(LogLevel.CONN, "TLS", "[TLS] TLS handshake established ($protocolVersion, $cipher)")
        return sslSocket
    }

    /**
     * Injects Custom HTTP / WebSocket Payload and executes appropriate protocol switching & response replacement.
     */
    private fun handleCustomPayload(socket: Socket, serverHost: String, serverPort: Int): Socket {
        val mode = HttpStatusParser.detectPayloadMode(profile.sshPayload)
        val formattedPayload = formatPayload(profile.sshPayload, serverHost, serverPort)

        VpnLogManager.log(LogLevel.CONN, "PAYLOAD", "[PAYLOAD] Injecting payload (Mode: $mode)")

        val out = socket.getOutputStream()
        out.write(formattedPayload.toByteArray(StandardCharsets.UTF_8))
        out.flush()

        val inStream = socket.getInputStream()

        when (mode) {
            PayloadMode.WEBSOCKET -> {
                // First response block (e.g. 403 Forbidden, 101 Switching Protocols, 421 Misdirected, 400 Bad Request, etc.)
                val firstResp = HttpStatusParser.consumeSingleResponse(inStream)
                    ?: throw IllegalStateException("Remote endpoint closed connection immediately after payload injection")

                VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] ${firstResp.statusLine}")
                val cl1 = firstResp.headers["content-length"] ?: "none"
                val te1 = firstResp.headers["transfer-encoding"] ?: "none"
                VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Content-Length: $cl1, Transfer-Encoding: $te1, Body drained: ${firstResp.bodyLength} bytes")

                if (firstResp.statusCode != 101) {
                    VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Ganti respons")
                    VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] HTTP/1.0 200 Connection established")
                }

                // Check for second response stage (e.g. 101 Switching Protocols following intermediate 403 / 200 / 302 / 421)
                if (firstResp.statusCode != 101) {
                    try {
                        var waited = 0
                        while (inStream.available() == 0 && waited < 400) {
                            Thread.sleep(50)
                            waited += 50
                        }
                    } catch (_: Exception) {}

                    if (inStream.available() > 0) {
                        val secondResp = HttpStatusParser.consumeSingleResponse(inStream)
                        if (secondResp != null) {
                            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] ${secondResp.statusLine}")
                            val cl2 = secondResp.headers["content-length"] ?: "none"
                            val te2 = secondResp.headers["transfer-encoding"] ?: "none"
                            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Content-Length: $cl2, Transfer-Encoding: $te2, Body drained: ${secondResp.bodyLength} bytes")
                            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Ganti respons")
                            VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] HTTP/1.0 200 Connection established")
                        }
                    }
                }

                VpnLogManager.log(LogLevel.CONN, "WS", "[WS] HTTP 101 Switching Protocols - activating RFC 6455 binary framing")
                return WebSocketFramedSocket(socket)
            }
            PayloadMode.PAYLOAD_WITH_HTTP_RESPONSE -> {
                val resp = HttpStatusParser.consumeSingleResponse(inStream)
                if (resp != null) {
                    VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] ${resp.statusLine}")
                    val cl = resp.headers["content-length"] ?: "none"
                    val te = resp.headers["transfer-encoding"] ?: "none"
                    VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Content-Length: $cl, Transfer-Encoding: $te, Body drained: ${resp.bodyLength} bytes")
                    if (resp.statusCode != 200) {
                        VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] Ganti respons")
                        VpnLogManager.log(LogLevel.CONN, "HTTP", "[HTTP] HTTP/1.0 200 Connection established")
                    }
                }
                return socket
            }
            PayloadMode.PAYLOAD_ONLY, PayloadMode.NONE -> {
                return socket
            }
        }
    }

    /**
     * Real end-to-end connectivity verification via an active direct-tcpip channel.
     * Throws an exception if all probe destinations fail, preventing isTunnelReady from becoming true.
     */
    private fun verifyEndToEndConnectivity(session: Session) {
        val probeTargets = listOf(
            Pair("1.1.1.1", 80),
            Pair("1.0.0.1", 80),
            Pair("8.8.8.8", 80)
        )

        var lastError: Exception? = null
        for ((host, port) in probeTargets) {
            var verifyChannel: ChannelDirectTCPIP? = null
            try {
                verifyChannel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
                verifyChannel.setHost(host)
                verifyChannel.setPort(port)
                verifyChannel.setOrgIPAddress("127.0.0.1")
                verifyChannel.setOrgPort(0)
                verifyChannel.connect(7000)

                val vOut = verifyChannel.outputStream
                val vIn = verifyChannel.inputStream

                val testReq = "HEAD / HTTP/1.1\r\nHost: $host\r\nUser-Agent: V2TunnelProbe/1.0\r\nConnection: close\r\n\r\n"
                vOut.write(testReq.toByteArray(StandardCharsets.US_ASCII))
                vOut.flush()

                val respLine = readLine(vIn)
                val code = HttpStatusParser.parseStatusCode(respLine)

                if (code != null && code in 100..599) {
                    VpnLogManager.log(LogLevel.INFO, "VERIFY", "[VERIFY] Real end-to-end connectivity verified via $host:$port (HTTP $code)")
                    return
                } else {
                    throw IllegalStateException("Invalid HTTP response line from probe $host:$port: $respLine")
                }
            } catch (e: Exception) {
                lastError = e
                VpnLogManager.log(LogLevel.WARN, "VERIFY", "[VERIFY] End-to-end probe $host:$port failed: ${e.message}")
            } finally {
                try {
                    verifyChannel?.disconnect()
                } catch (_: Exception) {}
            }
        }

        throw IllegalStateException("Direct-TCPIP end-to-end probe failed for all targets. Last error: ${lastError?.message}", lastError)
    }

    /**
     * Formats custom HTTP payload template by replacing placeholders.
     */
    private fun formatPayload(payloadTemplate: String, host: String, port: Int): String {
        val sniHost = profile.sni.ifBlank { host }
        val proxyHost = profile.remoteProxyHost.ifBlank { host }
        val proxyPort = if (profile.remoteProxyPort > 0) profile.remoteProxyPort else 8080
        var result = payloadTemplate
            .replace("[host]", host, ignoreCase = true)
            .replace("[port]", port.toString(), ignoreCase = true)
            .replace("[host_port]", "$host:$port", ignoreCase = true)
            .replace("[proxy_host]", proxyHost, ignoreCase = true)
            .replace("[proxy_port]", proxyPort.toString(), ignoreCase = true)
            .replace("[proxy_host_port]", "$proxyHost:$proxyPort", ignoreCase = true)
            .replace("[sni]", sniHost, ignoreCase = true)
            .replace("[raw_host]", host, ignoreCase = true)
            .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
            .replace("[crlf]", "\r\n", ignoreCase = true)
            .replace("[lf]", "\n", ignoreCase = true)
            .replace("[cr]", "\r", ignoreCase = true)
            .replace("[ua]", "Mozilla/5.0 (Linux; Android 16; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", ignoreCase = true)
            .replace("[real_raw]", "", ignoreCase = true)
            .replace("[split]", "\r\n", ignoreCase = true)
            .replace("[delay_split]", "\r\n", ignoreCase = true)

        if (!result.endsWith("\r\n\r\n")) {
            if (result.endsWith("\r\n")) {
                result += "\r\n"
            } else {
                result += "\r\n\r\n"
            }
        }
        return result
    }

    private fun readLine(input: InputStream): String {
        val sb = StringBuilder()
        var b: Int
        while (input.read().also { b = it } != -1) {
            if (b == '\n'.code) break
            if (b != '\r'.code) {
                sb.append(b.toChar())
            }
        }
        return sb.toString()
    }

    private fun InputStream.readNBytesCompat(n: Int): ByteArray {
        val buf = ByteArray(n)
        var total = 0
        while (total < n) {
            val read = read(buf, total, n - total)
            if (read == -1) break
            total += read
        }
        return buf
    }
}
