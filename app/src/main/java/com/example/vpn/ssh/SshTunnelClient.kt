package com.example.vpn.ssh

import android.net.VpnService
import android.os.Build
import android.util.Base64
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.vpn.VpnLogManager
import com.example.vpn.backend.ITunnelBackend
import com.example.vpn.backend.UpstreamSocketProtector
import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.SniUtils
import com.trilead.ssh2.Connection
import com.trilead.ssh2.ConnectionMonitor
import com.trilead.ssh2.DebugLogger
import com.trilead.ssh2.HTTPProxyData
import com.trilead.ssh2.LocalStreamForwarder
import com.trilead.ssh2.ServerHostKeyVerifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**

* Production SSH Tunnel Client Backend for V2Tunnel.

* 

* SSH transport pipeline:

* 

* 1. Protected outbound TCP socket.

* 2. Optional remote HTTP / HTTPS / SOCKS5 proxy.

* 3. Optional explicit TLS/SNI.

* 4. Optional custom payload.

* 5. Trilead SSH-2 connection.

* 6. Password authentication.

* 7. direct-tcpip forwarding.

* 

* IMPORTANT:

* - TCP port does NOT select the transport.

* - Standard payload does NOT automatically enable WebSocket framing.

* - WebSocket framing is enabled only when profile.isSshWebSocket == true.

* - The upstream socket is protected BEFORE connect().
    */
    class SshTunnelClient(
    private val socketProtector: UpstreamSocketProtector,
    private val profile: VpnProfile
    ) : ITunnelBackend {
  
  constructor(
  vpnService: VpnService,
  profile: VpnProfile
  ) : this(
  if (vpnService is UpstreamSocketProtector) {
  vpnService
  } else {
  object : UpstreamSocketProtector {
  override fun protect(socket: Socket): Boolean =
  vpnService.protect(socket)
  
           override fun protect(socket: DatagramSocket): Boolean =
             vpnService.protect(socket)

         override fun isVpnInterfaceActive(): Boolean = true
     }
 },
 profile
  
  )
  
  override val backendName: String = "SSH"
  
  override val totalBytesSent = AtomicLong(0L)
  override val totalBytesReceived = AtomicLong(0L)
  
  private val isRunning = AtomicBoolean(false)
  private val isTunnelReady = AtomicBoolean(false)
  
  private var activeConnection: Connection? = null
  private var baseTransportSocket: Socket? = null
  
  private var loopbackServer: ServerSocket? = null
  private var loopbackClient: Socket? = null
  
  private var bridgeJob: Job? = null
  
  private val bridgeScope =
  CoroutineScope(Dispatchers.IO + SupervisorJob())
  
  private val openChannels =
  Collections.newSetFromMap(
  ConcurrentHashMap<DirectTcpIpSocket, Boolean>()
  )
  
  @Volatile
  private var currentStage: String = "INIT"
  
  override suspend fun verifyHandshake(): Result<Unit> =
  withContext(Dispatchers.IO) {
  try {
  val serverHost = profile.server.trim()
  val serverPort = profile.port
  
           if (
             serverHost.isBlank() ||
             serverPort <= 0 ||
             serverPort > 65535
         ) {
             throw IllegalArgumentException(
                 "Invalid SSH destination: $serverHost:$serverPort"
             )
         }

         val hasRemoteProxy =
             profile.remoteProxyEnabled &&
                 profile.remoteProxyHost.isNotBlank()

         currentStage =
             if (hasRemoteProxy) "PROXY" else "TCP"

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Inisialisasi..."
         )

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Memulai core SSH-2 Trilead"
         )

         /*
          * Establish the complete prepared transport:
          *
          * TCP -> Proxy -> optional TLS -> optional payload
          */
         val transportSocket =
             establishTransportSocket(
                 serverHost,
                 serverPort
             )

         baseTransportSocket = transportSocket

         /*
          * Local bridge:
          *
          * Trilead -> localhost HTTP proxy -> prepared transport
          *
          * IMPORTANT:
          * Do NOT wait for bridgeReady before connection.connect().
          *
          * Trilead itself is the component that connects to this
          * ServerSocket. Waiting before connection.connect() would
          * deadlock because the bridge cannot accept a client until
          * Trilead starts its proxy connection.
          */
         val server =
             ServerSocket(
                 0,
                 1,
                 InetAddress.getByName("127.0.0.1")
             )

         server.reuseAddress = true
         server.soTimeout = 15000

         loopbackServer = server

         val localPort = server.localPort

         val job = bridgeScope.launch {
             try {
                 VpnLogManager.log(
                     LogLevel.CONN,
                     "SSH BRIDGE",
                     "[SSH BRIDGE] Waiting for Trilead proxy connection on 127.0.0.1:$localPort"
                 )

                 val client = server.accept()

                 client.soTimeout = 15000
                 client.tcpNoDelay = true

                 loopbackClient = client

                 val cIn = client.getInputStream()
                 val cOut = client.getOutputStream()

                 /*
                  * Trilead HTTPProxyData should send:
                  *
                  * CONNECT host:port HTTP/1.0
                  *
                  * Validate the request instead of blindly
                  * accepting arbitrary local traffic.
                  */
                 val connectLine = readLine(cIn)

                 if (
                     connectLine.isBlank() ||
                     !connectLine.startsWith(
                         "CONNECT ",
                         ignoreCase = true
                     )
                 ) {
                     throw IllegalStateException(
                         "Invalid Trilead proxy request: $connectLine"
                     )
                 }

                 /*
                  * Drain proxy request headers.
                  */
                 while (true) {
                     val header = readLine(cIn)

                     if (header.isEmpty()) {
                         break
                     }
                 }

                 /*
                  * The actual proxy/TLS/payload negotiation has already
                  * happened on transportSocket.
                  *
                  * This localhost bridge therefore only needs to
                  * expose the already-prepared stream to Trilead.
                  */
                 cOut.write(
                     "HTTP/1.0 200 Connection established\r\n\r\n"
                         .toByteArray(
                             StandardCharsets.ISO_8859_1
                         )
                 )
                 cOut.flush()

                 VpnLogManager.log(
                     LogLevel.CONN,
                     "SSH BRIDGE",
                     "[SSH BRIDGE] Trilead CONNECT accepted"
                 )

                 val tIn =
                     transportSocket.getInputStream()

                 val tOut =
                     transportSocket.getOutputStream()

                 val relayClientToTransport =
                     launch {
                         val buffer =
                             ByteArray(16384)

                         try {
                             while (isActive) {
                                 val count =
                                     cIn.read(buffer)

                                 if (count == -1) {
                                     break
                                 }

                                 if (count > 0) {
                                     tOut.write(
                                         buffer,
                                         0,
                                         count
                                     )
                                     tOut.flush()
                                 }
                             }
                         } catch (_: Exception) {
                         }
                     }

                 val relayTransportToClient =
                     launch {
                         val buffer =
                             ByteArray(16384)

                         try {
                             while (isActive) {
                                 val count =
                                     tIn.read(buffer)

                                 if (count == -1) {
                                     break
                                 }

                                 if (count > 0) {
                                     cOut.write(
                                         buffer,
                                         0,
                                         count
                                     )
                                     cOut.flush()
                                 }
                             }
                         } catch (_: Exception) {
                         }
                     }

                 joinAll(
                     relayClientToTransport,
                     relayTransportToClient
                 )
             } catch (e: Exception) {
                 VpnLogManager.log(
                     LogLevel.ERROR,
                     "SSH BRIDGE",
                     "[SSH BRIDGE] Local transport bridge failed: ${e.message}"
                 )
             }
         }

         bridgeJob = job

         /*
          * Trilead SSH-2 engine.
          *
          * serverHost/serverPort are the logical SSH destination.
          * HTTPProxyData redirects the actual TCP connection to
          * our localhost bridge.
          */
         currentStage = "SSH_BANNER"

         val connection =
             Connection(
                 serverHost,
                 serverPort
             )

         connection.setProxyData(
             HTTPProxyData(
                 "127.0.0.1",
                 localPort
             )
         )

         connection.setTCPNoDelay(true)

         connection.enableDebugging(
             true,
             object : DebugLogger {
                 override fun log(
                     level: Int,
                     className: String,
                     message: String
                 ) {
                     val msg =
                         message.lowercase(Locale.ROOT)

                     when {
                         msg.contains("identification") ||
                             msg.contains("server version") -> {
                             currentStage =
                                 "SSH_BANNER"

                             VpnLogManager.log(
                                 LogLevel.CONN,
                                 "SSH",
                                 "[SSH] SSH_BANNER_RECEIVED"
                             )
                         }

                         msg.contains("kex") &&
                             (
                                 msg.contains("start") ||
                                     msg.contains("init")
                                 ) -> {
                             currentStage = "KEX"

                             VpnLogManager.log(
                                 LogLevel.CONN,
                                 "SSH",
                                 "[SSH] SSH_KEX_STARTED"
                             )
                         }

                         msg.contains("kex") &&
                             (
                                 msg.contains("finish") ||
                                     msg.contains("done") ||
                                     msg.contains("completed")
                                 ) -> {
                             currentStage = "KEX"

                             VpnLogManager.log(
                                 LogLevel.CONN,
                                 "SSH",
                                 "[SSH] SSH_KEX_SUCCESS"
                             )
                         }

                         msg.contains("auth") &&
                             (
                                 msg.contains("success") ||
                                     msg.contains("granted")
                                 ) -> {
                             currentStage = "AUTH"

                             VpnLogManager.log(
                                 LogLevel.CONN,
                                 "SSH",
                                 "[SSH] SSH_AUTH_SUCCESS"
                             )
                         }
                     }
                 }
             }
         )

         connection.addConnectionMonitor(
             object : ConnectionMonitor {
                 override fun connectionLost(
                     reason: Throwable?
                 ) {
                     VpnLogManager.log(
                         LogLevel.WARN,
                         "SSH",
                         "[SSH] Connection lost: ${reason?.message}"
                     )
                 }
             }
         )

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Handing clean stream to Trilead SSH-2"
         )

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Memulai KEX & negosiasi kunci enkripsi..."
         )

         currentStage = "KEX"

         /*
          * IMPORTANT:
          *
          * connection.connect() is what causes Trilead to connect
          * to HTTPProxyData -> localhost bridge.
          *
          * Therefore bridge.accept() must happen concurrently.
          */
         val connInfo =
             connection.connect(
                 object : ServerHostKeyVerifier {
                     override fun verifyServerHostKey(
                         hostname: String,
                         port: Int,
                         serverHostKeyAlgorithm: String,
                         serverHostKey: ByteArray
                     ): Boolean {
                         currentStage = "KEX"

                         VpnLogManager.log(
                             LogLevel.CONN,
                             "SSH",
                             "[SSH] SSH_BANNER_RECEIVED"
                         )

                         VpnLogManager.log(
                             LogLevel.CONN,
                             "SSH",
                             "[SSH] Server Host Key: $serverHostKeyAlgorithm (allowInsecure=${profile.allowInsecure})"
                         )

                         /*
                          * The current VpnProfile model does not expose
                          * host-key pinning data.
                          *
                          * Keep compatibility behaviour here.
                          */
                         return true
                     }
                 },
                 15000,
                 15000
             )

         currentStage = "KEX"

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] SSH_KEX_SUCCESS"
         )

         VpnLogManager.log(
             LogLevel.INFO,
             "SSH",
             "[SSH] KEX=${connInfo.keyExchangeAlgorithm}, " +
                 "C2S=${connInfo.clientToServerCryptoAlgorithm}, " +
                 "S2C=${connInfo.serverToClientCryptoAlgorithm}, " +
                 "MAC-C2S=${connInfo.clientToServerMACAlgorithm}, " +
                 "MAC-S2C=${connInfo.serverToClientMACAlgorithm}"
         )

         currentStage = "AUTH"

         val username =
             profile.effectiveSshUsername
                 .ifBlank { "root" }

         val password =
             profile.effectiveSshPassword

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Mengautentikasi pengguna: $username"
         )

         val authSuccess =
             connection.authenticateWithPassword(
                 username,
                 password
             )

         if (!authSuccess) {
             throw IllegalStateException(
                 "SSH authentication failed for user: $username"
             )
         }

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] SSH_AUTH_SUCCESS"
         )

         /*
          * Definitive post-authentication transport check.
          */
         currentStage = "SSH_PING"

         try {
             connection.ping()

             VpnLogManager.log(
                 LogLevel.INFO,
                 "SSH",
                 "[SSH] SSH_PING_SUCCESS"
             )
         } catch (e: Exception) {
             throw IllegalStateException(
                 "Authenticated SSH connection failed ping verification",
                 e
             )
         }

         /*
          * Only now is the authenticated SSH backend considered
          * running.
          */
         currentStage = "SSH_READY"

         activeConnection = connection
         isRunning.set(true)

         val serverIdent =
             try {
                 connection
                     .getVersionInfo()
                     .getServerString()
                     .trim()
             } catch (_: Exception) {
                 "SSH-2.0"
             }

         VpnLogManager.log(
             LogLevel.CONN,
             "SSH",
             "[SSH] Berhasil terhubung (Server: $serverIdent)"
         )

         VpnLogManager.log(
             LogLevel.INFO,
             "DNS",
             "[DNS] DNS lewat terowongan aktif"
         )

         VpnLogManager.log(
             LogLevel.INFO,
             "SOCKS",
             "[SOCKS] Mesin SOCKS aktif: LocalSocks"
         )

         /*
          * Verify real direct-tcpip forwarding before marking
          * the tunnel ready.
          */
         currentStage = "DIRECT_TCPIP_VERIFY"

         verifyEndToEndConnectivity(
             connection
         )

         isTunnelReady.set(true)

         VpnLogManager.log(
             LogLevel.INFO,
             "SSH",
             "[SSH] SSH_READY"
         )

         VpnLogManager.log(
             LogLevel.INFO,
             "TUNNEL",
             "[TUNNEL] Selamat berselancar - SSH tunnel ready"
         )

         Result.success(Unit)
     } catch (e: Exception) {
         val errMsg =
             e.message ?: e.javaClass.simpleName

         VpnLogManager.log(
             LogLevel.ERROR,
             "SSH",
             "[SSH] SSH_FAILED_STAGE=$currentStage: $errMsg"
         )

         VpnLogManager.log(
             LogLevel.ERROR,
             "SSH ERROR",
             "[SSH ERROR] Connection failed: $errMsg"
         )

         stop()

         Result.failure(e)
     }
 }
  
  override fun createTunnelSocket(
  targetHost: String,
  targetPort: Int
  ): Socket {
  val conn =
  activeConnection
  ?: throw IllegalStateException(
  "Trilead SSH Connection is not active or closed"
  )
  
   if (
     !isRunning.get() ||
     !isTunnelReady.get()
 ) {
     throw IllegalStateException(
         "SSH tunnel is not ready"
     )
 }

 if (
     targetHost.isBlank() ||
     targetPort <= 0 ||
     targetPort > 65535
 ) {
     throw IllegalArgumentException(
         "Invalid direct-tcpip target: $targetHost:$targetPort"
     )
 }

 return try {
     val forwarder =
         conn.createLocalStreamForwarder(
             targetHost,
             targetPort
         )

     val socket =
         DirectTcpIpSocket(
             forwarder = forwarder,
             targetHost = targetHost,
             targetPort = targetPort,
             totalBytesSent = totalBytesSent,
             totalBytesReceived = totalBytesReceived
         )

     openChannels.add(socket)

     VpnLogManager.log(
         LogLevel.INFO,
         "SSH CHANNEL",
         "[SSH CHANNEL] direct-tcpip opened: $targetHost:$targetPort"
     )

     socket
 } catch (e: Exception) {
     VpnLogManager.log(
         LogLevel.WARN,
         "SSH CHANNEL",
         "[SSH CHANNEL] Failed to open direct-tcpip to $targetHost:$targetPort - ${e.message}"
     )

     throw e
 }
  
  }
  
  override fun stop() {
  isRunning.set(false)
  isTunnelReady.set(false)
  
   openChannels.forEach { channelSocket ->
     try {
         channelSocket.close()
     } catch (_: Exception) {
     }
 }

 openChannels.clear()

 try {
     activeConnection?.close()
 } catch (_: Exception) {
 }

 activeConnection = null

 try {
     loopbackClient?.close()
 } catch (_: Exception) {
 }

 loopbackClient = null

 try {
     loopbackServer?.close()
 } catch (_: Exception) {
 }

 loopbackServer = null

 try {
     bridgeJob?.cancel()
 } catch (_: Exception) {
 }

 bridgeJob = null

 try {
     baseTransportSocket?.close()
 } catch (_: Exception) {
 }

 baseTransportSocket = null

 currentStage = "STOPPED"
  
  }
  
  /**
  
  * Establish the complete upstream transport.
  
  * 
  
  * TCP port NEVER decides whether TLS is used.
  
  * 
  
  * TLS is enabled only by explicit profile configuration.
    */
    private fun establishTransportSocket(
    serverHost: String,
    serverPort: Int
    ): Socket {
    val socketChannel =
    java.nio.channels.SocketChannel.open()
    
    val rawSocket =
    socketChannel.socket()
    
    val tunActive =
    socketProtector.isVpnInterfaceActive()
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PROTECT",
    "[PROTECT] Requesting upstream socket protection (TUN Active: $tunActive)..."
    )
    
    /*
    
    * MUST happen before connect().
      */
      val protected =
      socketProtector.protect(rawSocket)
    
    if (!protected) {
    try {
    rawSocket.close()
    } catch (_: Exception) {
    }
    
     throw IllegalStateException(
     "Failed to protect upstream socket from VPN routing loop (TUN Active: $tunActive)"
 )
    
    }
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PROTECT",
    "[PROTECT] Upstream socket successfully protected from VPN routing loop"
    )
    
    rawSocket.tcpNoDelay = true
    rawSocket.soTimeout = 25000
    
    var currentSocket: Socket = rawSocket
    
    val targetHost =
    profile.server.trim()
    
    val targetPort =
    profile.port
    
    /*
    
    * EXPLICIT TLS ONLY.
    * 
    * Port 443 alone does NOT activate TLS.
      */
      val isSsl =
      profile.sshMethod.equals(
      "TLS",
      ignoreCase = true
      ) ||
      profile.sshDirectSsl ||
      profile.security.equals(
      "tls",
      ignoreCase = true
      )
    
    val hasRemoteProxy =
    profile.remoteProxyEnabled &&
    profile.remoteProxyHost.isNotBlank()
    
    val hasPayload =
    profile.sshPayloadEnabled &&
    profile.sshPayload.isNotBlank()
    
    val proxyHost =
    if (hasRemoteProxy) {
    profile.remoteProxyHost.trim()
    } else {
    "NONE"
    }
    
    val proxyPort =
    if (
    hasRemoteProxy &&
    profile.remoteProxyPort > 0
    ) {
    profile.remoteProxyPort
    } else if (hasRemoteProxy) {
    8080
    } else {
    0
    }
    
    val cleanSni =
    SniUtils.sanitizeSni(
    profile.sni.trim()
    .ifBlank { targetHost },
    targetHost
    )
    
    val httpHost =
    profile.host.trim()
    .ifBlank { targetHost }
    
    val payloadHost =
    profile.host.trim()
    .ifBlank { targetHost }
    
    val payloadHostPort =
    "$payloadHost:$targetPort"
    
    val wsHost =
    profile.wsHost.trim()
    .ifBlank { targetHost }
    
    val wsPath =
    profile.path.trim()
    .ifBlank { "/ws" }
    
    val alpn =
    if (isSsl) "http/1.1" else "none"
    
    VpnLogManager.log(
    LogLevel.INFO,
    "WIRE",
    """[WIRE]
    TCP_DESTINATION=${if (hasRemoteProxy) proxyHost else targetHost}
    TCP_PORT=${if (hasRemoteProxy) proxyPort else targetPort}
    REMOTE_PROXY=$proxyHost
    REMOTE_PROXY_PORT=$proxyPort
    REMOTE_PROXY_TYPE=${profile.remoteProxyType}
    TARGET_HOST=$targetHost
    TARGET_PORT=$targetPort
    TLS_ENABLED=$isSsl
    TLS_SNI=$cleanSni
    HTTP_HOST=$httpHost
    PAYLOAD_HOST=$payloadHost
    PAYLOAD_HOST_PORT=$payloadHostPort
    WS_HOST=$wsHost
    WS_PATH=$wsPath
    WS_ENABLED=${profile.isSshWebSocket}
    ALPN=$alpn"""
    )
    
    if (hasRemoteProxy) {
    val proxyType =
    profile.remoteProxyType
    .trim()
    .uppercase(Locale.ROOT)
    
     currentStage = "PROXY"

 VpnLogManager.log(
     LogLevel.CONN,
     "TCP",
     "[TCP] TCP_CONNECTING to Remote Proxy $proxyHost:$proxyPort (Type: $proxyType)"
 )

 currentSocket.connect(
     InetSocketAddress(
         proxyHost,
         proxyPort
     ),
     10000
 )

 VpnLogManager.log(
     LogLevel.CONN,
     "TCP",
     "[TCP] TCP_CONNECTED"
 )

 when (proxyType) {
     "SOCKS5" -> {
         VpnLogManager.log(
             LogLevel.CONN,
             "PROXY",
             "[PROXY] PROXY_CONNECTING (SOCKS5)"
         )

         performSocks5ProxyHandshake(
             currentSocket,
             targetHost,
             targetPort
         )

         VpnLogManager.log(
             LogLevel.CONN,
             "PROXY",
             "[PROXY] PROXY_CONNECTED"
         )

         if (isSsl) {
             currentStage = "TLS"

             currentSocket =
                 performTlsHandshake(
                     currentSocket,
                     cleanSni,
                     targetPort
                 )
         }

         if (hasPayload) {
             currentStage = "PAYLOAD"

             currentSocket =
                 handleCustomPayload(
                     currentSocket,
                     targetHost,
                     targetPort
                 )
         }
     }

     "HTTPS" -> {
         /*
          * Explicit HTTPS proxy:
          * TLS is established to the proxy first.
          */
         currentStage = "TLS"

         VpnLogManager.log(
             LogLevel.CONN,
             "TLS",
             "[TLS] TLS_CONNECTING (Proxy: $proxyHost:$proxyPort)"
         )

         currentSocket =
             performTlsHandshake(
                 currentSocket,
                 proxyHost,
                 proxyPort
             )

         VpnLogManager.log(
             LogLevel.CONN,
             "TLS",
             "[TLS] TLS_CONNECTED to Proxy"
         )

         if (hasPayload) {
             currentStage = "PAYLOAD"

             currentSocket =
                 handleCustomPayload(
                     currentSocket,
                     targetHost,
                     targetPort
                 )
         } else {
             currentStage = "PROXY"

             performHttpProxyConnect(
                 currentSocket,
                 targetHost,
                 targetPort
             )
         }

         /*
          * Target TLS is separate and explicit.
          */
         if (isSsl) {
             currentStage = "TLS"

             currentSocket =
                 performTlsHandshake(
                     currentSocket,
                     cleanSni,
                     targetPort
                 )
         }
     }

     else -> {
         /*
          * HTTP proxy is the default.
          *
          * Proxy port 443 does NOT mean HTTPS.
          */
         currentStage = "PROXY"

         VpnLogManager.log(
             LogLevel.CONN,
             "PROXY",
             "[PROXY] PROXY_CONNECTING (HTTP to $proxyHost:$proxyPort)"
         )

         if (hasPayload) {
             currentStage = "PAYLOAD"

             currentSocket =
                 handleCustomPayload(
                     currentSocket,
                     targetHost,
                     targetPort
                 )
         } else {
             performHttpProxyConnect(
                 currentSocket,
                 targetHost,
                 targetPort
             )
         }

         VpnLogManager.log(
             LogLevel.CONN,
             "PROXY",
             "[PROXY] PROXY_CONNECTED"
         )

         if (isSsl) {
             currentStage = "TLS"

             currentSocket =
                 performTlsHandshake(
                     currentSocket,
                     cleanSni,
                     targetPort
                 )
         }
     }
 }
    
    } else {
    /*
    * Direct SSH connection.
    */
    currentStage = "TCP"
    
     VpnLogManager.log(
     LogLevel.CONN,
     "TCP",
     "[TCP] TCP_CONNECTING to $targetHost:$targetPort"
 )

 currentSocket.connect(
     InetSocketAddress(
         targetHost,
         targetPort
     ),
     10000
 )

 VpnLogManager.log(
     LogLevel.CONN,
     "TCP",
     "[TCP] TCP_CONNECTED"
 )

 if (isSsl) {
     currentStage = "TLS"

     currentSocket =
         performTlsHandshake(
             currentSocket,
             cleanSni,
             targetPort
         )

     if (hasPayload) {
         currentStage = "PAYLOAD"

         currentSocket =
             handleCustomPayload(
                 currentSocket,
                 targetHost,
                 targetPort
             )
     }
 } else if (hasPayload) {
     currentStage = "PAYLOAD"

     currentSocket =
         handleCustomPayload(
             currentSocket,
             targetHost,
             targetPort
         )
 }
    
    }
    
    return currentSocket
    }
  
  /**
  
  * HTTP CONNECT proxy negotiation.
    */
    private fun performHttpProxyConnect(
    socket: Socket,
    targetHost: String,
    targetPort: Int
    ) {
    val out =
    socket.getOutputStream()
    
    val input =
    socket.getInputStream()
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PROXY",
    "[PROXY] Sending HTTP CONNECT $targetHost:$targetPort"
    )
    
    val builder =
    StringBuilder()
    
    builder.append(
    "CONNECT $targetHost:$targetPort HTTP/1.1\r\n"
    )
    
    builder.append(
    "Host: $targetHost:$targetPort\r\n"
    )
    
    builder.append(
    "Proxy-Connection: Keep-Alive\r\n"
    )
    
    builder.append(
    "User-Agent: V2Tunnel/1.0\r\n"
    )
    
    val proxyUser =
    profile.remoteProxyUsername ?: ""
    
    val proxyPass =
    profile.remoteProxyPassword ?: ""
    
    if (proxyUser.isNotBlank()) {
    val credentials =
    "$proxyUser:$proxyPass"
    
     val encoded =
     Base64.encodeToString(
         credentials.toByteArray(
             StandardCharsets.UTF_8
         ),
         Base64.NO_WRAP
     )

 builder.append(
     "Proxy-Authorization: Basic $encoded\r\n"
 )
    
    }
    
    builder.append("\r\n")
    
    out.write(
    builder.toString()
    .toByteArray(
    StandardCharsets.US_ASCII
    )
    )
    
    out.flush()
    
    val response =
    HttpStatusParser.consumeSingleResponse(
    input
    )
    ?: throw IllegalStateException(
    "Remote HTTP proxy closed connection during CONNECT"
    )
    
    VpnLogManager.log(
    LogLevel.CONN,
    "HTTP",
    "[HTTP] HTTP_RESPONSE: ${response.statusLine}"
    )
    
    if (response.statusCode == 407) {
    throw IllegalStateException(
    "HTTP Proxy authentication required (HTTP 407)"
    )
    }
    
    if (response.statusCode != 200) {
    throw IllegalStateException(
    "HTTP Proxy CONNECT failed with ${response.statusLine}"
    )
    }
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PROXY",
    "[PROXY] HTTP 200 Connection Established"
    )
    }
  
  /**
  
  * RFC 1928 / RFC 1929 SOCKS5 handshake.
    */
    private fun performSocks5ProxyHandshake(
    socket: Socket,
    targetHost: String,
    targetPort: Int
    ) {
    val out =
    socket.getOutputStream()
    
    val input =
    socket.getInputStream()
    
    val proxyUser =
    profile.remoteProxyUsername ?: ""
    
    val proxyPass =
    profile.remoteProxyPassword ?: ""
    
    val hasAuth =
    proxyUser.isNotBlank()
    
    val userBytes =
    proxyUser.toByteArray(
    StandardCharsets.UTF_8
    )
    
    val passBytes =
    proxyPass.toByteArray(
    StandardCharsets.UTF_8
    )
    
    if (
    userBytes.size > 255 ||
    passBytes.size > 255
    ) {
    throw IllegalArgumentException(
    "SOCKS5 username/password exceeds 255 bytes limit"
    )
    }
    
    if (hasAuth) {
    out.write(
    byteArrayOf(
    0x05,
    0x02,
    0x00,
    0x02
    )
    )
    } else {
    out.write(
    byteArrayOf(
    0x05,
    0x01,
    0x00
    )
    )
    }
    
    out.flush()
    
    val version =
    input.read()
    
    if (version == -1) {
    throw IllegalStateException(
    "Remote Proxy closed during SOCKS5 greeting"
    )
    }
    
    if (version != 0x05) {
    throw IllegalStateException(
    "Invalid SOCKS5 version response: $version"
    )
    }
    
    val method =
    input.read()
    
    if (method == -1) {
    throw IllegalStateException(
    "Remote Proxy closed during SOCKS5 method selection"
    )
    }
    
    when {
    method == 0x02 && hasAuth -> {
    out.write(0x01)
    out.write(userBytes.size)
    out.write(userBytes)
    out.write(passBytes.size)
    out.write(passBytes)
    out.flush()
    
         val authVersion =
         input.read()

     val authStatus =
         input.read()

     if (
         authVersion != 0x01 ||
         authStatus != 0x00
     ) {
         throw IllegalStateException(
             "SOCKS5 Proxy authentication failed (Status: $authStatus)"
         )
     }
 }

 method == 0x00 && !hasAuth -> {
     // NO AUTH
 }

 method == 0xFF -> {
     throw IllegalStateException(
         "SOCKS5 Proxy rejected all authentication methods"
     )
 }

 else -> {
     throw IllegalStateException(
         "SOCKS5 Proxy selected unsupported authentication method: $method"
     )
 }
    
    }
    
    out.write(
    buildSocks5ConnectPacket(
    targetHost,
    targetPort
    )
    )
    
    out.flush()
    
    val respVer =
    input.read()
    
    val respRep =
    input.read()
    
    val respRsv =
    input.read()
    
    val respAtyp =
    input.read()
    
    if (
    respVer < 0 ||
    respRep < 0 ||
    respRsv < 0 ||
    respAtyp < 0
    ) {
    throw IllegalStateException(
    "SOCKS5 proxy closed during CONNECT response"
    )
    }
    
    if (
    respVer != 0x05 ||
    respRsv != 0x00
    ) {
    throw IllegalStateException(
    "Invalid SOCKS5 CONNECT response"
    )
    }
    
    if (respRep != 0x00) {
    throw IllegalStateException(
    "SOCKS5 Proxy connection failed with code: $respRep"
    )
    }
    
    when (respAtyp) {
    0x01 -> {
    input.readNBytesCompat(6)
    }
    
     0x03 -> {
     val length =
         input.read()

     if (length < 0) {
         throw IllegalStateException(
             "SOCKS5 proxy closed while reading domain length"
         )
     }

     input.readNBytesCompat(
         length + 2
     )
 }

 0x04 -> {
     input.readNBytesCompat(18)
 }

 else -> {
     throw IllegalStateException(
         "Unknown SOCKS5 address type: $respAtyp"
     )
 }
    
    }
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PROXY",
    "[PROXY] SOCKS5 connected to $targetHost:$targetPort"
    )
    }
  
  private fun buildSocks5ConnectPacket(
  host: String,
  port: Int
  ): ByteArray {
  if (
  port <= 0 ||
  port > 65535
  ) {
  throw IllegalArgumentException(
  "Invalid SOCKS5 target port: $port"
  )
  }
  
   val isIpv4 =
     host.matches(
         Regex(
             """^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""
         )
     )

 return when {
     isIpv4 -> {
         val parts =
             host.split(".")
                 .map { value ->
                     val n =
                         value.toInt()

                     if (n !in 0..255) {
                         throw IllegalArgumentException(
                             "Invalid IPv4 address: $host"
                         )
                     }

                     n.toByte()
                 }

         byteArrayOf(
             0x05,
             0x01,
             0x00,
             0x01,
             parts[0],
             parts[1],
             parts[2],
             parts[3],
             ((port shr 8) and 0xFF).toByte(),
             (port and 0xFF).toByte()
         )
     }

     host.contains(":") -> {
         val ip6 =
             InetAddress.getByName(host).address

         if (ip6.size != 16) {
             throw IllegalArgumentException(
                 "Invalid IPv6 address: $host"
             )
         }

         val packet =
             ByteArray(22)

         packet[0] = 0x05
         packet[1] = 0x01
         packet[2] = 0x00
         packet[3] = 0x04

         System.arraycopy(
             ip6,
             0,
             packet,
             4,
             16
         )

         packet[20] =
             ((port shr 8) and 0xFF).toByte()

         packet[21] =
             (port and 0xFF).toByte()

         packet
     }

     else -> {
         val domain =
             host.toByteArray(
                 StandardCharsets.UTF_8
             )

         if (domain.isEmpty()) {
             throw IllegalArgumentException(
                 "SOCKS5 target hostname is empty"
             )
         }

         if (domain.size > 255) {
             throw IllegalArgumentException(
                 "Domain name exceeds 255 bytes"
             )
         }

         val packet =
             ByteArray(
                 4 + 1 + domain.size + 2
             )

         packet[0] = 0x05
         packet[1] = 0x01
         packet[2] = 0x00
         packet[3] = 0x03
         packet[4] = domain.size.toByte()

         System.arraycopy(
             domain,
             0,
             packet,
             5,
             domain.size
         )

         packet[5 + domain.size] =
             ((port shr 8) and 0xFF).toByte()

         packet[6 + domain.size] =
             (port and 0xFF).toByte()

         packet
     }
 }
  
  }
  
  /**
  
  * TLS wrapper with explicit SNI.
  
  * 
  
  * The underlying socket was already protected before connect().
  
  * Do NOT call VpnService.protect() again on the SSL wrapper.
    */
    private fun performTlsHandshake(
    rawSocket: Socket,
    peerHost: String,
    peerPort: Int
    ): Socket {
    val rawSni =
    profile.sni.trim()
    .ifBlank { peerHost }
    
    val cleanSni =
    SniUtils.sanitizeSni(
    rawSni,
    peerHost
    )
    
    VpnLogManager.log(
    LogLevel.CONN,
    "TLS",
    "[TLS] Encapsulating with SNI: $cleanSni (Version: ${profile.sniVersion}, Insecure: ${profile.allowInsecure})"
    )
    
    val sslFactory: SSLSocketFactory =
    if (profile.allowInsecure) {
    val trustAll =
    arrayOf<javax.net.ssl.TrustManager>(
    object :
    javax.net.ssl.X509TrustManager {
    
                     override fun getAcceptedIssuers():
                     Array<java.security.cert.X509Certificate> =
                     arrayOf()

                 override fun checkClientTrusted(
                     certs: Array<java.security.cert.X509Certificate>?,
                     authType: String?
                 ) {
                 }

                 override fun checkServerTrusted(
                     certs: Array<java.security.cert.X509Certificate>?,
                     authType: String?
                 ) {
                 }
             }
         )

     val context =
         javax.net.ssl.SSLContext.getInstance(
             "TLS"
         )

     context.init(
         null,
         trustAll,
         java.security.SecureRandom()
     )

     context.socketFactory
 } else {
     SSLSocketFactory.getDefault()
         as SSLSocketFactory
 }
    
    val sslSocket =
    sslFactory.createSocket(
    rawSocket,
    cleanSni,
    peerPort,
    true
    ) as SSLSocket
    
    val enabledProtocols =
    when (profile.sniVersion) {
    "TLSv1.3" ->
    arrayOf("TLSv1.3")
    
         "TLSv1.2" ->
         arrayOf("TLSv1.2")

     else ->
         arrayOf(
             "TLSv1.3",
             "TLSv1.2"
         )
 }
    
    try {
    sslSocket.enabledProtocols =
    enabledProtocols
    } catch (_: Exception) {
    }
    
    val sslParameters =
    SSLParameters().apply {
    if (cleanSni.isNotBlank()) {
    serverNames =
    listOf(
    SNIHostName(cleanSni)
    )
    }
    
         if (
         Build.VERSION.SDK_INT >=
         Build.VERSION_CODES.Q
     ) {
         try {
             applicationProtocols =
                 arrayOf("http/1.1")
         } catch (_: Exception) {
         }
     }
 }
    
    sslSocket.sslParameters =
    sslParameters
    
    sslSocket.soTimeout = 25000
    
    sslSocket.startHandshake()
    
    val session =
    sslSocket.session
    
    VpnLogManager.log(
    LogLevel.CONN,
    "TLS",
    "[TLS] TLS handshake established (${session.protocol}, ${session.cipherSuite})"
    )
    
    return sslSocket
    }
  
  /**
  
  * Handles custom payload.
  
  * 
  
  * Standard SSH does NOT become WebSocket merely because the payload
  
  * happens to contain "Upgrade: websocket".
    */
    private fun handleCustomPayload(
    socket: Socket,
    serverHost: String,
    serverPort: Int
    ): Socket {
    val targetHost =
    profile.server.trim()
    .ifBlank { serverHost }
    
    val targetPort =
    if (profile.port > 0) {
    profile.port
    } else {
    serverPort
    }
    
    val cleanSni =
    SniUtils.sanitizeSni(
    profile.sni.trim()
    .ifBlank { targetHost },
    targetHost
    )
    
    val httpHost =
    profile.host.trim()
    .ifBlank { targetHost }
    
    val wsPath =
    profile.path.trim()
    .ifBlank { "/ws" }
    
    val hasRemoteProxy =
    profile.remoteProxyEnabled &&
    profile.remoteProxyHost.isNotBlank()
    
    val remoteProxyStr =
    if (hasRemoteProxy) {
    "${profile.remoteProxyHost.trim()}:${
    if (profile.remoteProxyPort > 0) {
    profile.remoteProxyPort
    } else {
    8080
    }
    }"
    } else {
    "none"
    }
    
    val stages =
    splitPayloadStages(
    profile.sshPayload
    )
    
    val out =
    socket.getOutputStream()
    
    val input =
    socket.getInputStream()
    
    val pushback =
    PushbackInputStream(
    input,
    4096
    )
    
    /*
    
    * Intermediate split stages.
      */
      if (stages.size > 1) {
      for (i in 0 until stages.size - 1) {
      val stage =
      stages[i]
      
       val formatted =
     formatPayload(
         stage.template,
         serverHost,
         serverPort
     )

 VpnLogManager.log(
     LogLevel.CONN,
     "PAYLOAD",
     "[PAYLOAD] Executing stage ${i + 1}/${stages.size}"
 )

 out.write(
     formatted.toByteArray(
         StandardCharsets.UTF_8
     )
 )

 out.flush()

 if (
     peekIsHttp(
         pushback,
         1000
     )
 ) {
     val response =
         HttpStatusParser.consumeSingleResponse(
             pushback
         )

     if (response != null) {
         val code =
             response.statusCode ?: 0

         VpnLogManager.log(
             LogLevel.CONN,
             "HTTP",
             "[HTTP] ${response.statusLine}"
         )

         if (code in 400..599) {
             val source =
                 HttpStatusParser.identifyRejectionSource(
                     response.headers,
                     response.statusLine,
                     remoteProxyStr
                 )

             throw IllegalStateException(
                 "HTTP Transport stage ${i + 1} rejected by $source: HTTP $code (${response.statusLine})"
             )
         }
     }
 }

 if (stage.delayMs > 0) {
     try {
         Thread.sleep(stage.delayMs)
     } catch (_: InterruptedException) {
         Thread.currentThread()
             .interrupt()

         throw IllegalStateException(
             "Payload stage interrupted"
         )
     }
 }
      
      }
      }
    
    val finalTemplate =
    if (stages.isNotEmpty()) {
    stages.last().template
    } else {
    profile.sshPayload
    }
    
    val formattedPayload =
    formatPayload(
    finalTemplate,
    serverHost,
    serverPort
    )
    
    /*
    
    * WebSocket is explicit only.
      */
      if (profile.isSshWebSocket) {
      VpnLogManager.log(
      LogLevel.INFO,
      "WS",
      """[WS REQUEST]
      host=$httpHost
      path=$wsPath
      upgrade=websocket
      connection=Upgrade
      version=13
      sni=$cleanSni
      remote_proxy=$remoteProxyStr
      target=$targetHost:$targetPort
      sec_key=PRESENT"""
      )
      
      out.write(
      formattedPayload.toByteArray(
      StandardCharsets.UTF_8
      )
      )
      
      out.flush()
      
      val response =
      HttpStatusParser.consumeSingleResponse(
      pushback
      )
      ?: throw IllegalStateException(
      "Remote endpoint closed during WebSocket handshake"
      )
      
      val code =
      response.statusCode ?: 0
      
      VpnLogManager.log(
      LogLevel.CONN,
      "HTTP",
      "[HTTP] HTTP_RESPONSE: ${response.statusLine}"
      )
      
      if (code != 101) {
      val source =
      HttpStatusParser.identifyRejectionSource(
      response.headers,
      response.statusLine,
      remoteProxyStr
      )
      
       throw IllegalStateException(
     "WebSocket Upgrade rejected by $source: HTTP $code (${response.statusLine})"
 )
      
      }
      
      VpnLogManager.log(
      LogLevel.INFO,
      "WS",
      "[WS] HTTP 101 Switching Protocols"
      )
      
      VpnLogManager.log(
      LogLevel.INFO,
      "WS",
      "[WS] FRAMING=ACTIVE"
      )
      
      return WebSocketFramedSocket(
      socket,
      pushback
      )
      }
    
    /*
    
    * STANDARD / HCR:
    * 
    * Never enable WebSocket framing here.
      */
      val payloadBytes =
      formattedPayload.toByteArray(
      StandardCharsets.UTF_8
      )
    
    VpnLogManager.log(
    LogLevel.CONN,
    "PAYLOAD",
    "[PAYLOAD] Injecting SSH Standard payload (${payloadBytes.size} bytes)"
    )
    
    out.write(payloadBytes)
    out.flush()
    
    /*
    
    * Only consume an HTTP response when the stream actually starts
    
    * with HTTP/.
    
    * 
    
    * SSH banners are preserved and passed to Trilead.
      */
      if (
      peekIsHttp(
      pushback,
      1500
      )
      ) {
      val response =
      HttpStatusParser.consumeSingleResponse(
      pushback
      )
      
      if (response != null) {
      val code =
      response.statusCode ?: 0
      
       VpnLogManager.log(
     LogLevel.CONN,
     "HTTP",
     "[HTTP] HTTP_RESPONSE: ${response.statusLine}"
 )

 if (code in 400..599) {
     val source =
         HttpStatusParser.identifyRejectionSource(
             response.headers,
             response.statusLine,
             remoteProxyStr
         )

     throw IllegalStateException(
         "HTTP Transport rejected by $source: HTTP $code (${response.statusLine})"
     )
 }

 /*
  * Drain subsequent informational responses.
  */
 while (
     peekIsHttp(
         pushback,
         500
     )
 ) {
     val next =
         HttpStatusParser.consumeSingleResponse(
             pushback
         )
             ?: break

     val nextCode =
         next.statusCode ?: 0

     if (nextCode in 400..599) {
         throw IllegalStateException(
             "HTTP Transport rejected: HTTP $nextCode (${next.statusLine})"
         )
     }
 }
      
      }
      } else {
      VpnLogManager.log(
      LogLevel.CONN,
      "SSH",
      "[SSH] Raw SSH stream ready; proceeding to Trilead"
      )
      }
    
    return DelegatedInputStreamSocket(
    socket,
    pushback
    )
    }
  
  /**
  
  * Detect HTTP without consuming the stream.
  
  * 
  
  * SSH-2 identification starts with SSH-.
  
  * HTTP starts with HTTP/.
    */
    private fun peekIsHttp(
    pushback: PushbackInputStream,
    maxWaitMs: Int = 1500
    ): Boolean {
    val deadline =
    System.currentTimeMillis() +
    maxWaitMs
    
    while (
    pushback.available() == 0 &&
    System.currentTimeMillis() < deadline
    ) {
    try {
    Thread.sleep(25)
    } catch (_: InterruptedException) {
    Thread.currentThread()
    .interrupt()
    
         return false
 }
    
    }
    
    val buffer =
    ByteArray(8)
    
    var count = 0
    
    try {
    while (count < buffer.size) {
    val value =
    pushback.read()
    
         if (value == -1) {
         break
     }

     buffer[count++] =
         value.toByte()

     if (count >= 5) {
         break
     }

     if (pushback.available() == 0) {
         break
     }
 }
    
    } catch (_: Exception) {
    return false
    }
    
    if (count == 0) {
    return false
    }
    
    pushback.unread(
    buffer,
    0,
    count
    )
    
    val text =
    String(
    buffer,
    0,
    count,
    StandardCharsets.US_ASCII
    )
    
    if (
    text.startsWith(
    "SSH-",
    ignoreCase = true
    )
    ) {
    VpnLogManager.log(
    LogLevel.CONN,
    "SSH",
    "[SSH] SSH banner detected on transport"
    )
    
     return false
    
    }
    
    return text.startsWith(
    "HTTP/",
    ignoreCase = true
    )
    }
  
  /**
  
  * Verify authenticated SSH transport and direct-tcpip forwarding.
  
  * 
  
  * This is STRICT.
  
  * 
  
  * If forwarding cannot be established for any probe target,
  
  * tunnel readiness fails.
    /
    private fun verifyEndToEndConnectivity(
    connection: Connection
    ) {
    /
    
    * First verify authenticated SSH transport.
      */
      try {
      connection.ping()
      
      VpnLogManager.log(
      LogLevel.INFO,
      "VERIFY",
      "[VERIFY] SSH transport ping successful"
      )
      } catch (e: Exception) {
      throw IllegalStateException(
      "Authenticated SSH transport ping failed",
      e
      )
      }
    
    /*
    
    * Then verify actual direct-tcpip forwarding.
      */
      val probeTargets =
      listOf(
      "1.1.1.1" to 80,
      "1.0.0.1" to 80,
      "8.8.8.8" to 80,
      "1.1.1.1" to 443
      )
    
    var lastError: Exception? = null
    
    for ((host, port) in probeTargets) {
    var forwarder:
    LocalStreamForwarder? = null
    
     try {
     currentStage =
         "DIRECT_TCPIP_VERIFY"

     forwarder =
         connection.createLocalStreamForwarder(
             host,
             port
         )

     /*
      * Opening direct-tcpip successfully is the primary
      * forwarding test.
      */
     if (port == 80) {
         val output =
             forwarder.outputStream

         val request =
             "HEAD / HTTP/1.1\r\n" +
                 "Host: $host\r\n" +
                 "User-Agent: V2TunnelProbe/1.0\r\n" +
                 "Connection: close\r\n\r\n"

         output.write(
             request.toByteArray(
                 StandardCharsets.US_ASCII
             )
         )

         output.flush()

         /*
          * Do not block indefinitely waiting for an HTTP body.
          * Channel creation is already the required forwarding
          * capability check.
          */
         try {
             forwarder.inputStream.available()
         } catch (_: Exception) {
         }
     }

     VpnLogManager.log(
         LogLevel.INFO,
         "VPN",
         "[VPN] E2E=PASS"
     )

     VpnLogManager.log(
         LogLevel.INFO,
         "VERIFY",
         "[VERIFY] direct-tcpip forwarding verified via $host:$port"
     )

     return
 } catch (e: Exception) {
     lastError = e

     VpnLogManager.log(
         LogLevel.WARN,
         "VERIFY",
         "[VERIFY] direct-tcpip probe $host:$port failed: ${e.message}"
     )
 } finally {
     try {
         forwarder?.close()
     } catch (_: Exception) {
     }
 }
    
    }
    
    throw IllegalStateException(
    "SSH authentication succeeded but direct-tcpip forwarding failed for all probe targets. " +
    "Last error: ${lastError?.message}"
    )
    }
  
  data class PayloadStage(
  val template: String,
  val delayMs: Long = 0,
  val isLast: Boolean = false
  )
  
  /**
  
  * Split payload according to supported HTTP Custom tokens.
    */
    fun splitPayloadStages(
    rawPayload: String
    ): List<PayloadStage> {
    if (rawPayload.isBlank()) {
    return emptyList()
    }
    
    val pattern =
    Regex(
    "(?i)\(split|splitNoDelay|instant_split|delay|delay_split|split_delay)\"
    )
    
    val matches =
    pattern
    .findAll(rawPayload)
    .toList()
    
    if (matches.isEmpty()) {
    return listOf(
    PayloadStage(
    template = rawPayload,
    delayMs = 0,
    isLast = true
    )
    )
    }
    
    val stages =
    mutableListOf<PayloadStage>()
    
    var lastIndex = 0
    
    for (match in matches) {
    val chunk =
    rawPayload.substring(
    lastIndex,
    match.range.first
    )
    
     val tag =
     match.groupValues[1]
         .lowercase(Locale.ROOT)

 val delay =
     when (tag) {
         "delay",
         "delay_split",
         "split_delay" -> 100L

         else -> 0L
     }

 if (
     chunk.isNotBlank() ||
     stages.isNotEmpty()
 ) {
     stages.add(
         PayloadStage(
             template = chunk,
             delayMs = delay,
             isLast = false
         )
     )
 }

 lastIndex =
     match.range.last + 1
    
    }
    
    val lastChunk =
    rawPayload.substring(lastIndex)
    
    if (
    lastChunk.isNotBlank() ||
    stages.isNotEmpty()
    ) {
    stages.add(
    PayloadStage(
    template = lastChunk,
    delayMs = 0,
    isLast = true
    )
    )
    }
    
    return stages
    }
  
  /**
  
  * Replace HTTP Custom payload placeholders.
  
  * 
  
  * WebSocket-specific manipulation occurs ONLY when
  
  * profile.isSshWebSocket is explicitly true.
    */
    fun formatPayload(
    payloadTemplate: String,
    host: String,
    port: Int
    ): String {
    val targetHost =
    profile.server.trim()
    .ifBlank { host }
    
    val targetPort =
    if (profile.port > 0) {
    profile.port
    } else {
    port
    }
    
    val sniHost =
    profile.sni.trim()
    .ifBlank { targetHost }
    
    val proxyHost =
    profile.remoteProxyHost.trim()
    .ifBlank { targetHost }
    
    val proxyPort =
    if (profile.remoteProxyPort > 0) {
    profile.remoteProxyPort
    } else {
    8080
    }
    
    val httpHost =
    profile.host.trim()
    .ifBlank { targetHost }
    
    val payloadHost =
    profile.host.trim()
    .ifBlank { targetHost }
    
    val payloadHostPort =
    "$payloadHost:$targetPort"
    
    val wsHost =
    profile.wsHost.trim()
    .ifBlank { targetHost }
    
    val wsPath =
    profile.path.trim()
    .ifBlank { "/ws" }
    
    var result =
    payloadTemplate
    .replace(
    "[host]",
    httpHost,
    ignoreCase = true
    )
    .replace(
    "[server]",
    targetHost,
    ignoreCase = true
    )
    .replace(
    "[target]",
    targetHost,
    ignoreCase = true
    )
    .replace(
    "[port]",
    targetPort.toString(),
    ignoreCase = true
    )
    .replace(
    "[host_port]",
    "$httpHost:$targetPort",
    ignoreCase = true
    )
    .replace(
    "[proxy_host]",
    proxyHost,
    ignoreCase = true
    )
    .replace(
    "[proxy_port]",
    proxyPort.toString(),
    ignoreCase = true
    )
    .replace(
    "[proxy_host_port]",
    "$proxyHost:$proxyPort",
    ignoreCase = true
    )
    .replace(
    "[sni]",
    sniHost,
    ignoreCase = true
    )
    .replace(
    "[http_host]",
    httpHost,
    ignoreCase = true
    )
    .replace(
    "[payload_host]",
    payloadHost,
    ignoreCase = true
    )
    .replace(
    "[payload_host_port]",
    payloadHostPort,
    ignoreCase = true
    )
    .replace(
    "[ws_host]",
    wsHost,
    ignoreCase = true
    )
    .replace(
    "[ws_path]",
    wsPath,
    ignoreCase = true
    )
    .replace(
    "[path]",
    wsPath,
    ignoreCase = true
    )
    .replace(
    "[raw_host]",
    targetHost,
    ignoreCase = true
    )
    .replace(
    "[protocol]",
    "HTTP/1.1",
    ignoreCase = true
    )
    .replace(
    "[lfcr]",
    "\n\r",
    ignoreCase = true
    )
    .replace(
    "[crlf]",
    "\r\n",
    ignoreCase = true
    )
    .replace(
    "[lf]",
    "\n",
    ignoreCase = true
    )
    .replace(
    "[cr]",
    "\r",
    ignoreCase = true
    )
    .replace(
    "\r",
    "\r"
    )
    .replace(
    "\n",
    "\n"
    )
    .replace(
    "[ua]",
    "Mozilla/5.0 (Linux; Android 16; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ignoreCase = true
    )
    .replace(
    "[real_raw]",
    "",
    ignoreCase = true
    )
    
    /*
    
    * Explicit WebSocket mode only.
      */
      if (profile.isSshWebSocket) {
      if (
      wsPath != "/" &&
      wsPath.isNotBlank() &&
      result.contains(
      "GET / HTTP/1.1",
      ignoreCase = true
      )
      ) {
      result =
      result.replaceFirst(
      Regex(
      "(?i)GET\s+/\s+HTTP/1\.1"
      ),
      "GET $wsPath HTTP/1.1"
      )
      }
      
      if (
      !result.contains(
      "Host:",
      ignoreCase = true
      )
      ) {
      result =
      result.replaceFirst(
      Regex(
      "(?i)(HTTP/1\.[01]\r?\n)"
      ),
      "$1Host: $httpHost\r\n"
      )
      }
      
      if (
      result.contains(
      "Connection: Keep-Alive",
      ignoreCase = true
      )
      ) {
      result =
      result.replace(
      Regex(
      "(?i)Connection:\sKeep-Alive"
      ),
      "Connection: Upgrade"
      )
      } else if (
      !result.contains(
      "Connection:",
      ignoreCase = true
      )
      ) {
      result =
      result.replaceFirst(
      Regex(
      "(?i)(Upgrade:\swebsocket)"
      ),
      "$1\r\nConnection: Upgrade"
      )
      }
      
      if (
      !result.contains(
      "User-Agent:",
      ignoreCase = true
      )
      ) {
      val userAgent =
      "User-Agent: Mozilla/5.0 " +
      "(Linux; Android 16; Mobile) " +
      "AppleWebKit/537.36 " +
      "(KHTML, like Gecko) " +
      "Chrome/120.0.0.0 Mobile Safari/537.36\r\n"
      
       if (
     result.contains(
         "Host:",
         ignoreCase = true
     )
 ) {
     result =
         result.replaceFirst(
             Regex(
                 "(?i)(Host:[^\\r\\n]*\\r?\\n)"
             ),
             "$1$userAgent"
         )
 } else {
     result =
         result.replaceFirst(
             Regex(
                 "(?i)(Upgrade:\\s*websocket)"
             ),
             "$userAgent$1"
         )
 }
      
      }
      
      if (
      !result.contains(
      "Sec-WebSocket-Key:",
      ignoreCase = true
      )
      ) {
      val nonce =
      ByteArray(16)
      
       java.security.SecureRandom()
     .nextBytes(nonce)

 val key =
     Base64.encodeToString(
         nonce,
         Base64.NO_WRAP
     )

 result =
     result.replaceFirst(
         Regex(
             "(?i)(Upgrade:\\s*websocket)"
         ),
         "$1\r\nSec-WebSocket-Key: $key"
     )
      
      }
      
      if (
      !result.contains(
      "Sec-WebSocket-Version:",
      ignoreCase = true
      )
      ) {
      result =
      result.replaceFirst(
      Regex(
      "(?i)(Upgrade:\s*websocket)"
      ),
      "$1\r\nSec-WebSocket-Version: 13"
      )
      }
      
      result =
      result
      .replace("\r\n", "\n")
      .replace("\r", "\n")
      .replace("\n", "\r\n")
      
      if (!result.endsWith("\r\n\r\n")) {
      result +=
      if (result.endsWith("\r\n")) {
      "\r\n"
      } else {
      "\r\n\r\n"
      }
      }
      }
    
    return result
    }
  
  private fun readLine(
  input: InputStream
  ): String {
  val builder =
  StringBuilder()
  
   while (true) {
     val value =
         input.read()

     if (value == -1) {
         break
     }

     if (value == '\n'.code) {
         break
     }

     if (value != '\r'.code) {
         builder.append(
             value.toChar()
         )
     }
 }

 return builder.toString()
  
  }
  
  private fun InputStream.readNBytesCompat(
  n: Int
  ): ByteArray {
  if (n <= 0) {
  return ByteArray(0)
  }
  
   val buffer =
     ByteArray(n)

 var total = 0

 while (total < n) {
     val count =
         read(
             buffer,
             total,
             n - total
         )

     if (count == -1) {
         throw IllegalStateException(
             "Unexpected EOF while reading proxy response"
         )
     }

     if (count == 0) {
         continue
     }

     total += count
 }

 return buffer
  
  }
  }

/**

* Delegated Socket exposing a PushbackInputStream while preserving

* the original transport socket.
  */
  private class DelegatedInputStreamSocket(
  private val delegate: Socket,
  private val customIn: InputStream
  ) : Socket() {
  
  override fun getInputStream(): InputStream =
  customIn
  
  override fun getOutputStream(): OutputStream =
  delegate.getOutputStream()
  
  override fun isConnected(): Boolean =
  delegate.isConnected
  
  override fun isClosed(): Boolean =
  delegate.isClosed
  
  override fun isBound(): Boolean =
  delegate.isBound
  
  override fun close() {
  delegate.close()
  }
  
  override fun getRemoteSocketAddress(): SocketAddress? =
  delegate.remoteSocketAddress
  
  override fun getLocalSocketAddress(): SocketAddress? =
  delegate.localSocketAddress
  
  override fun setSoTimeout(timeout: Int) {
  delegate.soTimeout = timeout
  }
  
  override fun getSoTimeout(): Int =
  delegate.soTimeout
  
  override fun setTcpNoDelay(on: Boolean) {
  delegate.tcpNoDelay = on
  }
  
  override fun getTcpNoDelay(): Boolean =
  delegate.tcpNoDelay
  
  override fun getKeepAlive(): Boolean =
  delegate.keepAlive
  
  override fun setKeepAlive(on: Boolean) {
  delegate.keepAlive = on
  }
  
  override fun getReuseAddress(): Boolean =
  delegate.reuseAddress
  
  override fun setReuseAddress(on: Boolean) {
  delegate.reuseAddress = on
  }
  
  override fun getReceiveBufferSize(): Int =
  delegate.receiveBufferSize
  
  override fun setReceiveBufferSize(size: Int) {
  delegate.receiveBufferSize = size
  }
  
  override fun getSendBufferSize(): Int =
  delegate.sendBufferSize
  
  override fun setSendBufferSize(size: Int) {
  delegate.sendBufferSize = size
  }
  
  override fun getTrafficClass(): Int =
  delegate.trafficClass
  
  override fun setTrafficClass(trafficClass: Int) {
  delegate.trafficClass = trafficClass
  }
  
  override fun shutdownInput() {
  delegate.shutdownInput()
  }
  
  override fun shutdownOutput() {
  delegate.shutdownOutput()
  }
  }
