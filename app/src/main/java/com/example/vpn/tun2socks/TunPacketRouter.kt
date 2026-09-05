package com.example.vpn.tun2socks

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.example.model.LogLevel
import com.example.vpn.VpnLogManager
import com.example.vpn.socks.LocalSocksServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * TCP/IP Tun2Socks engine for the Android TUN interface.
 *
 * Responsibilities:
 * - Handle IPv4 TCP traffic from the Android TUN interface.
 * - Maintain a virtual TCP session for each application connection.
 * - Forward TCP streams through the local SOCKS5 server.
 * - Buffer application payload that arrives before the SOCKS5 connection
 *   has completed its handshake.
 * - Segment upstream data into IPv4/TCP packets using MSS.
 * - Handle TCP FIN/RST teardown.
 * - Forward DNS UDP/53 queries through a protected upstream socket.
 *
 * This class is a custom Kotlin tun2socks implementation.
 * It is NOT BadVPN and does not contain a native BadVPN engine.
 */
class TunPacketRouter(
    private val vpnService: VpnService,
    private val tunInterface: ParcelFileDescriptor,
    private val socksServer: LocalSocksServer,
    private val upstreamDnsIp: String = "1.1.1.1"
) {
    private val isRunning = AtomicBoolean(false)
    private val routerScope = CoroutineScope(Dispatchers.IO)
    private var readJob: Job? = null

    val totalRxBytes = AtomicLong(0)
    val totalTxBytes = AtomicLong(0)

    private val activeSessions = ConcurrentHashMap<String, TcpSession>()
    private val openSockets = Collections.newSetFromMap(
        ConcurrentHashMap<Socket, Boolean>()
    )

    private var tunOutputStream: FileOutputStream? = null
    private val writeLock = Any()

    private val dnsSocket = java.nio.channels.DatagramChannel.open().socket().apply {
        soTimeout = 5000
        vpnService.protect(this)
    }

    companion object {
        const val MTU = 1500
        const val IP_HEADER_LEN = 20
        const val TCP_HEADER_LEN = 20
        const val MSS = MTU - IP_HEADER_LEN - TCP_HEADER_LEN
    }

    /**
     * Represents one virtual TCP connection between an Android application
     * and the remote destination.
     */
    inner class TcpSession(
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int,
        var clientSeq: Long,
        var serverSeq: Long,
        @Volatile var state: TcpState,
        @Volatile var socksSocket: Socket? = null,
        @Volatile var remoteJob: Job? = null
    ) {
        val lastActivityTime = AtomicLong(System.currentTimeMillis())

        /**
         * Payload received from the Android application before the SOCKS5
         * connection has become ready.
         *
         * Access is protected by [sessionLock].
         */
        private val pendingPayloads = ArrayList<ByteArray>()

        /**
         * Protects the SOCKS socket publication and pending payload queue.
         */
        val sessionLock = Any()

        fun updateActivity() {
            lastActivityTime.set(System.currentTimeMillis())
        }

        /**
         * Queue data until the SOCKS5 connection is fully established.
         */
        fun bufferPayload(payload: ByteArray) {
            if (payload.isEmpty()) return

            synchronized(sessionLock) {
                if (state != TcpState.CLOSED) {
                    pendingPayloads.add(payload.copyOf())
                }
            }
        }

        /**
         * Publishes the ready SOCKS socket and atomically takes all payload
         * that arrived while the SOCKS handshake was in progress.
         */
        fun publishSocksSocket(socket: Socket): List<ByteArray> {
            synchronized(sessionLock) {
                if (state == TcpState.CLOSED) {
                    throw IllegalStateException("TCP session already closed")
                }

                socksSocket = socket

                val buffered = ArrayList(pendingPayloads)
                pendingPayloads.clear()

                return buffered
            }
        }

        fun clearPendingPayloads() {
            synchronized(sessionLock) {
                pendingPayloads.clear()
            }
        }

        fun close() {
            val socketToClose: Socket?

            synchronized(sessionLock) {
                state = TcpState.CLOSED
                pendingPayloads.clear()

                remoteJob?.cancel()

                socketToClose = socksSocket
                socksSocket = null
            }

            socketToClose?.let { sock ->
                try {
                    openSockets.remove(sock)
                    sock.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    enum class TcpState {
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
        CLOSED
    }

    fun start() {
        if (isRunning.getAndSet(true)) return

        VpnLogManager.log(
            LogLevel.INFO,
            "TUN2SOCKS START",
            "[TUN2SOCKS START] Attached to TUN interface fd=${tunInterface.fd} " +
                "(MTU: $MTU, MSS: $MSS)"
        )

        VpnLogManager.log(
            LogLevel.INFO,
            "TUN2SOCKS START",
            "[TUN2SOCKS START] Routing TCP traffic to SOCKS5 " +
                "127.0.0.1:${socksServer.port}"
        )

        VpnLogManager.log(
            LogLevel.INFO,
            "DNS",
            "[DNS] Upstream DNS resolver configured: $upstreamDnsIp:53 (protected)"
        )

        readJob = routerScope.launch {
            val fileDescriptor = tunInterface.fileDescriptor
            val inputStream = FileInputStream(fileDescriptor)
            val outputStream = FileOutputStream(fileDescriptor)

            tunOutputStream = outputStream

            val packetBuffer = ByteBuffer.allocate(32767)
            val inChannel = inputStream.channel

            while (isActive && isRunning.get()) {
                try {
                    packetBuffer.clear()

                    val bytesRead = inChannel.read(packetBuffer)

                    if (bytesRead > 0) {
                        packetBuffer.flip()

                        totalTxBytes.addAndGet(bytesRead.toLong())

                        processTunPacket(packetBuffer)
                    } else if (bytesRead < 0) {
                        break
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        VpnLogManager.log(
                            LogLevel.WARN,
                            "TUN",
                            "[TUN] Read stream closed: ${e.message}"
                        )
                    }
                    break
                }
            }
        }
    }

    private fun processTunPacket(packet: ByteBuffer) {
        if (packet.remaining() < IP_HEADER_LEN) return

        val versionAndIhl = packet.get(0).toInt() and 0xFF
        val version = versionAndIhl ushr 4

        if (version != 4) return

        val ihl = (versionAndIhl and 0x0F) * 4

        if (ihl < IP_HEADER_LEN || packet.remaining() < ihl) return

        val totalLength =
            ((packet.get(2).toInt() and 0xFF) shl 8) or
                (packet.get(3).toInt() and 0xFF)

        if (totalLength < ihl || totalLength > packet.remaining()) return

        val protocol = packet.get(9).toInt() and 0xFF

        val srcIp = ByteArray(4).apply {
            packet.position(12)
            packet.get(this)
        }

        val dstIp = ByteArray(4).apply {
            packet.position(16)
            packet.get(this)
        }

        when (protocol) {
            17 -> handleUdpPacket(packet, ihl, srcIp, dstIp)
            6 -> handleTcpPacket(packet, ihl, totalLength, srcIp, dstIp)
            1 -> handleIcmpPacket(packet, ihl, totalLength, srcIp, dstIp)
        }
    }

    /**
     * Handles IPv4 TCP packets from the TUN interface.
     */
    private fun handleTcpPacket(
        packet: ByteBuffer,
        ihl: Int,
        totalLength: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        if (totalLength < ihl + TCP_HEADER_LEN) return

        val tcpOffset = ihl

        val srcPort =
            ((packet.get(tcpOffset).toInt() and 0xFF) shl 8) or
                (packet.get(tcpOffset + 1).toInt() and 0xFF)

        val dstPort =
            ((packet.get(tcpOffset + 2).toInt() and 0xFF) shl 8) or
                (packet.get(tcpOffset + 3).toInt() and 0xFF)

        val seqNum =
            packet.getInt(tcpOffset + 4).toLong() and 0xFFFFFFFFL

        val ackNum =
            packet.getInt(tcpOffset + 8).toLong() and 0xFFFFFFFFL

        val dataOffset =
            ((packet.get(tcpOffset + 12).toInt() and 0xF0) ushr 4) * 4

        if (dataOffset < TCP_HEADER_LEN ||
            totalLength < ihl + dataOffset
        ) {
            return
        }

        val flags = packet.get(tcpOffset + 13).toInt() and 0xFF

        val isFin = (flags and 0x01) != 0
        val isSyn = (flags and 0x02) != 0
        val isRst = (flags and 0x04) != 0
        val isPsh = (flags and 0x08) != 0
        val isAck = (flags and 0x10) != 0

        // isPsh is intentionally decoded because PSH is part of normal
        // TCP traffic. Data handling is based on payload length, not PSH.
        @Suppress("UNUSED_VARIABLE")
        val ignoredPsh = isPsh

        val payloadOffset = ihl + dataOffset
        val payloadLen = totalLength - payloadOffset

        val sessionKey =
            "${formatIp(srcIp)}:$srcPort->${formatIp(dstIp)}:$dstPort"

        if (isRst) {
            activeSessions.remove(sessionKey)?.close()
            return
        }

        /*
         * New TCP connection.
         *
         * A SYN is allowed to create the virtual server side of the TCP
         * connection. If a stale session exists for the same 4-tuple,
         * close it before replacing it.
         */
        if (isSyn) {
            activeSessions.remove(sessionKey)?.close()

            val initialServerSeq =
                System.currentTimeMillis() and 0x7FFFFFFFL

            val newSession = TcpSession(
                srcIp = srcIp.copyOf(),
                srcPort = srcPort,
                dstIp = dstIp.copyOf(),
                dstPort = dstPort,
                clientSeq = seqNum + 1,
                serverSeq = initialServerSeq,
                state = TcpState.SYN_RECEIVED
            )

            activeSessions[sessionKey] = newSession

            /*
             * Send virtual SYN-ACK immediately.
             */
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = newSession.serverSeq,
                ackNum = newSession.clientSeq,
                flags = 0x12,
                payload = ByteArray(0)
            )

            newSession.serverSeq += 1

            /*
             * Start SOCKS5 establishment asynchronously.
             *
             * Application payload arriving before this coroutine finishes
             * is buffered by handleTcpPacket() instead of being discarded.
             */
            connectSessionToSocks(newSession, sessionKey)

            /*
             * A SYN normally has no application payload. If a malformed or
             * unusual SYN contains payload, preserve it instead of dropping it.
             */
            if (payloadLen > 0) {
                val payload = ByteArray(payloadLen)
                packet.position(payloadOffset)
                packet.get(payload)

                newSession.clientSeq = seqNum + payloadLen

                sendTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seqNum = newSession.serverSeq,
                    ackNum = newSession.clientSeq,
                    flags = 0x10,
                    payload = ByteArray(0)
                )

                newSession.bufferPayload(payload)
            }

            return
        }

        val session = activeSessions[sessionKey]

        if (session == null) {
            if (isAck || isFin) {
                /*
                 * Unknown TCP flow. Reset it rather than silently accepting
                 * packets for a session that no longer exists.
                 */
                sendTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seqNum = ackNum,
                    ackNum = seqNum +
                        if (payloadLen > 0) payloadLen else 1,
                    flags = 0x14,
                    payload = ByteArray(0)
                )
            }

            return
        }

        session.updateActivity()

        /*
         * FIN from application.
         */
        if (isFin) {
            session.clientSeq = seqNum + 1
            session.state = TcpState.CLOSE_WAIT

            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x10,
                payload = ByteArray(0)
            )

            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x11,
                payload = ByteArray(0)
            )

            session.serverSeq += 1

            session.close()
            activeSessions.remove(sessionKey, session)

            return
        }

        /*
         * Application payload.
         *
         * Important:
         * Do not discard the payload when SOCKS is still connecting.
         */
        if (payloadLen > 0) {
            val payload = ByteArray(payloadLen)

            packet.position(payloadOffset)
            packet.get(payload)

            session.clientSeq = seqNum + payloadLen

            /*
             * ACK the application's payload immediately so the Android TCP
             * stack does not repeatedly retransmit while the SOCKS handshake
             * is taking place.
             */
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x10,
                payload = ByteArray(0)
            )

            val socket = synchronized(session.sessionLock) {
                session.socksSocket
            }

            if (socket != null) {
                try {
                    val out = socket.getOutputStream()
                    out.write(payload)
                    out.flush()
                } catch (e: Exception) {
                    VpnLogManager.log(
                        LogLevel.WARN,
                        "TUN2SOCKS",
                        "[TUN2SOCKS] Failed to write TCP payload " +
                            "to SOCKS5: ${e.message}"
                    )

                    session.close()
                    activeSessions.remove(sessionKey, session)
                }
            } else {
                /*
                 * SOCKS5 is not ready yet.
                 *
                 * Preserve the payload. The connection coroutine will flush
                 * all queued payload after SOCKS5 CONNECT succeeds.
                 */
                session.bufferPayload(payload)
            }
        }
    }

    /**
     * Establishes a connection from a virtual TCP session to the local SOCKS5
     * server and then relays upstream data back into the TUN interface.
     */
    private fun connectSessionToSocks(
        session: TcpSession,
        sessionKey: String
    ) {
        session.remoteJob = routerScope.launch {
            var socksSocket: Socket? = null

            try {
                socksSocket = Socket()

                openSockets.add(socksSocket)

                socksSocket.tcpNoDelay = true

                /*
                 * Do not use a read timeout for an established VPN TCP stream.
                 *
                 * A long-lived TCP connection may legitimately remain idle for
                 * more than 30 seconds. A socket timeout here would incorrectly
                 * destroy such a connection.
                 */
                socksSocket.soTimeout = 0

                socksSocket.connect(
                    InetSocketAddress(
                        "127.0.0.1",
                        socksServer.port
                    ),
                    5000
                )

                val sIn = socksSocket.getInputStream()
                val sOut = socksSocket.getOutputStream()

                /*
                 * SOCKS5 method negotiation.
                 *
                 * We currently request NO_AUTH only because the local
                 * LocalSocksServer is expected to use the no-auth method.
                 */
                sOut.write(
                    byteArrayOf(
                        0x05,
                        0x01,
                        0x00
                    )
                )
                sOut.flush()

                val authResp = ByteArray(2)

                readFully(sIn, authResp)

                if (authResp[0] != 0x05.toByte()) {
                    throw IllegalStateException(
                        "Invalid SOCKS5 version in method response"
                    )
                }

                if (authResp[1] != 0x00.toByte()) {
                    throw IllegalStateException(
                        "SOCKS5 auth negotiation failed: " +
                            "method=0x${authResp[1].toInt() and 0xFF}"
                    )
                }

                /*
                 * SOCKS5 CONNECT.
                 *
                 * This router receives IPv4 destinations from the current
                 * IPv4 TUN implementation, so ATYP=IPv4 is appropriate here.
                 */
                val connectReq = ByteArray(10)

                connectReq[0] = 0x05
                connectReq[1] = 0x01
                connectReq[2] = 0x00
                connectReq[3] = 0x01

                System.arraycopy(
                    session.dstIp,
                    0,
                    connectReq,
                    4,
                    4
                )

                connectReq[8] =
                    ((session.dstPort ushr 8) and 0xFF).toByte()

                connectReq[9] =
                    (session.dstPort and 0xFF).toByte()

                sOut.write(connectReq)
                sOut.flush()

                /*
                 * Parse SOCKS5 response correctly.
                 *
                 * Previous implementation always read 10 bytes. That is only
                 * correct for ATYP=IPv4. SOCKS5 replies may contain IPv4,
                 * DOMAIN, or IPv6 addresses.
                 */
                readSocks5ConnectResponse(sIn)

                /*
                 * Publish the socket only after the entire SOCKS5 handshake
                 * has succeeded.
                 *
                 * This makes the state transition atomic from the point of
                 * view of handleTcpPacket().
                 */
                val bufferedPayloads = session.publishSocksSocket(socksSocket)

                session.state = TcpState.ESTABLISHED

                VpnLogManager.log(
                    LogLevel.DATA,
                    "TRAFFIC",
                    "[TRAFFIC] TCP session connected: $sessionKey " +
                        "via SOCKS5"
                )

                /*
                 * Flush every TCP payload that arrived while SOCKS5 was
                 * connecting.
                 */
                for (payload in bufferedPayloads) {
                    if (!isActive ||
                        !isRunning.get() ||
                        session.state == TcpState.CLOSED
                    ) {
                        break
                    }

                    try {
                        sOut.write(payload)
                        sOut.flush()
                    } catch (e: Exception) {
                        throw IllegalStateException(
                            "Failed to flush buffered TCP payload: " +
                                e.message,
                            e
                        )
                    }
                }

                /*
                 * Read data coming back from the remote destination and
                 * package it into IPv4/TCP packets.
                 */
                val buffer = ByteArray(MSS)

                while (
                    isActive &&
                    isRunning.get() &&
                    session.state == TcpState.ESTABLISHED
                ) {
                    val bytesRead = sIn.read(buffer)

                    if (bytesRead < 0) {
                        break
                    }

                    if (bytesRead == 0) {
                        continue
                    }

                    val chunk = ByteArray(bytesRead)

                    System.arraycopy(
                        buffer,
                        0,
                        chunk,
                        0,
                        bytesRead
                    )

                    sendTcpPacket(
                        srcIp = session.dstIp,
                        dstIp = session.srcIp,
                        srcPort = session.dstPort,
                        dstPort = session.srcPort,
                        seqNum = session.serverSeq,
                        ackNum = session.clientSeq,
                        flags = 0x18,
                        payload = chunk
                    )

                    session.serverSeq += bytesRead

                    totalRxBytes.addAndGet(bytesRead.toLong())

                    session.updateActivity()
                }
            } catch (e: Exception) {
                if (isRunning.get() &&
                    session.state != TcpState.CLOSED
                ) {
                    VpnLogManager.log(
                        LogLevel.WARN,
                        "TUN2SOCKS",
                        "[TUN2SOCKS] SOCKS5 session failed " +
                            "$sessionKey: ${e.message}"
                    )
                }
            } finally {
                /*
                 * session.close() closes the published socket when one exists.
                 * If the socket failed before publication, close it here.
                 */
                if (socksSocket != null) {
                    synchronized(session.sessionLock) {
                        if (session.socksSocket !== socksSocket) {
                            try {
                                openSockets.remove(socksSocket)
                                socksSocket.close()
                            } catch (_: Exception) {
                            }
                        }
                    }
                }

                session.close()

                activeSessions.remove(sessionKey, session)
            }
        }
    }

    /**
     * Reads a complete SOCKS5 CONNECT response.
     *
     * Response format:
     *
     *   VER  REP  RSV  ATYP  BND.ADDR  BND.PORT
     *
     * ATYP:
     *   0x01 = IPv4    -> 4 address bytes
     *   0x03 = DOMAIN  -> 1 length byte + N address bytes
     *   0x04 = IPv6    -> 16 address bytes
     */
    private fun readSocks5ConnectResponse(input: InputStream) {
        val header = ByteArray(4)

        readFully(input, header)

        val version = header[0].toInt() and 0xFF
        val reply = header[1].toInt() and 0xFF
        val reserved = header[2].toInt() and 0xFF
        val addressType = header[3].toInt() and 0xFF

        if (version != 0x05) {
            throw IllegalStateException(
                "Invalid SOCKS5 response version: $version"
            )
        }

        if (reserved != 0x00) {
            throw IllegalStateException(
                "Invalid SOCKS5 reserved byte: $reserved"
            )
        }

        if (reply != 0x00) {
            throw IllegalStateException(
                "SOCKS5 connect rejected with code $reply"
            )
        }

        when (addressType) {
            0x01 -> {
                /*
                 * IPv4 BND.ADDR.
                 */
                val address = ByteArray(4)
                readFully(input, address)
            }

            0x03 -> {
                /*
                 * DOMAIN BND.ADDR.
                 */
                val lengthByte = ByteArray(1)
                readFully(input, lengthByte)

                val domainLength =
                    lengthByte[0].toInt() and 0xFF

                if (domainLength > 255) {
                    throw IllegalStateException(
                        "Invalid SOCKS5 domain length: $domainLength"
                    )
                }

                if (domainLength > 0) {
                    val domain = ByteArray(domainLength)
                    readFully(input, domain)
                }
            }

            0x04 -> {
                /*
                 * IPv6 BND.ADDR.
                 */
                val address = ByteArray(16)
                readFully(input, address)
            }

            else -> {
                throw IllegalStateException(
                    "Unsupported SOCKS5 address type: $addressType"
                )
            }
        }

        /*
         * BND.PORT is always 2 bytes.
         */
        val boundPort = ByteArray(2)
        readFully(input, boundPort)
    }

    /**
     * Handles UDP packets.
     *
     * Current implementation forwards DNS queries on UDP/53 through a
     * protected upstream UDP socket.
     */
    private fun handleUdpPacket(
        packet: ByteBuffer,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        val totalLength =
            ((packet.get(2).toInt() and 0xFF) shl 8) or
                (packet.get(3).toInt() and 0xFF)

        if (totalLength < ihl + 8) return

        val srcPort =
            ((packet.get(ihl).toInt() and 0xFF) shl 8) or
                (packet.get(ihl + 1).toInt() and 0xFF)

        val dstPort =
            ((packet.get(ihl + 2).toInt() and 0xFF) shl 8) or
                (packet.get(ihl + 3).toInt() and 0xFF)

        val udpLength =
            ((packet.get(ihl + 4).toInt() and 0xFF) shl 8) or
                (packet.get(ihl + 5).toInt() and 0xFF)

        if (udpLength < 8) return

        if (ihl + udpLength > totalLength) return

        if (dstPort == 53 && udpLength > 8) {
            val payloadLength = udpLength - 8

            val dnsQueryBytes = ByteArray(payloadLength)

            packet.position(ihl + 8)
            packet.get(dnsQueryBytes)

            routerScope.launch {
                try {
                    val upstreamAddr =
                        InetAddress.getByName(upstreamDnsIp)

                    val sendPacket = DatagramPacket(
                        dnsQueryBytes,
                        dnsQueryBytes.size,
                        upstreamAddr,
                        53
                    )

                    dnsSocket.send(sendPacket)

                    val respBuffer = ByteArray(2048)

                    val recvPacket = DatagramPacket(
                        respBuffer,
                        respBuffer.size
                    )

                    dnsSocket.receive(recvPacket)

                    val respLength = recvPacket.length

                    if (respLength > 0) {
                        val dnsRespBytes =
                            ByteArray(respLength)

                        System.arraycopy(
                            respBuffer,
                            0,
                            dnsRespBytes,
                            0,
                            respLength
                        )

                        val responseIpPacket =
                            buildUdpIpPacket(
                                srcIp = dstIp,
                                dstIp = srcIp,
                                srcPort = dstPort,
                                dstPort = srcPort,
                                payload = dnsRespBytes
                            )

                        writeToTun(responseIpPacket)

                        totalRxBytes.addAndGet(
                            responseIpPacket.size.toLong()
                        )

                        VpnLogManager.log(
                            LogLevel.DATA,
                            "DNS",
                            "[DNS] Resolved domain query via " +
                                "$upstreamDnsIp:53 " +
                                "($respLength bytes)"
                        )
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        VpnLogManager.log(
                            LogLevel.WARN,
                            "DNS",
                            "[DNS] Upstream query error: ${e.message}"
                        )
                    }
                }
            }
        }
    }

    /**
     * Handles ICMP Echo Requests locally.
     */
    private fun handleIcmpPacket(
        packet: ByteBuffer,
        ihl: Int,
        totalLength: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        if (totalLength < ihl + 8) return

        val type = packet.get(ihl).toInt() and 0xFF

        if (type == 8) {
            val echoBytes =
                ByteArray(totalLength - ihl)

            packet.position(ihl)
            packet.get(echoBytes)

            /*
             * Echo Reply.
             */
            echoBytes[0] = 0

            /*
             * Clear ICMP checksum.
             */
            echoBytes[2] = 0
            echoBytes[3] = 0

            val checksum =
                calculateChecksum(
                    echoBytes,
                    0,
                    echoBytes.size
                )

            echoBytes[2] =
                ((checksum ushr 8) and 0xFF).toByte()

            echoBytes[3] =
                (checksum and 0xFF).toByte()

            val replyPacket = buildIpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                protocol = 1,
                payload = echoBytes
            )

            writeToTun(replyPacket)

            totalRxBytes.addAndGet(
                replyPacket.size.toLong()
            )
        }
    }

    /**
     * Builds and sends a complete IPv4/TCP packet through the TUN interface.
     */
    private fun sendTcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray
    ) {
        val tcpHeaderLen = TCP_HEADER_LEN
        val tcpLen = tcpHeaderLen + payload.size

        /*
         * IPv4 total length is 16-bit.
         */
        if (tcpLen > 65535 - IP_HEADER_LEN) {
            return
        }

        val tcpPacket = ByteArray(tcpLen)

        tcpPacket[0] =
            ((srcPort ushr 8) and 0xFF).toByte()

        tcpPacket[1] =
            (srcPort and 0xFF).toByte()

        tcpPacket[2] =
            ((dstPort ushr 8) and 0xFF).toByte()

        tcpPacket[3] =
            (dstPort and 0xFF).toByte()

        /*
         * Sequence Number.
         */
        tcpPacket[4] =
            ((seqNum ushr 24) and 0xFF).toByte()

        tcpPacket[5] =
            ((seqNum ushr 16) and 0xFF).toByte()

        tcpPacket[6] =
            ((seqNum ushr 8) and 0xFF).toByte()

        tcpPacket[7] =
            (seqNum and 0xFF).toByte()

        /*
         * Acknowledgment Number.
         */
        tcpPacket[8] =
            ((ackNum ushr 24) and 0xFF).toByte()

        tcpPacket[9] =
            ((ackNum ushr 16) and 0xFF).toByte()

        tcpPacket[10] =
            ((ackNum ushr 8) and 0xFF).toByte()

        tcpPacket[11] =
            (ackNum and 0xFF).toByte()

        /*
         * Data Offset = 5 => 20-byte TCP header.
         */
        tcpPacket[12] = 0x50.toByte()

        tcpPacket[13] = flags.toByte()

        /*
         * Window Size = 65535.
         */
        tcpPacket[14] = 0xFF.toByte()
        tcpPacket[15] = 0xFF.toByte()

        /*
         * TCP checksum placeholder.
         */
        tcpPacket[16] = 0
        tcpPacket[17] = 0

        /*
         * Urgent Pointer.
         */
        tcpPacket[18] = 0
        tcpPacket[19] = 0

        if (payload.isNotEmpty()) {
            System.arraycopy(
                payload,
                0,
                tcpPacket,
                tcpHeaderLen,
                payload.size
            )
        }

        val checksum =
            calculateTcpChecksum(
                srcIp,
                dstIp,
                tcpPacket,
                tcpLen
            )

        tcpPacket[16] =
            ((checksum ushr 8) and 0xFF).toByte()

        tcpPacket[17] =
            (checksum and 0xFF).toByte()

        val ipPacket =
            buildIpPacket(
                srcIp = srcIp,
                dstIp = dstIp,
                protocol = 6,
                payload = tcpPacket
            )

        writeToTun(ipPacket)
    }

    private fun buildUdpIpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpHeader = ByteArray(8)

        udpHeader[0] =
            ((srcPort ushr 8) and 0xFF).toByte()

        udpHeader[1] =
            (srcPort and 0xFF).toByte()

        udpHeader[2] =
            ((dstPort ushr 8) and 0xFF).toByte()

        udpHeader[3] =
            (dstPort and 0xFF).toByte()

        val udpLen = 8 + payload.size

        if (udpLen > 65535) {
            return ByteArray(0)
        }

        udpHeader[4] =
            ((udpLen ushr 8) and 0xFF).toByte()

        udpHeader[5] =
            (udpLen and 0xFF).toByte()

        /*
         * UDP checksum is currently zero.
         */
        udpHeader[6] = 0
        udpHeader[7] = 0

        val udpPacket = ByteArray(udpLen)

        System.arraycopy(
            udpHeader,
            0,
            udpPacket,
            0,
            8
        )

        System.arraycopy(
            payload,
            0,
            udpPacket,
            8,
            payload.size
        )

        return buildIpPacket(
            srcIp,
            dstIp,
            protocol = 17,
            payload = udpPacket
        )
    }

    private fun buildIpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength =
            IP_HEADER_LEN + payload.size

        if (srcIp.size != 4 ||
            dstIp.size != 4 ||
            totalLength > 65535
        ) {
            return ByteArray(0)
        }

        val ipPacket = ByteArray(totalLength)

        /*
         * IPv4, IHL=5.
         */
        ipPacket[0] = 0x45.toByte()

        /*
         * DSCP / ECN.
         */
        ipPacket[1] = 0x00

        ipPacket[2] =
            ((totalLength ushr 8) and 0xFF).toByte()

        ipPacket[3] =
            (totalLength and 0xFF).toByte()

        /*
         * Identification.
         */
        val id =
            (System.currentTimeMillis() and 0xFFFF).toInt()

        ipPacket[4] =
            ((id ushr 8) and 0xFF).toByte()

        ipPacket[5] =
            (id and 0xFF).toByte()

        /*
         * Don't Fragment.
         */
        ipPacket[6] = 0x40.toByte()
        ipPacket[7] = 0x00

        /*
         * TTL.
         */
        ipPacket[8] = 64.toByte()

        ipPacket[9] = protocol.toByte()

        /*
         * IPv4 header checksum placeholder.
         */
        ipPacket[10] = 0
        ipPacket[11] = 0

        System.arraycopy(
            srcIp,
            0,
            ipPacket,
            12,
            4
        )

        System.arraycopy(
            dstIp,
            0,
            ipPacket,
            16,
            4
        )

        val headerChecksum =
            calculateChecksum(
                ipPacket,
                0,
                IP_HEADER_LEN
            )

        ipPacket[10] =
            ((headerChecksum ushr 8) and 0xFF).toByte()

        ipPacket[11] =
            (headerChecksum and 0xFF).toByte()

        System.arraycopy(
            payload,
            0,
            ipPacket,
            IP_HEADER_LEN,
            payload.size
        )

        return ipPacket
    }

    /**
     * Calculates the TCP checksum including the IPv4 pseudo-header.
     */
    private fun calculateTcpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        tcpData: ByteArray,
        tcpLength: Int
    ): Int {
        var sum = 0

        /*
         * Source IP.
         */
        sum +=
            ((srcIp[0].toInt() and 0xFF) shl 8) or
                (srcIp[1].toInt() and 0xFF)

        sum +=
            ((srcIp[2].toInt() and 0xFF) shl 8) or
                (srcIp[3].toInt() and 0xFF)

        /*
         * Destination IP.
         */
        sum +=
            ((dstIp[0].toInt() and 0xFF) shl 8) or
                (dstIp[1].toInt() and 0xFF)

        sum +=
            ((dstIp[2].toInt() and 0xFF) shl 8) or
                (dstIp[3].toInt() and 0xFF)

        /*
         * Protocol = TCP.
         */
        sum += 6

        /*
         * TCP length.
         */
        sum += tcpLength

        /*
         * TCP header + payload.
         */
        var i = 0

        while (i < tcpLength - 1) {
            val word =
                ((tcpData[i].toInt() and 0xFF) shl 8) or
                    (tcpData[i + 1].toInt() and 0xFF)

            sum += word
            i += 2
        }

        if (i < tcpLength) {
            sum +=
                (tcpData[i].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) > 0) {
            sum =
                (sum and 0xFFFF) +
                    (sum ushr 16)
        }

        return sum.inv() and 0xFFFF
    }

    /**
     * Calculates an Internet checksum.
     */
    private fun calculateChecksum(
        data: ByteArray,
        offset: Int,
        length: Int
    ): Int {
        var sum = 0
        var i = offset

        while (i < offset + length - 1) {
            val word =
                ((data[i].toInt() and 0xFF) shl 8) or
                    (data[i + 1].toInt() and 0xFF)

            sum += word
            i += 2
        }

        if (i < offset + length) {
            sum +=
                (data[i].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) > 0) {
            sum =
                (sum and 0xFFFF) +
                    (sum ushr 16)
        }

        return sum.inv() and 0xFFFF
    }

    private fun writeToTun(packet: ByteArray) {
        if (packet.isEmpty()) return

        try {
            synchronized(writeLock) {
                tunOutputStream?.write(packet)
                tunOutputStream?.flush()
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                VpnLogManager.log(
                    LogLevel.WARN,
                    "TUN",
                    "[TUN] Failed to write packet: ${e.message}"
                )
            }
        }
    }

    /**
     * Reads exactly buffer.size bytes unless EOF is reached.
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
                    "Unexpected EOF while reading socket"
                )
            }

            if (n == 0) {
                continue
            }

            total += n
        }
    }

    private fun formatIp(ip: ByteArray): String {
        if (ip.size < 4) {
            return "0.0.0.0"
        }

        return "${ip[0].toInt() and 0xFF}." +
            "${ip[1].toInt() and 0xFF}." +
            "${ip[2].toInt() and 0xFF}." +
            "${ip[3].toInt() and 0xFF}"
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return

        readJob?.cancel()
        readJob = null

        activeSessions.values.forEach { session ->
            session.close()
        }

        activeSessions.clear()

        openSockets.forEach { sock ->
            try {
                sock.close()
            } catch (_: Exception) {
            }
        }

        openSockets.clear()

        try {
            dnsSocket.close()
        } catch (_: Exception) {
        }

        synchronized(writeLock) {
            try {
                tunOutputStream?.flush()
            } catch (_: Exception) {
            }

            tunOutputStream = null
        }

        VpnLogManager.log(
            LogLevel.INFO,
            "TUN2SOCKS",
            "[TUN2SOCKS] Tun2Socks engine stopped cleanly."
        )
    }
}
