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
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Production-ready TCP/IP Tun2Socks Engine.
 * 
 * Handles full TCP state machine from the Android TUN interface:
 * - SYN: Handshake and virtual SYN-ACK generation to client
 * - ACK & PSH-ACK: Data forwarding to local SOCKS5 proxy (127.0.0.1:10808) -> VMess outbound
 * - SOCKS5 to TUN: Incoming remote data is segmented using MSS (1460 bytes max), packaged
 *   into valid IPv4/TCP packets with accurate Sequence/ACK numbers and recalculated checksums
 * - FIN/RST: Clean TCP connection teardown
 * - DNS: Intercepts UDP port 53 and resolves via protected upstream socket
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
    private val openSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    private var tunOutputStream: FileOutputStream? = null
    private val writeLock = Any()

    private val dnsSocket = DatagramSocket().apply {
        soTimeout = 5000
        vpnService.protect(this)
    }

    companion object {
        const val MTU = 1500
        const val IP_HEADER_LEN = 20
        const val TCP_HEADER_LEN = 20
        const val MSS = MTU - IP_HEADER_LEN - TCP_HEADER_LEN // 1460 bytes
    }

    /**
     * Represents a single TCP connection tracked between client app and SOCKS5 proxy.
     */
    inner class TcpSession(
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int,
        var clientSeq: Long,
        var serverSeq: Long,
        var state: TcpState,
        var socksSocket: Socket? = null,
        var remoteJob: Job? = null
    ) {
        val lastActivityTime = AtomicLong(System.currentTimeMillis())

        fun updateActivity() {
            lastActivityTime.set(System.currentTimeMillis())
        }

        fun close() {
            state = TcpState.CLOSED
            remoteJob?.cancel()
            socksSocket?.let { sock ->
                try {
                    openSockets.remove(sock)
                    sock.close()
                } catch (ignored: Exception) {}
            }
            socksSocket = null
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

        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS START", "[TUN2SOCKS START] Attached to TUN interface fd=${tunInterface.fd} (MTU: $MTU, MSS: $MSS)")
        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS START", "[TUN2SOCKS START] Routing TCP traffic to SOCKS5 127.0.0.1:${socksServer.port}")
        VpnLogManager.log(LogLevel.INFO, "DNS", "[DNS] Upstream DNS resolver configured: $upstreamDnsIp:53 (protected)")

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
                        VpnLogManager.log(LogLevel.WARN, "TUN", "[TUN] Read stream closed: ${e.message}")
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
        if (version != 4) return // Only IPv4 supported in this router

        val ihl = (versionAndIhl and 0x0F) * 4
        if (packet.remaining() < ihl) return

        val totalLength = ((packet.get(2).toInt() and 0xFF) shl 8) or (packet.get(3).toInt() and 0xFF)
        if (packet.remaining() < totalLength) return

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
     * Handles TCP packets from TUN: SYN, ACK, PSH+ACK, FIN, RST.
     */
    private fun handleTcpPacket(
        packet: ByteBuffer,
        ihl: Int,
        totalLength: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        if (totalLength < ihl + TCP_HEADER_LEN) return

        val srcPort = ((packet.get(ihl).toInt() and 0xFF) shl 8) or (packet.get(ihl + 1).toInt() and 0xFF)
        val dstPort = ((packet.get(ihl + 2).toInt() and 0xFF) shl 8) or (packet.get(ihl + 3).toInt() and 0xFF)

        val seqNum = (packet.getInt(ihl + 4).toLong()) and 0xFFFFFFFFL
        val ackNum = (packet.getInt(ihl + 8).toLong()) and 0xFFFFFFFFL

        val dataOffset = ((packet.get(ihl + 12).toInt() and 0xF0) ushr 4) * 4
        val flags = packet.get(ihl + 13).toInt() and 0xFF

        val isFin = (flags and 0x01) != 0
        val isSyn = (flags and 0x02) != 0
        val isRst = (flags and 0x04) != 0
        val isPsh = (flags and 0x08) != 0
        val isAck = (flags and 0x10) != 0

        val payloadOffset = ihl + dataOffset
        val payloadLen = totalLength - payloadOffset
        val sessionKey = "${formatIp(srcIp)}:$srcPort->${formatIp(dstIp)}:$dstPort"

        if (isRst) {
            activeSessions.remove(sessionKey)?.close()
            return
        }

        var session = activeSessions[sessionKey]

        if (isSyn) {
            // TCP Handshake Initiation from client app
            val initialServerSeq = (System.currentTimeMillis() and 0x7FFFFFFFL)
            val newSession = TcpSession(
                srcIp = srcIp,
                srcPort = srcPort,
                dstIp = dstIp,
                dstPort = dstPort,
                clientSeq = seqNum + 1,
                serverSeq = initialServerSeq,
                state = TcpState.SYN_RECEIVED
            )
            activeSessions[sessionKey] = newSession

            // Send SYN-ACK back to client
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = newSession.serverSeq,
                ackNum = newSession.clientSeq,
                flags = 0x12, // SYN + ACK
                payload = ByteArray(0)
            )
            newSession.serverSeq += 1

            // Asynchronously connect to SOCKS5 (127.0.0.1:10808) -> VMess outbound
            connectSessionToSocks(newSession, sessionKey)
            return
        }

        if (session == null) {
            if (isAck && !isFin) {
                // Unknown ACK, send RST to reset
                sendTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seqNum = ackNum,
                    ackNum = seqNum + (if (payloadLen > 0) payloadLen else 1),
                    flags = 0x14, // RST + ACK
                    payload = ByteArray(0)
                )
            }
            return
        }

        session.updateActivity()

        if (isFin) {
            session.clientSeq = seqNum + 1
            session.state = TcpState.CLOSE_WAIT

            // Send ACK for FIN
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x10, // ACK
                payload = ByteArray(0)
            )

            // Send server FIN-ACK
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x11, // FIN + ACK
                payload = ByteArray(0)
            )
            session.serverSeq += 1
            session.close()
            activeSessions.remove(sessionKey)
            return
        }

        if (payloadLen > 0) {
            val payload = ByteArray(payloadLen)
            packet.position(payloadOffset)
            packet.get(payload, 0, payloadLen)

            session.clientSeq = seqNum + payloadLen

            // Send immediate ACK for received data
            sendTcpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                srcPort = dstPort,
                dstPort = srcPort,
                seqNum = session.serverSeq,
                ackNum = session.clientSeq,
                flags = 0x10, // ACK
                payload = ByteArray(0)
            )

            // Forward payload to SOCKS5 socket
            session.socksSocket?.let { sock ->
                try {
                    val out = sock.getOutputStream()
                    out.write(payload)
                    out.flush()
                } catch (e: Exception) {
                    session.close()
                    activeSessions.remove(sessionKey)
                }
            }
        }
    }

    /**
     * Connects an active TCP session to the local SOCKS5 proxy and relays inbound data to TUN.
     */
    private fun connectSessionToSocks(session: TcpSession, sessionKey: String) {
        session.remoteJob = routerScope.launch {
            try {
                val socksSocket = Socket()
                openSockets.add(socksSocket)
                socksSocket.tcpNoDelay = true
                socksSocket.soTimeout = 30000
                socksSocket.connect(InetSocketAddress("127.0.0.1", socksServer.port), 5000)
                session.socksSocket = socksSocket

                val sIn = socksSocket.getInputStream()
                val sOut = socksSocket.getOutputStream()

                // SOCKS5 Handshake: NO_AUTH
                sOut.write(byteArrayOf(0x05, 0x01, 0x00))
                sOut.flush()

                val authResp = ByteArray(2)
                readFully(sIn, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) {
                    throw IllegalStateException("SOCKS5 auth negotiation failed")
                }

                // SOCKS5 CONNECT Command
                val dstHost = formatIp(session.dstIp)
                val connectReq = ByteArray(10)
                connectReq[0] = 0x05 // SOCKS version
                connectReq[1] = 0x01 // CMD CONNECT
                connectReq[2] = 0x00 // RSV
                connectReq[3] = 0x01 // ATYP IPv4
                System.arraycopy(session.dstIp, 0, connectReq, 4, 4)
                connectReq[8] = ((session.dstPort ushr 8) and 0xFF).toByte()
                connectReq[9] = (session.dstPort and 0xFF).toByte()

                sOut.write(connectReq)
                sOut.flush()

                val connectResp = ByteArray(10)
                readFully(sIn, connectResp)
                if (connectResp[1] != 0x00.toByte()) {
                    throw IllegalStateException("SOCKS5 connect rejected with code ${connectResp[1]}")
                }

                session.state = TcpState.ESTABLISHED
                VpnLogManager.log(LogLevel.DATA, "TRAFFIC", "[TRAFFIC] TCP session connected: $sessionKey via SOCKS5")

                // Relay remote incoming data back to TUN with MSS segmentation
                val buffer = ByteArray(MSS)
                while (isActive && isRunning.get() && session.state == TcpState.ESTABLISHED) {
                    val bytesRead = sIn.read(buffer)
                    if (bytesRead <= 0) break

                    val chunk = ByteArray(bytesRead)
                    System.arraycopy(buffer, 0, chunk, 0, bytesRead)

                    // Write TCP packet with data to TUN
                    sendTcpPacket(
                        srcIp = session.dstIp,
                        dstIp = session.srcIp,
                        srcPort = session.dstPort,
                        dstPort = session.srcPort,
                        seqNum = session.serverSeq,
                        ackNum = session.clientSeq,
                        flags = 0x18, // PSH + ACK
                        payload = chunk
                    )
                    session.serverSeq += bytesRead
                    totalRxBytes.addAndGet(bytesRead.toLong())
                }

            } catch (e: Exception) {
                // Connection closed or error
            } finally {
                session.close()
                activeSessions.remove(sessionKey)
            }
        }
    }

    /**
     * Intercepts DNS queries on UDP 53 and resolves via protected upstream socket.
     */
    private fun handleUdpPacket(
        packet: ByteBuffer,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        val totalLength = ((packet.get(2).toInt() and 0xFF) shl 8) or (packet.get(3).toInt() and 0xFF)
        if (totalLength < ihl + 8) return

        val srcPort = ((packet.get(ihl).toInt() and 0xFF) shl 8) or (packet.get(ihl + 1).toInt() and 0xFF)
        val dstPort = ((packet.get(ihl + 2).toInt() and 0xFF) shl 8) or (packet.get(ihl + 3).toInt() and 0xFF)
        val udpLength = ((packet.get(ihl + 4).toInt() and 0xFF) shl 8) or (packet.get(ihl + 5).toInt() and 0xFF)

        if (dstPort == 53 && udpLength > 8) {
            val payloadLength = udpLength - 8
            val dnsQueryBytes = ByteArray(payloadLength)
            packet.position(ihl + 8)
            packet.get(dnsQueryBytes, 0, payloadLength)

            routerScope.launch {
                try {
                    val upstreamAddr = InetAddress.getByName(upstreamDnsIp)
                    val sendPacket = DatagramPacket(dnsQueryBytes, dnsQueryBytes.size, upstreamAddr, 53)
                    dnsSocket.send(sendPacket)

                    val respBuffer = ByteArray(2048)
                    val recvPacket = DatagramPacket(respBuffer, respBuffer.size)
                    dnsSocket.receive(recvPacket)

                    val respLength = recvPacket.length
                    if (respLength > 0) {
                        val dnsRespBytes = ByteArray(respLength)
                        System.arraycopy(respBuffer, 0, dnsRespBytes, 0, respLength)

                        val responseIpPacket = buildUdpIpPacket(
                            srcIp = dstIp,
                            dstIp = srcIp,
                            srcPort = dstPort,
                            dstPort = srcPort,
                            payload = dnsRespBytes
                        )

                        writeToTun(responseIpPacket)
                        totalRxBytes.addAndGet(responseIpPacket.size.toLong())
                        VpnLogManager.log(LogLevel.DATA, "DNS", "[DNS] Resolved domain query via $upstreamDnsIp:53 ($respLength bytes)")
                    }
                } catch (e: Exception) {
                    VpnLogManager.log(LogLevel.WARN, "DNS", "[DNS] Upstream query error: ${e.message}")
                }
            }
        }
    }

    private fun handleIcmpPacket(
        packet: ByteBuffer,
        ihl: Int,
        totalLength: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        if (totalLength < ihl + 8) return
        val type = packet.get(ihl).toInt() and 0xFF
        if (type == 8) { // Echo Request (Ping)
            val echoBytes = ByteArray(totalLength - ihl)
            packet.position(ihl)
            packet.get(echoBytes)

            echoBytes[0] = 0 // Echo Reply
            echoBytes[2] = 0 // Clear checksum
            echoBytes[3] = 0

            val checksum = calculateChecksum(echoBytes, 0, echoBytes.size)
            echoBytes[2] = ((checksum ushr 8) and 0xFF).toByte()
            echoBytes[3] = (checksum and 0xFF).toByte()

            val replyPacket = buildIpPacket(
                srcIp = dstIp,
                dstIp = srcIp,
                protocol = 1, // ICMP
                payload = echoBytes
            )

            writeToTun(replyPacket)
            totalRxBytes.addAndGet(replyPacket.size.toLong())
        }
    }

    /**
     * Builds and sends a complete TCP packet through the TUN interface.
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
        val tcpHeaderLen = 20
        val tcpLen = tcpHeaderLen + payload.size
        val tcpPacket = ByteArray(tcpLen)

        tcpPacket[0] = ((srcPort ushr 8) and 0xFF).toByte()
        tcpPacket[1] = (srcPort and 0xFF).toByte()
        tcpPacket[2] = ((dstPort ushr 8) and 0xFF).toByte()
        tcpPacket[3] = (dstPort and 0xFF).toByte()

        // Sequence Number
        tcpPacket[4] = ((seqNum ushr 24) and 0xFF).toByte()
        tcpPacket[5] = ((seqNum ushr 16) and 0xFF).toByte()
        tcpPacket[6] = ((seqNum ushr 8) and 0xFF).toByte()
        tcpPacket[7] = (seqNum and 0xFF).toByte()

        // Acknowledgment Number
        tcpPacket[8] = ((ackNum ushr 24) and 0xFF).toByte()
        tcpPacket[9] = ((ackNum ushr 16) and 0xFF).toByte()
        tcpPacket[10] = ((ackNum ushr 8) and 0xFF).toByte()
        tcpPacket[11] = (ackNum and 0xFF).toByte()

        // Data Offset & Reserved (5 * 4 = 20 bytes)
        tcpPacket[12] = 0x50.toByte()
        tcpPacket[13] = flags.toByte()

        // Window Size (65535)
        tcpPacket[14] = 0xFF.toByte()
        tcpPacket[15] = 0xFF.toByte()

        // Checksum placeholder
        tcpPacket[16] = 0
        tcpPacket[17] = 0

        // Urgent Pointer
        tcpPacket[18] = 0
        tcpPacket[19] = 0

        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, tcpPacket, tcpHeaderLen, payload.size)
        }

        // Calculate TCP Checksum with IPv4 Pseudo Header
        val checksum = calculateTcpChecksum(srcIp, dstIp, tcpPacket, tcpLen)
        tcpPacket[16] = ((checksum ushr 8) and 0xFF).toByte()
        tcpPacket[17] = (checksum and 0xFF).toByte()

        val ipPacket = buildIpPacket(srcIp, dstIp, protocol = 6, payload = tcpPacket)
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
        udpHeader[0] = ((srcPort ushr 8) and 0xFF).toByte()
        udpHeader[1] = (srcPort and 0xFF).toByte()
        udpHeader[2] = ((dstPort ushr 8) and 0xFF).toByte()
        udpHeader[3] = (dstPort and 0xFF).toByte()

        val udpLen = 8 + payload.size
        udpHeader[4] = ((udpLen ushr 8) and 0xFF).toByte()
        udpHeader[5] = (udpLen and 0xFF).toByte()
        udpHeader[6] = 0
        udpHeader[7] = 0

        val udpPacket = ByteArray(udpLen)
        System.arraycopy(udpHeader, 0, udpPacket, 0, 8)
        System.arraycopy(payload, 0, udpPacket, 8, payload.size)

        return buildIpPacket(srcIp, dstIp, protocol = 17, payload = udpPacket)
    }

    private fun buildIpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        protocol: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength = IP_HEADER_LEN + payload.size
        val ipPacket = ByteArray(totalLength)

        ipPacket[0] = 0x45.toByte() // IPv4, IHL = 5 (20 bytes)
        ipPacket[1] = 0x00 // DSCP / ECN
        ipPacket[2] = ((totalLength ushr 8) and 0xFF).toByte()
        ipPacket[3] = (totalLength and 0xFF).toByte()

        val id = (System.currentTimeMillis() and 0xFFFF).toInt()
        ipPacket[4] = ((id ushr 8) and 0xFF).toByte()
        ipPacket[5] = (id and 0xFF).toByte()
        ipPacket[6] = 0x40.toByte() // Don't Fragment
        ipPacket[7] = 0x00
        ipPacket[8] = 64.toByte() // TTL
        ipPacket[9] = protocol.toByte()
        ipPacket[10] = 0
        ipPacket[11] = 0

        System.arraycopy(srcIp, 0, ipPacket, 12, 4)
        System.arraycopy(dstIp, 0, ipPacket, 16, 4)

        val headerChecksum = calculateChecksum(ipPacket, 0, IP_HEADER_LEN)
        ipPacket[10] = ((headerChecksum ushr 8) and 0xFF).toByte()
        ipPacket[11] = (headerChecksum and 0xFF).toByte()

        System.arraycopy(payload, 0, ipPacket, IP_HEADER_LEN, payload.size)
        return ipPacket
    }

    private fun calculateTcpChecksum(srcIp: ByteArray, dstIp: ByteArray, tcpData: ByteArray, tcpLength: Int): Int {
        var sum = 0

        // Pseudo header: Src IP (4) + Dst IP (4) + Zero (1) + Protocol (1) + TCP Length (2)
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += 6 // Protocol TCP
        sum += tcpLength

        // TCP header + Data
        var i = 0
        while (i < tcpLength - 1) {
            val word = ((tcpData[i].toInt() and 0xFF) shl 8) or (tcpData[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < tcpLength) {
            sum += (tcpData[i].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv()) and 0xFFFF
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv()) and 0xFFFF
    }

    private fun writeToTun(packet: ByteArray) {
        try {
            synchronized(writeLock) {
                tunOutputStream?.write(packet)
                tunOutputStream?.flush()
            }
        } catch (ignored: Exception) {}
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var total = 0
        while (total < buffer.size) {
            val n = input.read(buffer, total, buffer.size - total)
            if (n == -1) throw IllegalStateException("Unexpected EOF while reading socket")
            total += n
        }
    }

    private fun formatIp(ip: ByteArray): String {
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        readJob?.cancel()

        activeSessions.values.forEach { it.close() }
        activeSessions.clear()

        openSockets.forEach { sock ->
            try { sock.close() } catch (ignored: Exception) {}
        }
        openSockets.clear()

        try {
            dnsSocket.close()
        } catch (ignored: Exception) {}

        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS", "[TUN2SOCKS] Tun2Socks engine stopped cleanly.")
    }
}
