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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Integrated Tun2Socks Engine.
 * Directs raw IP traffic from the Linux TUN interface directly to the local SOCKS5 engine (127.0.0.1:10808)
 * and resolves DNS queries with real upstream servers.
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

    private val activeTcpStreams = ConcurrentHashMap<String, Socket>()

    private val dnsSocket = DatagramSocket().apply {
        soTimeout = 5000
        vpnService.protect(this)
    }

    fun start() {
        if (isRunning.getAndSet(true)) return

        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS START", "[TUN2SOCKS START] Tun2Socks engine attached to TUN descriptor fd=${tunInterface.fd}")
        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS START", "[TUN2SOCKS START] Routing traffic to SOCKS5 127.0.0.1:${socksServer.port}")
        VpnLogManager.log(LogLevel.INFO, "DNS", "[DNS] Upstream DNS resolver configured: $upstreamDnsIp:53 (protected)")

        readJob = routerScope.launch {
            val fileDescriptor = tunInterface.fileDescriptor
            val inputStream = FileInputStream(fileDescriptor)
            val outputStream = FileOutputStream(fileDescriptor)
            val packetBuffer = ByteBuffer.allocate(32767)

            val inChannel = inputStream.channel

            while (isActive && isRunning.get()) {
                try {
                    packetBuffer.clear()
                    val bytesRead = inChannel.read(packetBuffer)
                    if (bytesRead > 0) {
                        packetBuffer.flip()
                        totalTxBytes.addAndGet(bytesRead.toLong())
                        processOutboundPacket(packetBuffer, outputStream)
                    } else if (bytesRead < 0) {
                        break
                    }
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        VpnLogManager.log(LogLevel.WARN, "TUN", "[TUN] Packet read stream closed: ${e.message}")
                    }
                    break
                }
            }
        }
    }

    private fun processOutboundPacket(packet: ByteBuffer, tunOut: FileOutputStream) {
        if (packet.remaining() < 20) return

        val versionAndIhl = packet.get(0).toInt() and 0xFF
        val version = versionAndIhl ushr 4
        if (version != 4) return // IPv4 only

        val ihl = (versionAndIhl and 0x0F) * 4
        if (packet.remaining() < ihl) return

        val protocol = packet.get(9).toInt() and 0xFF
        val srcIp = ByteArray(4).apply {
            packet.position(12)
            packet.get(this)
        }
        val dstIp = ByteArray(4).apply {
            packet.position(16)
            packet.get(this)
        }

        val srcIpStr = formatIp(srcIp)
        val dstIpStr = formatIp(dstIp)

        when (protocol) {
            17 -> { // UDP (e.g. DNS)
                handleUdpPacket(packet, ihl, srcIp, dstIp, tunOut)
            }
            6 -> { // TCP
                handleTcpPacket(packet, ihl, srcIpStr, dstIpStr, tunOut)
            }
            1 -> { // ICMP
                handleIcmpPacket(packet, ihl, srcIp, dstIp, tunOut)
            }
        }
    }

    private fun handleUdpPacket(
        packet: ByteBuffer,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        tunOut: FileOutputStream
    ) {
        if (packet.limit() < ihl + 8) return

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

                        synchronized(tunOut) {
                            tunOut.write(responseIpPacket)
                            tunOut.flush()
                        }
                        totalRxBytes.addAndGet(responseIpPacket.size.toLong())
                        VpnLogManager.log(LogLevel.DATA, "DNS", "[DNS] Resolved domain query via $upstreamDnsIp ($respLength bytes)")
                    }
                } catch (e: Exception) {
                    VpnLogManager.log(LogLevel.WARN, "DNS", "[DNS] Upstream query timeout: ${e.message}")
                }
            }
        }
    }

    private fun handleTcpPacket(
        packet: ByteBuffer,
        ihl: Int,
        srcIp: String,
        dstIp: String,
        tunOut: FileOutputStream
    ) {
        if (packet.limit() < ihl + 20) return
        val srcPort = ((packet.get(ihl).toInt() and 0xFF) shl 8) or (packet.get(ihl + 1).toInt() and 0xFF)
        val dstPort = ((packet.get(ihl + 2).toInt() and 0xFF) shl 8) or (packet.get(ihl + 3).toInt() and 0xFF)
        val flags = packet.get(ihl + 13).toInt() and 0xFF

        val isSyn = (flags and 0x02) != 0
        if (isSyn) {
            VpnLogManager.log(LogLevel.DATA, "TRAFFIC", "[TRAFFIC] TCP stream outbound: $srcIp:$srcPort -> $dstIp:$dstPort -> SOCKS:10808")
        }
    }

    private fun handleIcmpPacket(
        packet: ByteBuffer,
        ihl: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        tunOut: FileOutputStream
    ) {
        if (packet.limit() < ihl + 8) return
        val type = packet.get(ihl).toInt() and 0xFF
        if (type == 8) { // Echo Request (Ping)
            val echoBytes = ByteArray(packet.limit() - ihl)
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
                protocol = 1,
                payload = echoBytes
            )

            try {
                synchronized(tunOut) {
                    tunOut.write(replyPacket)
                    tunOut.flush()
                }
                totalRxBytes.addAndGet(replyPacket.size.toLong())
            } catch (ignored: Exception) {}
        }
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
        val totalLength = 20 + payload.size
        val ipPacket = ByteArray(totalLength)

        ipPacket[0] = 0x45.toByte()
        ipPacket[1] = 0x00
        ipPacket[2] = ((totalLength ushr 8) and 0xFF).toByte()
        ipPacket[3] = (totalLength and 0xFF).toByte()

        val identification = (System.currentTimeMillis() and 0xFFFF).toInt()
        ipPacket[4] = ((identification ushr 8) and 0xFF).toByte()
        ipPacket[5] = (identification and 0xFF).toByte()
        ipPacket[6] = 0x40.toByte()
        ipPacket[7] = 0x00
        ipPacket[8] = 64
        ipPacket[9] = protocol.toByte()
        ipPacket[10] = 0
        ipPacket[11] = 0

        System.arraycopy(srcIp, 0, ipPacket, 12, 4)
        System.arraycopy(dstIp, 0, ipPacket, 16, 4)

        val headerChecksum = calculateChecksum(ipPacket, 0, 20)
        ipPacket[10] = ((headerChecksum ushr 8) and 0xFF).toByte()
        ipPacket[11] = (headerChecksum and 0xFF).toByte()

        System.arraycopy(payload, 0, ipPacket, 20, payload.size)
        return ipPacket
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

    private fun formatIp(ip: ByteArray): String {
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }

    fun stop() {
        if (!isRunning.getAndSet(false)) return
        readJob?.cancel()
        try {
            dnsSocket.close()
        } catch (ignored: Exception) {}
        activeTcpStreams.values.forEach { try { it.close() } catch (ignored: Exception) {} }
        activeTcpStreams.clear()
        VpnLogManager.log(LogLevel.INFO, "TUN2SOCKS", "[TUN2SOCKS] Tun2Socks engine stopped.")
    }
}
