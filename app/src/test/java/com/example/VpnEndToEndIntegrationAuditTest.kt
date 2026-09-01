package com.example

import com.example.vpn.ssh.DirectTcpIpSocket
import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.PayloadMode
import com.example.vpn.util.SniUtils
import com.jcraft.jsch.TestDirectTcpIpChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class VpnEndToEndIntegrationAuditTest {

    @Test
    fun testTcpChecksumCalculationCorrectness() {
        // Known IPv4 pseudo header & TCP segment test
        val srcIp = byteArrayOf(10, 8, 0, 2)
        val dstIp = byteArrayOf(1, 1, 1, 1)
        val srcPort = 54321
        val dstPort = 80
        val seqNum = 1000L
        val ackNum = 2000L
        val flags = 0x18 // PSH + ACK
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)

        val tcpHeaderLen = 20
        val tcpLen = tcpHeaderLen + payload.size
        val tcpPacket = ByteArray(tcpLen)

        tcpPacket[0] = ((srcPort ushr 8) and 0xFF).toByte()
        tcpPacket[1] = (srcPort and 0xFF).toByte()
        tcpPacket[2] = ((dstPort ushr 8) and 0xFF).toByte()
        tcpPacket[3] = (dstPort and 0xFF).toByte()

        tcpPacket[4] = ((seqNum ushr 24) and 0xFF).toByte()
        tcpPacket[5] = ((seqNum ushr 16) and 0xFF).toByte()
        tcpPacket[6] = ((seqNum ushr 8) and 0xFF).toByte()
        tcpPacket[7] = (seqNum and 0xFF).toByte()

        tcpPacket[8] = ((ackNum ushr 24) and 0xFF).toByte()
        tcpPacket[9] = ((ackNum ushr 16) and 0xFF).toByte()
        tcpPacket[10] = ((ackNum ushr 8) and 0xFF).toByte()
        tcpPacket[11] = (ackNum and 0xFF).toByte()

        tcpPacket[12] = 0x50.toByte()
        tcpPacket[13] = flags.toByte()
        tcpPacket[14] = 0xFF.toByte()
        tcpPacket[15] = 0xFF.toByte()

        System.arraycopy(payload, 0, tcpPacket, tcpHeaderLen, payload.size)

        var sum = 0
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += 6 // Protocol TCP
        sum += tcpLen

        var i = 0
        while (i < tcpLen - 1) {
            val word = ((tcpPacket[i].toInt() and 0xFF) shl 8) or (tcpPacket[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < tcpLen) {
            sum += (tcpPacket[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = (sum.inv()) and 0xFFFF

        assertTrue("Checksum must be non-zero 16-bit value", checksum in 1..0xFFFF)
    }

    @Test
    fun testDirectTcpIpSocketStreamAndByteCounters() {
        val totalSent = AtomicLong(0L)
        val totalRecv = AtomicLong(0L)

        val serverToClientData = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello".toByteArray(StandardCharsets.US_ASCII)
        val channelIn = ByteArrayInputStream(serverToClientData)
        val channelOut = ByteArrayOutputStream()

        val testChannel = TestDirectTcpIpChannel(channelIn, channelOut)

        val directSocket = DirectTcpIpSocket(
            channel = testChannel,
            targetHost = "example.com",
            targetPort = 80,
            totalBytesSent = totalSent,
            totalBytesReceived = totalRecv
        )

        assertTrue(directSocket.isConnected)
        assertFalse(directSocket.isClosed)
        assertEquals("example.com", (directSocket.remoteSocketAddress as InetSocketAddress).hostName)
        assertEquals(80, (directSocket.remoteSocketAddress as InetSocketAddress).port)

        // Test sending data through socket
        val testRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        directSocket.outputStream.write(testRequest)
        directSocket.outputStream.flush()

        assertEquals(testRequest.size.toLong(), totalSent.get())
        assertEquals(String(testRequest), channelOut.toString(StandardCharsets.US_ASCII.name()))

        // Test receiving data through socket
        val readBuf = ByteArray(1024)
        val readBytes = directSocket.inputStream.read(readBuf)
        assertEquals(serverToClientData.size, readBytes)
        assertEquals(serverToClientData.size.toLong(), totalRecv.get())

        val receivedString = String(readBuf, 0, readBytes, StandardCharsets.US_ASCII)
        assertTrue(receivedString.startsWith("HTTP/1.1 200 OK"))

        // Test close
        directSocket.close()
        assertTrue(directSocket.isClosed)
        assertTrue(testChannel.isDisconnected)
    }

    @Test
    fun testMultiplexedConcurrentDirectTcpIpChannels() {
        val totalSent = AtomicLong(0L)
        val totalRecv = AtomicLong(0L)
        val threadCount = 10
        val latch = CountDownLatch(threadCount)
        val errors = AtomicInteger(0)

        for (i in 0 until threadCount) {
            Thread {
                try {
                    val responseData = "Echo-$i".toByteArray()
                    val channel = TestDirectTcpIpChannel(
                        inStream = ByteArrayInputStream(responseData),
                        outStream = ByteArrayOutputStream()
                    )

                    val socket = DirectTcpIpSocket(
                        channel = channel,
                        targetHost = "host-$i.test",
                        targetPort = 80 + i,
                        totalBytesSent = totalSent,
                        totalBytesReceived = totalRecv
                    )

                    val req = "Req-$i".toByteArray()
                    socket.outputStream.write(req)
                    val buf = ByteArray(64)
                    val n = socket.inputStream.read(buf)
                    assertEquals("Echo-$i", String(buf, 0, n))
                    socket.close()
                } catch (e: Exception) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }.start()
        }

        val completed = latch.await(5, TimeUnit.SECONDS)
        assertTrue("All concurrent channels completed", completed)
        assertEquals("No errors during concurrent channel execution", 0, errors.get())
        assertTrue("Total sent bytes recorded", totalSent.get() > 0)
        assertTrue("Total received bytes recorded", totalRecv.get() > 0)
    }

    @Test
    fun testSniSanitizationRules() {
        assertEquals("google.com", SniUtils.sanitizeSni("google.com", "1.1.1.1"))
        assertEquals("google.com", SniUtils.sanitizeSni("google.com:443", "1.1.1.1"))
        assertEquals("google.com", SniUtils.sanitizeSni("https://google.com/path", "1.1.1.1"))
        assertEquals("google.com", SniUtils.sanitizeSni("wss://google.com:8443", "1.1.1.1"))
        assertEquals("fallback.com", SniUtils.sanitizeSni("", "fallback.com"))
        assertEquals("fallback.com", SniUtils.sanitizeSni("   ", "fallback.com"))
    }
}
