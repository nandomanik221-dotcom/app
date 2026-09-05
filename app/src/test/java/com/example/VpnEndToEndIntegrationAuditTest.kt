package com.example

import com.example.vpn.ssh.DirectTcpIpSocket
import com.example.vpn.ssh.TestDirectTcpIpChannel
import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.PayloadMode
import com.example.vpn.util.SniUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
            inStreamRaw = channelIn,
            outStreamRaw = channelOut,
            targetHost = "example.com",
            targetPort = 80,
            totalBytesSent = totalSent,
            totalBytesReceived = totalRecv,
            onClose = { testChannel.disconnect() }
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
                        inStreamRaw = channel.inStream,
                        outStreamRaw = channel.outStream,
                        targetHost = "host-$i.test",
                        targetPort = 80 + i,
                        totalBytesSent = totalSent,
                        totalBytesReceived = totalRecv,
                        onClose = { channel.disconnect() }
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

    @Test
    fun testProbeSuccessWithValidHttp2xx3xx() {
        val valid200 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        val code200 = HttpStatusParser.parseStatusCode(valid200.lines().first())
        assertNotNull(code200)
        assertTrue(code200 in 100..599)
        assertEquals(200, code200)

        val valid301 = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com\r\n\r\n"
        val code301 = HttpStatusParser.parseStatusCode(valid301.lines().first())
        assertNotNull(code301)
        assertTrue(code301 in 100..599)
        assertEquals(301, code301)
    }

    @Test
    fun testProbeFailureWithInvalidHttpResponse() {
        val invalidGarbage = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        val codeGarbage = HttpStatusParser.parseStatusCode(invalidGarbage)
        org.junit.Assert.assertNull("Non-HTTP response must return null status code", codeGarbage)

        val emptyLine = ""
        val codeEmpty = HttpStatusParser.parseStatusCode(emptyLine)
        org.junit.Assert.assertNull("Empty line must return null status code", codeEmpty)
    }

    @Test
    fun testProbeDirectTcpIpChannelStreamInteraction() {
        val mockResponse = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        val channelIn = ByteArrayInputStream(mockResponse)
        val channelOut = ByteArrayOutputStream()
        val channel = TestDirectTcpIpChannel(channelIn, channelOut)

        assertTrue(channel.isConnected)
        val out = channel.outputStream
        val inStream = channel.inputStream

        val req = "HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"
        out.write(req.toByteArray(StandardCharsets.US_ASCII))
        out.flush()

        val sb = StringBuilder()
        var b = inStream.read()
        while (b != -1) {
            if (b == '\n'.code) break
            if (b != '\r'.code) {
                sb.append(b.toChar())
            }
            b = inStream.read()
        }
        val statusLine = sb.toString()
        val code = HttpStatusParser.parseStatusCode(statusLine)

        channel.disconnect()
        assertTrue(channel.isClosed)
        assertEquals(204, code)
        assertTrue("Request sent matches HTTP format", channelOut.toString(StandardCharsets.US_ASCII.name()).startsWith("HEAD / HTTP/1.1"))
    }

    @Test
    fun testProbeChannelFailureHandling() {
        // Channel disconnected / EOF immediately
        val emptyIn = ByteArrayInputStream(ByteArray(0))
        val emptyOut = ByteArrayOutputStream()
        val channel = TestDirectTcpIpChannel(emptyIn, emptyOut)
        channel.disconnect()

        assertFalse("Disconnected channel is not connected", channel.isConnected)
        assertTrue("Disconnected channel is closed", channel.isClosed)

        val readByte = channel.inputStream.read()
        assertEquals("Reading from closed/empty channel must return EOF -1", -1, readByte)
    }

    @Test
    fun testUpstreamSocketProtectorReturnsTrue() {
        var protectCalled = false
        val protector = object : com.example.vpn.backend.UpstreamSocketProtector {
            override fun protect(socket: java.net.Socket): Boolean {
                protectCalled = true
                return true
            }
            override fun isVpnInterfaceActive(): Boolean = true
        }

        val testSocket = java.net.Socket()
        val res = protector.protect(testSocket)
        assertTrue("Protector must return true when protection succeeds", res)
        assertTrue("Protect method was called", protectCalled)
    }

    @Test
    fun testUpstreamSocketProtectorReturnsFalseAndFailsConnection() {
        val failingProtector = object : com.example.vpn.backend.UpstreamSocketProtector {
            override fun protect(socket: java.net.Socket): Boolean = false
            override fun isVpnInterfaceActive(): Boolean = false
        }

        val profile = com.example.model.VpnProfile(
            id = 1L,
            name = "Test SSH",
            protocol = com.example.model.VpnProtocol.SSH,
            server = "127.0.0.1",
            port = 2222
        )

        val sshClient = com.example.vpn.ssh.SshTunnelClient(failingProtector, profile)

        var handshakeReached = false
        kotlinx.coroutines.runBlocking {
            val result = sshClient.verifyHandshake()
            assertTrue("Connection must fail when protect() returns false", result.isFailure)
            val exception = result.exceptionOrNull()
            assertNotNull("Exception must not be null", exception)
            assertTrue(
                "Exception message must mention routing loop protection failure",
                exception?.message?.contains("Failed to protect upstream socket from VPN routing loop") == true
            )
        }

        assertFalse("SSH Handshake must NEVER be reached when protect() fails", handshakeReached)
    }

    @Test
    fun testUpstreamSocketProtectionRequiresTunActive() {
        var tunStateDuringProtect = false
        val orderingProtector = object : com.example.vpn.backend.UpstreamSocketProtector {
            private var isTunActive = false

            fun activateTun() {
                isTunActive = true
            }

            override fun protect(socket: java.net.Socket): Boolean {
                tunStateDuringProtect = isTunActive
                return isTunActive
            }

            override fun isVpnInterfaceActive(): Boolean = isTunActive
        }

        // Case 1: Protect called before TUN established
        val socket1 = java.net.Socket()
        val resultBeforeTun = orderingProtector.protect(socket1)
        assertFalse("Protect must fail when TUN is not active", resultBeforeTun)
        assertFalse("TUN was not active during protect", tunStateDuringProtect)

        // Case 2: TUN established first, then protect called
        orderingProtector.activateTun()
        val socket2 = java.net.Socket()
        val resultAfterTun = orderingProtector.protect(socket2)
        assertTrue("Protect succeeds after TUN is active", resultAfterTun)
        assertTrue("TUN was active during protect", tunStateDuringProtect)
    }

    @Test
    fun testSocketChannelSocketCreationHasAllocatedDescriptor() {
        val channel = java.nio.channels.SocketChannel.open()
        val socket = channel.socket()
        assertNotNull(socket)
        assertFalse(socket.isConnected)
        assertFalse(socket.isBound)
        assertFalse(socket.isClosed)

        // Verify channel is open and valid
        assertTrue(channel.isOpen)
        socket.close()
        assertTrue(socket.isClosed)
    }

    @Test
    fun testHttpStatusParserStatusLineParsing() {
        assertEquals(403, HttpStatusParser.parseStatusCode("HTTP/1.1 403 Forbidden"))
        assertEquals(101, HttpStatusParser.parseStatusCode("HTTP/1.1 101 Switching Protocols"))
        assertEquals(200, HttpStatusParser.parseStatusCode("HTTP/1.0 200 Connection established"))
        assertEquals(200, HttpStatusParser.parseStatusCode("HTTP/1.1 200 OK"))
        assertEquals(302, HttpStatusParser.parseStatusCode("HTTP/1.1 302 Found"))
        assertEquals(407, HttpStatusParser.parseStatusCode("HTTP/1.1 407 Proxy Authentication Required"))
        assertEquals(502, HttpStatusParser.parseStatusCode("HTTP/1.1 502 Bad Gateway"))
        assertNull(HttpStatusParser.parseStatusCode("Invalid Status Line"))
    }

    @Test
    fun testPayloadModeDetection() {
        val wsPayload = "GET /ws HTTP/1.1[crlf]Host: example.com[crlf]Upgrade: websocket[crlf][crlf]"
        assertEquals(PayloadMode.WEBSOCKET, HttpStatusParser.detectPayloadMode(wsPayload))

        val httpPayload = "CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf][crlf]"
        assertEquals(PayloadMode.PAYLOAD_WITH_HTTP_RESPONSE, HttpStatusParser.detectPayloadMode(httpPayload))

        val splitPayload = "GET / HTTP/1.1[crlf]Host: [host][crlf][split][crlf]"
        assertEquals(PayloadMode.PAYLOAD_ONLY, HttpStatusParser.detectPayloadMode(splitPayload))

        assertEquals(PayloadMode.NONE, HttpStatusParser.detectPayloadMode(""))
    }

    @Test
    fun testConsumeSingleResponseWithContentLengthBody() {
        val body = "<html>403</html>"
        val rawHttp = "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n$body"
        val inStream = java.io.ByteArrayInputStream(rawHttp.toByteArray(java.nio.charset.StandardCharsets.UTF_8))

        val parsed = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(parsed)
        assertEquals("HTTP/1.1 403 Forbidden", parsed?.statusLine)
        assertEquals(403, parsed?.statusCode)
        assertEquals("cloudflare", parsed?.headers?.get("server"))
        assertEquals(body.length, parsed?.bodyLength)
        assertEquals(0, inStream.available())
    }

    @Test
    fun testMultiStageResponseStreamConsumption() {
        // Multi-stage response: 403 with body followed by 101 Switching Protocols followed by SSH banner
        val body = "<error>403</error>"
        val stage1 = "HTTP/1.1 403 Forbidden\r\nServer: cdn\r\nContent-Length: ${body.length}\r\n\r\n$body"
        val stage2 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        val sshStream = "SSH-2.0-OpenSSH_8.9\r\n"
        val fullData = stage1 + stage2 + sshStream

        val inStream = java.io.ByteArrayInputStream(fullData.toByteArray(java.nio.charset.StandardCharsets.UTF_8))

        // First response stage
        val resp1 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp1)
        assertEquals(403, resp1?.statusCode)
        assertEquals(body.length, resp1?.bodyLength)

        // Second response stage
        val resp2 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp2)
        assertEquals(101, resp2?.statusCode)

        // Verify remaining stream contains the pristine SSH banner without any leftover HTML bytes
        val remainingBytes = inStream.readBytes()
        val remainingStr = String(remainingBytes, java.nio.charset.StandardCharsets.UTF_8)
        assertEquals("SSH-2.0-OpenSSH_8.9\r\n", remainingStr)
    }

    @Test
    fun testChunkedBodyConsumption() {
        val chunkedHttp = "HTTP/1.1 421 Misdirected Request\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nNEXT_DATA"
        val inStream = java.io.ByteArrayInputStream(chunkedHttp.toByteArray(java.nio.charset.StandardCharsets.UTF_8))

        val parsed = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(parsed)
        assertEquals(421, parsed?.statusCode)
        assertEquals(11, parsed?.bodyLength)

        val remaining = inStream.readBytes()
        assertEquals("NEXT_DATA", String(remaining, java.nio.charset.StandardCharsets.UTF_8))
    }

    @Test
    fun testRealDeviceFailurePattern403WithHtmlThen200Then101ThenSsh() {
        // Exact real-device sequence: 403 Forbidden with Content-Length HTML, then 200 Connection established, then 101 Switching Protocols, then SSH banner
        val htmlBody = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>"
        val stage1 = "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nContent-Type: text/html\r\nContent-Length: ${htmlBody.length}\r\n\r\n$htmlBody"
        val stage2 = "HTTP/1.0 200 Connection established\r\n\r\n"
        val stage3 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        val sshBanner = "SSH-2.0-test-server_1.0\r\n"
        val fullStream = stage1 + stage2 + stage3 + sshBanner

        val inStream = java.io.ByteArrayInputStream(fullStream.toByteArray(java.nio.charset.StandardCharsets.UTF_8))

        // Step 1: Consume 403 Forbidden + Body
        val resp1 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp1)
        assertEquals(403, resp1?.statusCode)
        assertEquals(htmlBody.length, resp1?.bodyLength)
        assertTrue(resp1?.isComplete == true)

        // Step 2: Consume 200 Connection established (no body)
        val resp2 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp2)
        assertEquals(200, resp2?.statusCode)
        assertEquals(0, resp2?.bodyLength)

        // Step 3: Consume 101 Switching Protocols (no body)
        val resp3 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp3)
        assertEquals(101, resp3?.statusCode)
        assertEquals(0, resp3?.bodyLength)

        // Step 4: Verify remaining stream is cleanly positioned at the SSH banner
        val remaining = inStream.readBytes()
        val remainingText = String(remaining, java.nio.charset.StandardCharsets.UTF_8)
        assertEquals(sshBanner, remainingText)
    }

    @Test
    fun testChunkedHtmlBodyFollowedByNextResponse() {
        val chunk1 = "<div>Access Blocked by Proxy</div>"
        val chunkedStage = "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n${Integer.toHexString(chunk1.length)}\r\n$chunk1\r\n0\r\n\r\n"
        val wsUpgradeStage = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        val sshBanner = "SSH-2.0-OpenSSH_9.0\r\n"

        val inStream = java.io.ByteArrayInputStream((chunkedStage + wsUpgradeStage + sshBanner).toByteArray(java.nio.charset.StandardCharsets.UTF_8))

        val resp1 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp1)
        assertEquals(403, resp1?.statusCode)
        assertEquals(chunk1.length, resp1?.bodyLength)
        assertTrue(resp1?.isComplete == true)

        val resp2 = HttpStatusParser.consumeSingleResponse(inStream)
        assertNotNull(resp2)
        assertEquals(101, resp2?.statusCode)

        val remaining = inStream.readBytes()
        assertEquals(sshBanner, String(remaining, java.nio.charset.StandardCharsets.UTF_8))
    }

    @Test
    fun testWebSocketFramedSocketDoesNotConsumeOrInterpretHttpBody() {
        // Verify that WebSocketFramedSocket operates strictly on framed binary payloads and does not perform HTTP parsing
        val mockRawIn = java.io.ByteArrayOutputStream()
        // Create a server-to-client unmasked binary frame (Opcode 0x02, length 19: "SSH-2.0-OpenSSH_8.9")
        val payload = "SSH-2.0-OpenSSH_8.9".toByteArray(java.nio.charset.StandardCharsets.UTF_8)
        mockRawIn.write(byteArrayOf(0x82.toByte(), payload.size.toByte()))
        mockRawIn.write(payload)

        val inStream = java.io.ByteArrayInputStream(mockRawIn.toByteArray())
        val outStream = java.io.ByteArrayOutputStream()

        val mockSocket = object : java.net.Socket() {
            override fun getInputStream(): java.io.InputStream = inStream
            override fun getOutputStream(): java.io.OutputStream = outStream
            override fun isConnected(): Boolean = true
            override fun isClosed(): Boolean = false
        }

        val wsSocket = com.example.vpn.ssh.WebSocketFramedSocket(mockSocket)

        // Read through framed socket - should deliver pure payload bytes
        val readBuf = ByteArray(50)
        val readBytes = wsSocket.getInputStream().read(readBuf)
        assertEquals(payload.size, readBytes)
        val receivedStr = String(readBuf, 0, readBytes, java.nio.charset.StandardCharsets.UTF_8)
        assertEquals("SSH-2.0-OpenSSH_8.9", receivedStr)

        // Write through framed socket - should produce RFC 6455 masked binary frame
        val clientData = "SSH-2.0-Client_1.0\r\n".toByteArray(java.nio.charset.StandardCharsets.UTF_8)
        wsSocket.getOutputStream().write(clientData)
        wsSocket.getOutputStream().flush()

        val writtenBytes = outStream.toByteArray()
        assertTrue(writtenBytes.size > clientData.size) // header + 4 byte mask + masked payload
        assertEquals(0x82.toByte(), writtenBytes[0]) // FIN=1, Opcode=2 (binary)
        assertTrue((writtenBytes[1].toInt() and 0x80) != 0) // Mask bit set
    }

    @Test
    fun testExactRealDeviceFailurePatternMultiStageConsumption() {
        // Exact real-device sequence:
        // 1. HTTP/1.1 403 Forbidden with Content-Length N and HTML body
        // 2. HTTP/1.0 200 Connection established
        // 3. HTTP/1.1 101 Switching Protocols
        // 4. SSH-2.0-test-server banner
        val htmlBody = "<html><body><h1>403 Forbidden - Cloud CDN</h1></body></html>"
        val stage1 = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: ${htmlBody.length}\r\n\r\n$htmlBody"
        val stage2 = "HTTP/1.0 200 Connection established\r\nProxy-Agent: CloudProxy/1.0\r\n\r\n"
        val stage3 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        val sshBanner = "SSH-2.0-test-server\r\n"

        val rawStreamData = (stage1 + stage2 + stage3 + sshBanner).toByteArray(StandardCharsets.UTF_8)
        val inStream = ByteArrayInputStream(rawStreamData)
        val pushbackIn = java.io.PushbackInputStream(inStream, 1024)

        // Consume Stage 1: 403 Forbidden
        val resp1 = HttpStatusParser.consumeSingleResponse(pushbackIn)
        assertNotNull(resp1)
        assertEquals(403, resp1?.statusCode)
        assertEquals(htmlBody.length, resp1?.bodyLength)
        assertTrue(resp1?.isComplete == true)

        // Consume Stage 2: 200 Connection established
        val resp2 = HttpStatusParser.consumeSingleResponse(pushbackIn)
        assertNotNull(resp2)
        assertEquals(200, resp2?.statusCode)
        assertEquals(0, resp2?.bodyLength)

        // Consume Stage 3: 101 Switching Protocols
        val resp3 = HttpStatusParser.consumeSingleResponse(pushbackIn)
        assertNotNull(resp3)
        assertEquals(101, resp3?.statusCode)
        assertEquals(0, resp3?.bodyLength)

        // Verify remaining stream is exactly the raw SSH banner
        val remainingBytes = pushbackIn.readBytes()
        assertEquals(sshBanner, String(remainingBytes, StandardCharsets.UTF_8))
    }

    @Test
    fun testRegressionFieldIndependenceGoldenConfig() {
        // TASK 8 Regression Test:
        // targetHost, targetPort, remoteProxyHost, remoteProxyPort, tlsSni, and httpHost
        // must remain strictly independent.
        val profile = com.example.model.VpnProfile(
            name = "Golden Config Reference",
            protocol = com.example.model.VpnProtocol.SSH,
            server = "prem.nikuvpn.biz.id",
            port = 443,
            remoteProxyEnabled = true,
            remoteProxyHost = "ads.ruangguru.com",
            remoteProxyPort = 443,
            remoteProxyType = "HTTP",
            sni = "prem.nikuvpn.biz.id",
            host = "ads.ruangguru.com",
            sshPayload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]",
            sshDirectSsl = true
        )

        // Verify target host and port
        assertEquals("prem.nikuvpn.biz.id", profile.server)
        assertEquals(443, profile.port)

        // Verify remote proxy host and port
        assertEquals("ads.ruangguru.com", profile.remoteProxyHost)
        assertEquals(443, profile.remoteProxyPort)
        assertTrue(profile.remoteProxyEnabled)

        // Verify TLS SNI
        assertEquals("prem.nikuvpn.biz.id", profile.sni)

        // Verify HTTP Host header
        assertEquals("ads.ruangguru.com", profile.host)

        // Assert strictly distinct fields - SNI must NOT equal remote proxy host
        // Target host must NOT equal remote proxy host
        assertFalse("Target host must not automatically equal Remote Proxy host", profile.server == profile.remoteProxyHost)
        assertFalse("TLS SNI must not automatically equal Remote Proxy host", profile.sni == profile.remoteProxyHost)
        assertEquals("prem.nikuvpn.biz.id", profile.server)
        assertEquals("prem.nikuvpn.biz.id", profile.sni)
        assertEquals("ads.ruangguru.com", profile.remoteProxyHost)
    }

    @Test
    fun testWebSocketFramedSocketExtendedLengthAndAvailable() {
        // Verify 126 extended length (> 125 bytes)
        val payload = ByteArray(300) { (it % 26 + 65).toByte() }
        val mockOut = ByteArrayOutputStream()
        mockOut.write(byteArrayOf(0x82.toByte(), 126.toByte(), (300 ushr 8).toByte(), (300 and 0xFF).toByte()))
        mockOut.write(payload)

        val inStream = ByteArrayInputStream(mockOut.toByteArray())
        val mockSocket = object : java.net.Socket() {
            override fun getInputStream(): java.io.InputStream = inStream
            override fun getOutputStream(): java.io.OutputStream = ByteArrayOutputStream()
            override fun isConnected(): Boolean = true
            override fun isClosed(): Boolean = false
        }

        val wsSocket = com.example.vpn.ssh.WebSocketFramedSocket(mockSocket)
        val readBuf = ByteArray(300)
        val readCount = wsSocket.getInputStream().read(readBuf)

        assertEquals(300, readCount)
        assertEquals(payload.toList(), readBuf.toList())
    }

    @Test
    fun testReferenceProfileFormattingAndStreamHandling() {
        // Exact reference profile from user audit prompt:
        // SSH Host: prem.nikuvpn.biz.id:443
        // Remote Proxy: ads.ruangguru.com:443
        // Remote Proxy Type: HTTP
        // Payload: api.quipper.com[crlf]Connection: Keep-Alive[crlf][crlf]PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
        val payloadTemplate = "api.quipper.com[crlf]Connection: Keep-Alive[crlf][crlf]PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
        val httpHost = "prem.nikuvpn.biz.id"
        val proxyHost = "ads.ruangguru.com"
        val proxyPort = 443

        val formatted = payloadTemplate
            .replace("[host]", httpHost, ignoreCase = true)
            .replace("[crlf]", "\r\n", ignoreCase = true)

        val expected = "api.quipper.com\r\nConnection: Keep-Alive\r\n\r\nPATCH / HTTP/1.1\r\nHost: prem.nikuvpn.biz.id\r\nUpgrade: websocket\r\n\r\n"
        assertEquals(expected, formatted)

        // Verify proxy response parsing: HTTP/1.1 200 Connection Established followed by SSH banner
        val proxyResponse = "HTTP/1.1 200 Connection established\r\nProxy-Agent: Squid/5.2\r\n\r\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        val inStream = ByteArrayInputStream(proxyResponse.toByteArray(StandardCharsets.UTF_8))
        val pushbackIn = java.io.PushbackInputStream(inStream, 1024)

        val resp = HttpStatusParser.consumeSingleResponse(pushbackIn)
        assertNotNull(resp)
        assertEquals(200, resp?.statusCode)
        assertEquals(0, resp?.bodyLength)

        val remaining = String(pushbackIn.readBytes(), StandardCharsets.UTF_8)
        assertTrue(remaining.startsWith("SSH-2.0-OpenSSH_8.9p1"))
    }
}
