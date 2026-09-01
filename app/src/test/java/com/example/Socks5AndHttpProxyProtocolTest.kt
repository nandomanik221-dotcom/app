package com.example

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class Socks5AndHttpProxyProtocolTest {

    @Test
    fun testSocks5GreetingPackets() {
        val noAuthGreeting = byteArrayOf(0x05, 0x01, 0x00)
        assertEquals(0x05, noAuthGreeting[0].toInt())
        assertEquals(1, noAuthGreeting[1].toInt())
        assertEquals(0x00, noAuthGreeting[2].toInt())

        val userPassGreeting = byteArrayOf(0x05, 0x02, 0x00, 0x02)
        assertEquals(0x05, userPassGreeting[0].toInt())
        assertEquals(2, userPassGreeting[1].toInt())
        assertEquals(0x02, userPassGreeting[3].toInt())
    }

    @Test
    fun testRfc1929UserPassAuthEncoding() {
        val user = "testuser"
        val pass = "secret123"

        val userBytes = user.toByteArray(StandardCharsets.UTF_8)
        val passBytes = pass.toByteArray(StandardCharsets.UTF_8)

        val out = ByteArrayOutputStream()
        out.write(0x01)
        out.write(userBytes.size)
        out.write(userBytes)
        out.write(passBytes.size)
        out.write(passBytes)

        val packet = out.toByteArray()
        assertEquals(0x01, packet[0].toInt()) // Auth version
        assertEquals(userBytes.size, packet[1].toInt())
        assertEquals(passBytes.size, packet[2 + userBytes.size].toInt())
    }

    @Test
    fun testSocks5Ipv4ConnectPacket() {
        val host = "1.1.1.1"
        val port = 443

        val parts = host.split(".").map { it.toInt().toByte() }
        val pkt = byteArrayOf(
            0x05, 0x01, 0x00, 0x01,
            parts[0], parts[1], parts[2], parts[3],
            ((port shr 8) and 0xFF).toByte(),
            (port and 0xFF).toByte()
        )

        assertEquals(0x05, pkt[0].toInt())
        assertEquals(0x01, pkt[1].toInt()) // CONNECT
        assertEquals(0x00, pkt[2].toInt()) // RSV
        assertEquals(0x01, pkt[3].toInt()) // IPv4
        assertEquals(1, pkt[4].toInt())
        assertEquals(443, ((pkt[8].toInt() and 0xFF) shl 8) or (pkt[9].toInt() and 0xFF))
    }

    @Test
    fun testSocks5DomainConnectPacket() {
        val domain = "ssh.example.com"
        val port = 22
        val domainBytes = domain.toByteArray(StandardCharsets.UTF_8)

        val pkt = ByteArray(4 + 1 + domainBytes.size + 2)
        pkt[0] = 0x05
        pkt[1] = 0x01
        pkt[2] = 0x00
        pkt[3] = 0x03 // Domain name
        pkt[4] = domainBytes.size.toByte()
        System.arraycopy(domainBytes, 0, pkt, 5, domainBytes.size)
        pkt[5 + domainBytes.size] = ((port shr 8) and 0xFF).toByte()
        pkt[6 + domainBytes.size] = (port and 0xFF).toByte()

        assertEquals(0x03, pkt[3].toInt())
        assertEquals(domainBytes.size, pkt[4].toInt())
        assertEquals(22, ((pkt[pkt.size - 2].toInt() and 0xFF) shl 8) or (pkt[pkt.size - 1].toInt() and 0xFF))
    }
}
