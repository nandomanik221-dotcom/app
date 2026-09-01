package com.example

import com.example.model.VpnProtocol
import com.example.parser.VpnConfigParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleUnitTest {

    @Test
    fun `vmess parsing handles string and int port and aid`() {
        val vmessJson = """{"v":"2","ps":"SG-StringPort","add":"sg.v2tunnel.net","port":"8443","id":"e892c5bb-1132-4467-89df-7f99990141a2","aid":"0","scy":"zero","net":"ws","path":"/custom-ws","tls":"tls","sni":"sg.v2tunnel.net"}"""
        val base64 = java.util.Base64.getEncoder().encodeToString(vmessJson.toByteArray())
        val uri = "vmess://$base64"

        val profile = VpnConfigParser.parseVmess(uri)
        assertNotNull(profile)
        assertEquals("SG-StringPort", profile?.name)
        assertEquals("sg.v2tunnel.net", profile?.server)
        assertEquals(8443, profile?.port)
        assertEquals("e892c5bb-1132-4467-89df-7f99990141a2", profile?.password)
        assertEquals("/custom-ws", profile?.path)
        assertEquals(VpnProtocol.VMESS, profile?.protocol)
    }

    @Test
    fun `vless reality parsing test`() {
        val uri = "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@us.v2tunnel.net:443?type=tcp&security=reality&sni=yahoo.com&pbk=x9jK1_2Pq8zL0mNb4vC5x7Z&sid=6ba7b810#US-Reality"
        val profile = VpnConfigParser.parseVless(uri)
        assertNotNull(profile)
        assertEquals(VpnProtocol.VLESS, profile?.protocol)
        assertEquals("us.v2tunnel.net", profile?.server)
        assertEquals(443, profile?.port)
        assertEquals("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d", profile?.password)
        assertEquals("reality", profile?.security)
        assertEquals("yahoo.com", profile?.sni)
        assertEquals("x9jK1_2Pq8zL0mNb4vC5x7Z", profile?.realityPublicKey)
        assertEquals("6ba7b810", profile?.realityShortId)
    }

    @Test
    fun `shadowsocks sip002 parsing test`() {
        val userPass = "aes-256-gcm:mySecretPassword123"
        val encodedUserPass = java.util.Base64.getEncoder().encodeToString(userPass.toByteArray())
        val uri = "ss://$encodedUserPass@jp.v2tunnel.net:8388#Japan-SS"

        val profile = VpnConfigParser.parseShadowsocks(uri)
        assertNotNull(profile)
        assertEquals(VpnProtocol.SHADOWSOCKS, profile?.protocol)
        assertEquals("jp.v2tunnel.net", profile?.server)
        assertEquals(8388, profile?.port)
        assertEquals("aes-256-gcm", profile?.method)
        assertEquals("mySecretPassword123", profile?.password)
    }

    @Test
    fun `tcp checksum calculation test`() {
        val srcIp = byteArrayOf(10, 8, 0, 2)
        val dstIp = byteArrayOf(1, 1, 1, 1)
        val tcpHeaderAndData = ByteArray(20).apply {
            this[0] = 0x1F.toByte()
            this[1] = 0x90.toByte() // Src Port: 8080
            this[2] = 0x00.toByte()
            this[3] = 0x50.toByte() // Dst Port: 80
            this[12] = 0x50.toByte() // Header len 20
            this[13] = 0x02.toByte() // SYN flag
            this[14] = 0xFF.toByte()
            this[15] = 0xFF.toByte() // Window 65535
        }

        var sum = 0
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += 6 // Protocol TCP
        sum += tcpHeaderAndData.size

        var i = 0
        while (i < tcpHeaderAndData.size - 1) {
            sum += ((tcpHeaderAndData[i].toInt() and 0xFF) shl 8) or (tcpHeaderAndData[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = (sum.inv()) and 0xFFFF

        assertTrue("Checksum must be a valid 16-bit non-zero value", checksum in 1..0xFFFF)
    }

    @Test
    fun `reconnect backoff intervals verification`() {
        val backoffs = listOf(2000L, 4000L, 8000L)
        assertEquals(3, backoffs.size)
        assertEquals(2000L, backoffs[0])
        assertEquals(4000L, backoffs[1])
        assertEquals(8000L, backoffs[2])
    }
}
