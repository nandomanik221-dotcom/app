package com.example

import com.example.model.SshTransport
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.parser.HostPortParser
import com.example.parser.VpnConfigParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SshStandardRedesignTest {

    @Test
    fun testHostPortParserStandardIpv4AndDomain() {
        val parsed1 = HostPortParser.parse("prem.nikuvpn.biz.id:443")
        assertNotNull(parsed1)
        assertEquals("prem.nikuvpn.biz.id", parsed1!!.host)
        assertEquals(443, parsed1.port)

        val parsed2 = HostPortParser.parse("104.21.56.88:8080")
        assertNotNull(parsed2)
        assertEquals("104.21.56.88", parsed2!!.host)
        assertEquals(8080, parsed2.port)

        val parsed3 = HostPortParser.parse("ssh.example.com", defaultPort = 22)
        assertNotNull(parsed3)
        assertEquals("ssh.example.com", parsed3!!.host)
        assertEquals(22, parsed3.port)
    }

    @Test
    fun testHostPortParserIpv6() {
        val parsed1 = HostPortParser.parse("[2001:db8::1]:22")
        assertNotNull(parsed1)
        assertEquals("2001:db8::1", parsed1!!.host)
        assertEquals(22, parsed1.port)

        val formatted = HostPortParser.format("2001:db8::1", 22)
        assertEquals("[2001:db8::1]:22", formatted)
    }

    @Test
    fun testSshProfileDefaultsAreStandardNotWebSocket() {
        val profile = VpnProfile(
            name = "Test SSH",
            protocol = VpnProtocol.SSH,
            server = "prem.nikuvpn.biz.id",
            port = 443,
            sshUsername = "testione",
            sshPassword = "wero"
        )

        assertEquals(SshTransport.STANDARD.name, profile.sshTransport)
        assertFalse("Standard SSH must not be identified as WebSocket", profile.isSshWebSocket)
        assertEquals("Default", profile.sniVersion)
        assertFalse(profile.allowInsecure)
        assertEquals("TLS", profile.sshMethod)
        assertTrue(profile.sshPayloadEnabled)
    }

    @Test
    fun testParseSshUriWithoutForcingWs() {
        val uri = "ssh://testione:wero@prem.nikuvpn.biz.id:443?sni=prem.nikuvpn.biz.id&proxy=ads.ruangguru.com:443&transport=standard&method=tls#NikuVPN%20SSH"
        val profile = VpnConfigParser.parseSsh(uri)
        assertNotNull(profile)
        assertEquals("prem.nikuvpn.biz.id", profile!!.server)
        assertEquals(443, profile.port)
        assertEquals("testione", profile.sshUsername)
        assertEquals("wero", profile.sshPassword)
        assertEquals("prem.nikuvpn.biz.id", profile.sni)
        assertEquals("ads.ruangguru.com", profile.remoteProxyHost)
        assertEquals(443, profile.remoteProxyPort)
        assertTrue(profile.remoteProxyEnabled)
        assertEquals("standard", profile.sshTransport)
        assertEquals("tls", profile.sshMethod)
        assertFalse("Parsed SSH standard profile must NOT have ws transport", profile.isSshWebSocket)
    }
}
