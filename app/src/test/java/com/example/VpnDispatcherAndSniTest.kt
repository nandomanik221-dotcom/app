package com.example

import android.content.Context
import android.net.VpnService
import androidx.test.core.app.ApplicationProvider
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.parser.VpnConfigParser
import com.example.vpn.backend.VpnBackendDispatcher
import com.example.vpn.ssh.SshTunnelClient
import com.example.vpn.util.SniUtils
import com.example.vpn.xray.XrayVmessClient
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VpnDispatcherAndSniTest {

    private lateinit var mockVpnService: VpnService

    @Before
    fun setup() {
        val controller = Robolectric.buildService(com.example.vpn.V2TunnelVpnService::class.java)
        mockVpnService = controller.get()
    }

    @Test
    fun `sni sanitization extracts pure rfc compliant hostnames without ports`() {
        // Standard SNI with port (like ads.ruangguru.com:443)
        assertEquals("ads.ruangguru.com", SniUtils.sanitizeSni("ads.ruangguru.com:443"))
        assertEquals("cdn.udemy.com", SniUtils.sanitizeSni("cdn.udemy.com:8443"))

        // Full URL with scheme and port
        assertEquals("prem.nikuvpn.biz.id", SniUtils.sanitizeSni("https://prem.nikuvpn.biz.id:443/ws"))
        assertEquals("sg.server.com", SniUtils.sanitizeSni("ws://sg.server.com:80/path"))

        // IP addresses
        assertEquals("104.28.19.42", SniUtils.sanitizeSni("104.28.19.42:443"))
        assertEquals("2001:db8::1", SniUtils.sanitizeSni("[2001:db8::1]:443"))

        // Already clean hostnames
        assertEquals("yahoo.com", SniUtils.sanitizeSni("yahoo.com"))
        assertEquals("m.youtube.com", SniUtils.sanitizeSni("m.youtube.com"))

        // Blank SNI fallback
        assertEquals("fallback.domain.com", SniUtils.sanitizeSni("", fallbackHost = "fallback.domain.com"))
    }

    @Test
    fun `ssh profile dispatches strictly to ssh backend and never to vmess`() {
        val sshProfile = VpnProfile(
            id = 101L,
            name = "Prem Niku SSH",
            protocol = VpnProtocol.SSH,
            server = "prem.nikuvpn.biz.id",
            port = 80,
            sshUsername = "testuser",
            sshPassword = "testpass",
            sni = "ads.ruangguru.com:443",
            sshDirectSsl = false
        )

        val backend = VpnBackendDispatcher.dispatch(mockVpnService, sshProfile)

        // Verifications
        assertNotNull(backend)
        assertEquals("SSH", backend.backendName)
        assertTrue("Backend must be SshTunnelClient instance", backend is SshTunnelClient)
        assertFalse("SSH must never instantiate XrayVmessClient", backend is XrayVmessClient)
        assertNotEquals("XrayVmessClient", backend.backendName)
    }

    @Test
    fun `vmess profile dispatches strictly to xray vmess backend`() {
        val vmessProfile = VpnProfile(
            id = 102L,
            name = "SG VMess",
            protocol = VpnProtocol.VMESS,
            server = "104.21.56.88",
            port = 443,
            password = "c7d2e1f4-90a8-43e5-8271-bf6308da5e91",
            security = "tls",
            sni = "sg02-cdn.v2tunnel.net"
        )

        val backend = VpnBackendDispatcher.dispatch(mockVpnService, vmessProfile)

        assertNotNull(backend)
        assertEquals("XrayVmessClient", backend.backendName)
        assertTrue("Backend must be XrayVmessClient instance", backend is XrayVmessClient)
        assertFalse("VMess must not be SshTunnelClient", backend is SshTunnelClient)
    }

    @Test
    fun `vless profile dispatches strictly to vless backend`() {
        val vlessProfile = VpnProfile(
            id = 103L,
            name = "ID VLESS Reality",
            protocol = VpnProtocol.VLESS,
            server = "id-xray.v2tunnel.net",
            port = 443,
            password = "e9a3b8d1-419a-4c40-9e0c-99c53f3e7a12",
            security = "tls"
        )

        val backend = VpnBackendDispatcher.dispatch(mockVpnService, vlessProfile)
        assertEquals("VLESS", backend.backendName)
    }

    @Test
    fun `trojan profile dispatches strictly to trojan backend`() {
        val trojanProfile = VpnProfile(
            id = 104L,
            name = "SG Trojan",
            protocol = VpnProtocol.TROJAN,
            server = "sg01.v2tunnel.net",
            port = 443,
            password = "trojan-secure-fast-pass",
            security = "tls"
        )

        val backend = VpnBackendDispatcher.dispatch(mockVpnService, trojanProfile)
        assertEquals("Trojan", backend.backendName)
    }

    @Test
    fun `shadowsocks and socks5 dispatch to their respective backends`() {
        val ssProfile = VpnProfile(
            id = 105L,
            name = "JP Shadowsocks",
            protocol = VpnProtocol.SHADOWSOCKS,
            server = "jp-tokyo.v2tunnel.net",
            port = 8388,
            password = "ss-secret-pass",
            method = "chacha20-ietf-poly1305"
        )
        val ssBackend = VpnBackendDispatcher.dispatch(mockVpnService, ssProfile)
        assertEquals("Shadowsocks", ssBackend.backendName)

        val socksProfile = VpnProfile(
            id = 106L,
            name = "Local SOCKS5",
            protocol = VpnProtocol.SOCKS5,
            server = "127.0.0.1",
            port = 1080
        )
        val socksBackend = VpnBackendDispatcher.dispatch(mockVpnService, socksProfile)
        assertEquals("SOCKS5", socksBackend.backendName)
    }

    @Test
    fun `ssh uri parsing configures ssh credentials and does not force tls on port 80`() {
        val uri = "ssh://nikuser:nikupass@prem.nikuvpn.biz.id:80?sni=ads.ruangguru.com:443&ssl=false#SSH-Custom"
        val profile = VpnConfigParser.parseSsh(uri)

        assertNotNull(profile)
        assertEquals(VpnProtocol.SSH, profile?.protocol)
        assertEquals("prem.nikuvpn.biz.id", profile?.server)
        assertEquals(80, profile?.port)
        assertEquals("nikuser", profile?.sshUsername)
        assertEquals("nikupass", profile?.sshPassword)
        assertEquals("ads.ruangguru.com:443", profile?.sni)
        assertFalse(profile?.sshDirectSsl == true)
        assertEquals("none", profile?.security)
    }
}
