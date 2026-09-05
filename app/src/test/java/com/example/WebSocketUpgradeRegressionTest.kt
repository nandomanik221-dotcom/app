package com.example

import android.net.VpnService
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.vpn.ssh.SshTunnelClient
import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.SniUtils
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class WebSocketUpgradeRegressionTest {

    private lateinit var mockVpnService: VpnService

    @Before
    fun setup() {
        val controller = Robolectric.buildService(com.example.vpn.V2TunnelVpnService::class.java)
        mockVpnService = controller.get()
    }

    /**
     * Test 1: Golden Config Independence & Host Mapping
     * TARGET: prem.nikuvpn.biz.id:443
     * REMOTE PROXY: ads.ruangguru.com:443
     * SNI: prem.nikuvpn.biz.id
     * Host header in payload must map to prem.nikuvpn.biz.id, NEVER to ads.ruangguru.com!
     */
    @Test
    fun `testHostMappingIndependence`() {
        val profile = VpnProfile(
            name = "Golden Config Test",
            protocol = VpnProtocol.SSH,
            server = "prem.nikuvpn.biz.id",
            port = 443,
            sni = "prem.nikuvpn.biz.id",
            remoteProxyEnabled = true,
            remoteProxyType = "HTTP",
            remoteProxyHost = "ads.ruangguru.com",
            remoteProxyPort = 443,
            sshPayload = "GET [path] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        )

        val client = SshTunnelClient(mockVpnService, profile)
        val formatted = client.formatPayload(profile.sshPayload, profile.server, profile.port)

        // Host header MUST be the target origin (prem.nikuvpn.biz.id), NOT remote proxy
        assertTrue("Formatted payload must contain Host: prem.nikuvpn.biz.id", formatted.contains("Host: prem.nikuvpn.biz.id\r\n"))
        assertFalse("Formatted payload must NOT contain remote proxy in Host header", formatted.contains("Host: ads.ruangguru.com"))

        // Remote proxy and target remain completely independent
        assertEquals("ads.ruangguru.com", profile.remoteProxyHost)
        assertEquals("prem.nikuvpn.biz.id", profile.server)
        assertEquals("prem.nikuvpn.biz.id", profile.sni)
    }

    /**
     * Test 2: SNI Mapping & Sanitization
     * Verifies SNI maps to clean hostname without port and is independent of Remote Proxy.
     */
    @Test
    fun `testSniMapping`() {
        val cleanSni = SniUtils.sanitizeSni("prem.nikuvpn.biz.id:443", fallbackHost = "prem.nikuvpn.biz.id")
        assertEquals("prem.nikuvpn.biz.id", cleanSni)

        // Remote proxy host has its own endpoint, does NOT pollute SNI
        val proxyHost = "ads.ruangguru.com"
        assertNotEquals(proxyHost, cleanSni)
    }

    /**
     * Test 3: WebSocket Path Mapping
     * Verifies path `/ws` is mapped correctly from `profile.path`, replacing `/` if `/ws` is configured.
     */
    @Test
    fun `testWebSocketPath`() {
        val profile = VpnProfile(
            name = "WS Path Test",
            protocol = VpnProtocol.SSH,
            sshTransport = "WebSocket",
            server = "prem.nikuvpn.biz.id",
            port = 443,
            path = "/ws",
            sshPayload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        )

        val client = SshTunnelClient(mockVpnService, profile)
        val formatted = client.formatPayload(profile.sshPayload, profile.server, profile.port)

        // The request line should be normalized to /ws
        assertTrue("Request line must target /ws path", formatted.startsWith("GET /ws HTTP/1.1\r\n"))
    }

    /**
     * Test 4: Upgrade Headers & User-Agent Enforcement
     * Verifies Upgrade: websocket, Connection: Upgrade, Sec-WebSocket-Version: 13, Sec-WebSocket-Key,
     * and User-Agent are present to prevent Cloudflare 403 Forbidden.
     */
    @Test
    fun `testUpgradeHeadersAndUserAgent`() {
        val profile = VpnProfile(
            name = "RFC 6455 Headers Test",
            protocol = VpnProtocol.SSH,
            sshTransport = "WebSocket",
            server = "prem.nikuvpn.biz.id",
            port = 443,
            path = "/ws",
            sshPayload = "GET /ws HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
        )

        val client = SshTunnelClient(mockVpnService, profile)
        val formatted = client.formatPayload(profile.sshPayload, profile.server, profile.port)

        assertTrue("Payload must contain Upgrade: websocket", formatted.contains("Upgrade: websocket", ignoreCase = true))
        assertTrue("Payload must contain Connection: Upgrade", formatted.contains("Connection: Upgrade", ignoreCase = true))
        assertTrue("Payload must contain Sec-WebSocket-Version: 13", formatted.contains("Sec-WebSocket-Version: 13", ignoreCase = true))
        assertTrue("Payload must contain Sec-WebSocket-Key", formatted.contains("Sec-WebSocket-Key:", ignoreCase = true))
        assertTrue("Payload must contain User-Agent to satisfy Cloudflare", formatted.contains("User-Agent:", ignoreCase = true))
        assertTrue("Payload must be properly CRLF terminated", formatted.endsWith("\r\n\r\n"))
    }

    /**
     * Test 5: Payload Ordering & Split Handling
     * Verifies multi-stage payloads with [split], [delay_split], [instant_split] are split into ordered stages.
     */
    @Test
    fun `testPayloadOrderingAndSplitHandling`() {
        val rawPayload = "GET http://ads.ruangguru.com/ HTTP/1.1[crlf]Host: ads.ruangguru.com[crlf][crlf][split]CONNECT [host_port] HTTP/1.1[crlf][crlf][delay_split]GET [path] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"

        val profile = VpnProfile(
            name = "Split Test",
            protocol = VpnProtocol.SSH,
            server = "prem.nikuvpn.biz.id",
            port = 443,
            path = "/ws",
            sshPayload = rawPayload
        )

        val client = SshTunnelClient(mockVpnService, profile)
        val stages = client.splitPayloadStages(rawPayload)

        assertEquals("Must have exactly 3 stages", 3, stages.size)
        assertTrue("Stage 1 must be HTTP GET to ads.ruangguru.com", stages[0].template.contains("GET http://ads.ruangguru.com/"))
        assertEquals(0L, stages[0].delayMs)
        assertFalse(stages[0].isLast)

        assertTrue("Stage 2 must be CONNECT request", stages[1].template.contains("CONNECT [host_port]"))
        assertEquals(100L, stages[1].delayMs) // [delay_split] sets 100ms
        assertFalse(stages[1].isLast)

        assertTrue("Stage 3 must be WebSocket upgrade request", stages[2].template.contains("Upgrade: websocket"))
        assertTrue(stages[2].isLast)
    }

    /**
     * Test 6: Rejection Source Identification
     * Verifies that Cloudflare 403 response is identified as C. CDN/Cloudflare,
     * Squid/Proxy is identified as A. Remote Proxy, and Origin is identified as B. Origin Server.
     */
    @Test
    fun `testRejectionSourceIdentification`() {
        // Cloudflare 403 response
        val cfHeaders = mapOf(
            "server" to "cloudflare",
            "cf-ray" to "8b1234567890-SIN",
            "content-length" to "553"
        )
        val cfSource = HttpStatusParser.identifyRejectionSource(cfHeaders, "HTTP/1.1 403 Forbidden", "ads.ruangguru.com:443")
        assertTrue("Must be identified as Cloudflare", cfSource.startsWith("C. CDN/Cloudflare"))

        // Remote Proxy 403 response
        val proxyHeaders = mapOf(
            "server" to "squid/4.15",
            "via" to "1.1 ads.ruangguru.com (squid/4.15)"
        )
        val proxySource = HttpStatusParser.identifyRejectionSource(proxyHeaders, "HTTP/1.1 403 Forbidden", "ads.ruangguru.com:443")
        assertTrue("Must be identified as Remote Proxy", proxySource.startsWith("A. Remote Proxy"))

        // Origin Server 403 response
        val originHeaders = mapOf(
            "server" to "nginx/1.22.1"
        )
        val originSource = HttpStatusParser.identifyRejectionSource(originHeaders, "HTTP/1.1 403 Forbidden", "ads.ruangguru.com:443")
        assertTrue("Must be identified as Origin Server", originSource.startsWith("B. Origin Server"))
    }

    /**
     * Test 7: HTTP 101 Switching Protocols Parsing
     * Verifies that HttpStatusParser parses status 101 correctly and extracts headers without body.
     */
    @Test
    fun `testConsume101SwitchingProtocolsResponse`() {
        val rawHttp101 = "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

        val inStream = ByteArrayInputStream(rawHttp101.toByteArray(Charsets.UTF_8))
        val parsed = HttpStatusParser.consumeSingleResponse(inStream)

        assertNotNull(parsed)
        assertEquals(101, parsed!!.statusCode)
        assertEquals("HTTP/1.1 101 Switching Protocols", parsed.statusLine)
        assertEquals("websocket", parsed.headers["upgrade"])
        assertEquals("upgrade", parsed.headers["connection"]?.lowercase())
        assertEquals(0, parsed.bodyLength) // 101 has no HTTP body
    }
}
