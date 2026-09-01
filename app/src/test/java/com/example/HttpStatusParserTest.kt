package com.example

import com.example.vpn.util.HttpStatusParser
import com.example.vpn.util.PayloadMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HttpStatusParserTest {

    @Test
    fun testParseStandardStatusCodes() {
        assertEquals(200, HttpStatusParser.parseStatusCode("HTTP/1.1 200 Connection Established"))
        assertEquals(200, HttpStatusParser.parseStatusCode("HTTP/1.1 200 OK"))
        assertEquals(101, HttpStatusParser.parseStatusCode("HTTP/1.1 101 Switching Protocols"))
        assertEquals(403, HttpStatusParser.parseStatusCode("HTTP/1.1 403 Forbidden"))
        assertEquals(407, HttpStatusParser.parseStatusCode("HTTP/1.1 407 Proxy Authentication Required"))
        assertEquals(502, HttpStatusParser.parseStatusCode("HTTP/1.0 502 Bad Gateway"))
        assertEquals(302, HttpStatusParser.parseStatusCode("HTTP/2 302 Found"))
    }

    @Test
    fun testParseInvalidStatusLines() {
        assertNull(HttpStatusParser.parseStatusCode(null))
        assertNull(HttpStatusParser.parseStatusCode(""))
        assertNull(HttpStatusParser.parseStatusCode("   "))
        assertNull(HttpStatusParser.parseStatusCode("SSH-2.0-OpenSSH_8.9p1"))
        assertNull(HttpStatusParser.parseStatusCode("Invalid header"))
        assertNull(HttpStatusParser.parseStatusCode("HTTP/1.1"))
    }

    @Test
    fun testDetectPayloadMode() {
        assertEquals(
            PayloadMode.WEBSOCKET,
            HttpStatusParser.detectPayloadMode("GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        )

        assertEquals(
            PayloadMode.PAYLOAD_WITH_HTTP_RESPONSE,
            HttpStatusParser.detectPayloadMode("CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]")
        )

        assertEquals(
            PayloadMode.PAYLOAD_ONLY,
            HttpStatusParser.detectPayloadMode("GET / HTTP/1.1[crlf][split]CONNECT [host_port] HTTP/1.1")
        )

        assertEquals(
            PayloadMode.NONE,
            HttpStatusParser.detectPayloadMode("")
        )
    }
}
