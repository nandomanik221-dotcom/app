package com.example

import com.example.parser.RemoteProxyAddressParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class RemoteProxyParserTest {

    @Test
    fun testParseSimpleDomain() {
        val result = RemoteProxyAddressParser.parse("ads.ruangguru.com:443")
        assertNotNull(result)
        assertEquals("ads.ruangguru.com", result!!.host)
        assertEquals(443, result.port)
        assertNull(result.username)
        assertNull(result.password)
    }

    @Test
    fun testParseWithUserPassAndDomain() {
        val result = RemoteProxyAddressParser.parse("user:password@ads.ruangguru.com:443")
        assertNotNull(result)
        assertEquals("ads.ruangguru.com", result!!.host)
        assertEquals(443, result.port)
        assertEquals("user", result.username)
        assertEquals("password", result.password)
    }

    @Test
    fun testParseIpv6() {
        val result = RemoteProxyAddressParser.parse("[2001:db8::1]:443")
        assertNotNull(result)
        assertEquals("2001:db8::1", result!!.host)
        assertEquals(443, result.port)
        assertNull(result.username)
        assertNull(result.password)
    }

    @Test
    fun testParseIpv6WithUserPass() {
        val result = RemoteProxyAddressParser.parse("user:password@[2001:db8::1]:443")
        assertNotNull(result)
        assertEquals("2001:db8::1", result!!.host)
        assertEquals(443, result.port)
        assertEquals("user", result.username)
        assertEquals("password", result.password)
    }

    @Test
    fun testInvalidInputs() {
        assertNull(RemoteProxyAddressParser.parse(""))
        assertNull(RemoteProxyAddressParser.parse("   "))
        assertNull(RemoteProxyAddressParser.parse("ads.ruangguru.com:999999"))
        assertNull(RemoteProxyAddressParser.parse("ads.ruangguru.com:-5"))
    }

    @Test
    fun testFormattingRoundTrip() {
        val formatted = RemoteProxyAddressParser.format(
            host = "ads.ruangguru.com",
            port = 443,
            username = "user",
            password = "password"
        )
        assertEquals("user:password@ads.ruangguru.com:443", formatted)

        val reParsed = RemoteProxyAddressParser.parse(formatted)
        assertNotNull(reParsed)
        assertEquals("ads.ruangguru.com", reParsed!!.host)
        assertEquals(443, reParsed.port)
        assertEquals("user", reParsed.username)
        assertEquals("password", reParsed.password)
    }
}
