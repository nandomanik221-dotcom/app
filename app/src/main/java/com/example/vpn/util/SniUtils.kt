package com.example.vpn.util

/**
 * Utility for sanitizing and preparing Server Name Indication (SNI) hostnames
 * for TLS/SSL handshakes across VMess, VLESS, Trojan, and SSH-SSL connections.
 */
object SniUtils {

    /**
     * Extracts a pure RFC-compliant TLS SNI hostname from any raw SNI, bug host, URL, or host:port string.
     * e.g., "ads.ruangguru.com:443" -> "ads.ruangguru.com"
     *       "https://cdn.udemy.com:8443/path" -> "cdn.udemy.com"
     *       "yahoo.com" -> "yahoo.com"
     */
    fun sanitizeSni(rawSni: String, fallbackHost: String = ""): String {
        var clean = rawSni.trim()
        if (clean.isBlank()) {
            clean = fallbackHost.trim()
        }
        if (clean.isBlank()) return ""

        // Strip URI scheme if present (e.g. https://, http://, wss://, ws://)
        if (clean.contains("://")) {
            clean = clean.substringAfter("://")
        }
        // Strip URI path, queries, fragments
        if (clean.contains("/")) {
            clean = clean.substringBefore("/")
        }
        if (clean.contains("?")) {
            clean = clean.substringBefore("?")
        }
        if (clean.contains("#")) {
            clean = clean.substringBefore("#")
        }
        // Strip user info if present (e.g. user:pass@host)
        if (clean.contains("@")) {
            clean = clean.substringAfterLast("@")
        }
        // Handle IPv6 bracket format [2001:db8::1]:443
        if (clean.startsWith("[")) {
            val endBracket = clean.indexOf("]")
            if (endBracket != -1) {
                return clean.substring(1, endBracket)
            }
        }
        // Strip port suffix if present (e.g. "ads.ruangguru.com:443" -> "ads.ruangguru.com")
        if (clean.contains(":") && !clean.contains("::") && clean.count { it == ':' } == 1) {
            clean = clean.substringBefore(":")
        }
        return clean.trim()
    }
}
