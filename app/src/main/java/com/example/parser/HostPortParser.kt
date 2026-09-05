package com.example.parser

/**
 * Robust Host and Port parser supporting:
 * - example.com:22
 * - example.com:80
 * - example.com:443
 * - example.com:8080
 * - [2001:db8::1]:22
 * - [2001:db8::1]
 * - 127.0.0.1:443
 * - example.com (using defaultPort)
 *
 * Avoids simple split(":") which breaks on IPv6 addresses.
 */
object HostPortParser {

    data class HostPort(
        val host: String,
        val port: Int
    ) {
        val formatted: String
            get() = format(host, port)
    }

    /**
     * Parses a host:port string into a [HostPort] instance.
     * If port is not specified, uses [defaultPort].
     */
    fun parse(rawInput: String, defaultPort: Int = 22): HostPort? {
        val trimmed = rawInput.trim()
        if (trimmed.isBlank()) return null

        var host: String
        val port: Int

        if (trimmed.startsWith("[")) {
            // IPv6 bracketed format: [2001:db8::1]:22 or [2001:db8::1]
            val closingBracket = trimmed.indexOf(']')
            if (closingBracket == -1) return null

            val rawIpv6 = trimmed.substring(1, closingBracket).trim()
            if (rawIpv6.isBlank()) return null
            host = rawIpv6

            val afterBracket = trimmed.substring(closingBracket + 1).trim()
            if (afterBracket.startsWith(":")) {
                val portStr = afterBracket.substring(1).trim()
                port = portStr.toIntOrNull() ?: return null
            } else {
                port = defaultPort
            }
        } else {
            // Check if there's a colon for port
            val colonIdx = trimmed.lastIndexOf(':')
            if (colonIdx != -1) {
                // Verify if it's unbracketed IPv6 (has more than one colon)
                val firstColon = trimmed.indexOf(':')
                if (firstColon != colonIdx) {
                    // Unbracketed IPv6 without port: 2001:db8::1
                    host = trimmed
                    port = defaultPort
                } else {
                    // Single colon: host:port
                    val hostPart = trimmed.substring(0, colonIdx).trim()
                    val portPart = trimmed.substring(colonIdx + 1).trim()
                    if (hostPart.isBlank()) return null
                    host = hostPart
                    port = portPart.toIntOrNull() ?: return null
                }
            } else {
                // No port specified: example.com
                host = trimmed
                port = defaultPort
            }
        }

        if (port !in 1..65535) return null
        return HostPort(host, port)
    }

    /**
     * Formats host and port into standard representation.
     * Encloses IPv6 addresses containing colons in brackets.
     */
    fun format(host: String, port: Int): String {
        val cleanHost = host.trim().removePrefix("[").removeSuffix("]")
        val formattedHost = if (cleanHost.contains(":")) "[$cleanHost]" else cleanHost
        return "$formattedHost:$port"
    }
}
