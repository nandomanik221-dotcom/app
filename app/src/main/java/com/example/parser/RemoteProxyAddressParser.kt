package com.example.parser

/**
 * Parser for HTTP Custom-style Remote Proxy addresses ("Proxy Jarak Jauh").
 *
 * Supported formats:
 * - host:port                       -> e.g. "ads.ruangguru.com:443"
 * - user:pass@host:port             -> e.g. "myuser:mypass@ads.ruangguru.com:8080"
 * - [IPv6]:port                     -> e.g. "[2001:db8::1]:443"
 * - user:pass@[IPv6]:port           -> e.g. "myuser:mypass@[2001:db8::1]:8080"
 *
 * Does not use simple split(":") to avoid breaking IPv6 addresses.
 */
object RemoteProxyAddressParser {

    data class ParsedProxyAddress(
        val host: String,
        val port: Int,
        val username: String? = null,
        val password: String? = null
    ) {
        val formattedString: String
            get() = format(host, port, username, password)
    }

    /**
     * Parses a raw remote proxy input string into a structured [ParsedProxyAddress].
     * Returns null if the input is blank, host is empty, or port is not within 1..65535.
     */
    fun parse(rawInput: String): ParsedProxyAddress? {
        val trimmed = rawInput.trim()
        if (trimmed.isBlank()) return null

        var workingStr = trimmed
        var extractedUser: String? = null
        var extractedPass: String? = null

        // 1. Extract user:password if '@' delimiter exists
        val atIndex = workingStr.lastIndexOf('@')
        if (atIndex != -1) {
            val userPassPart = workingStr.substring(0, atIndex)
            workingStr = workingStr.substring(atIndex + 1).trim()

            val colonIdx = userPassPart.indexOf(':')
            if (colonIdx != -1) {
                extractedUser = userPassPart.substring(0, colonIdx).trim().ifBlank { null }
                extractedPass = userPassPart.substring(colonIdx + 1).trim().ifBlank { null }
            } else {
                extractedUser = userPassPart.trim().ifBlank { null }
            }
        }

        // 2. Parse host and port (handling IPv6 brackets and standard domains/IPv4)
        var host: String
        val port: Int

        if (workingStr.startsWith("[")) {
            // IPv6 with brackets: [2001:db8::1]:443
            val closingBracket = workingStr.indexOf(']')
            if (closingBracket == -1) return null // Malformed bracket

            val rawIpv6 = workingStr.substring(1, closingBracket).trim()
            if (rawIpv6.isBlank()) return null
            host = rawIpv6

            val afterBracket = workingStr.substring(closingBracket + 1).trim()
            if (afterBracket.startsWith(":")) {
                val portStr = afterBracket.substring(1).trim()
                port = portStr.toIntOrNull() ?: return null
            } else {
                // Default port if omitted
                port = 8080
            }
        } else {
            // Domain or IPv4: host:port
            val lastColon = workingStr.lastIndexOf(':')
            if (lastColon != -1) {
                host = workingStr.substring(0, lastColon).trim()
                val portStr = workingStr.substring(lastColon + 1).trim()
                port = portStr.toIntOrNull() ?: return null
            } else {
                host = workingStr.trim()
                port = 8080
            }
        }

        // Clean any leading/trailing quotes or whitespace from host
        host = host.trim('"', '\'', ' ')
        if (host.isBlank()) return null
        if (port !in 1..65535) return null

        return ParsedProxyAddress(
            host = host,
            port = port,
            username = extractedUser,
            password = extractedPass
        )
    }

    /**
     * Formats structured fields back into standard HTTP Custom "Proxy Jarak Jauh" string.
     */
    fun format(
        host: String,
        port: Int,
        username: String? = null,
        password: String? = null
    ): String {
        val cleanHost = host.trim()
        if (cleanHost.isBlank()) return ""

        val effectivePort = if (port in 1..65535) port else 8080
        val isIpv6 = cleanHost.contains(":") && !cleanHost.startsWith("[")
        val formattedHost = if (isIpv6) "[$cleanHost]" else cleanHost

        val hasUser = !username.isNullOrBlank()
        val hasPass = !password.isNullOrBlank()

        return when {
            hasUser && hasPass -> "$username:$password@$formattedHost:$effectivePort"
            hasUser -> "$username@$formattedHost:$effectivePort"
            else -> "$formattedHost:$effectivePort"
        }
    }
}
