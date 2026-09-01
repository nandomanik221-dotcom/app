package com.example.vpn.util

/**
 * Robust HTTP Status Code and Payload Mode parser.
 *
 * Adheres strictly to RFC 7230 / RFC 9112:
 * Status-Line = HTTP-Version SP Status-Code SP [ Reason-Phrase ] CRLF
 */
object HttpStatusParser {

    private val STATUS_LINE_REGEX = Regex("""^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+.*)?$""", RegexOption.IGNORE_CASE)

    /**
     * Parses the integer HTTP status code from a raw status line.
     *
     * Example:
     * "HTTP/1.1 200 Connection Established" -> 200
     * "HTTP/1.1 101 Switching Protocols" -> 101
     * "HTTP/1.1 403 Forbidden" -> 403
     * "HTTP/1.1 407 Proxy Authentication Required" -> 407
     * "Invalid" -> null
     */
    fun parseStatusCode(statusLine: String?): Int? {
        if (statusLine.isNullOrBlank()) return null
        val match = STATUS_LINE_REGEX.find(statusLine.trim()) ?: return null
        return match.groupValues[1].toIntOrNull()
    }

    /**
     * Inspects a custom payload template and determines the expected handshake mode.
     */
    fun detectPayloadMode(payload: String): PayloadMode {
        if (payload.isBlank()) return PayloadMode.NONE

        val upper = payload.uppercase()
        return when {
            upper.contains("UPGRADE: WEBSOCKET") || upper.contains("UPGRADE:WEBSOCKET") -> {
                PayloadMode.WEBSOCKET
            }
            upper.contains("[CRLF][CRLF]") || upper.contains("\r\n\r\n") || upper.contains("HTTP/1.") -> {
                // If payload is HTTP request format and explicitly asks for response (e.g. GET/POST/HEAD with [split] or standard response expectation)
                if (upper.contains("[SPLIT]") || upper.contains("[RAW]") || upper.contains("[NETDATA]")) {
                    PayloadMode.PAYLOAD_ONLY
                } else {
                    PayloadMode.PAYLOAD_WITH_HTTP_RESPONSE
                }
            }
            else -> {
                PayloadMode.PAYLOAD_ONLY
            }
        }
    }
}

enum class PayloadMode {
    NONE,
    WEBSOCKET,                  // Expects 101 Switching Protocols + activates RFC 6455 framing
    PAYLOAD_WITH_HTTP_RESPONSE, // Expects 200 OK + consumes response headers
    PAYLOAD_ONLY                // Sends raw HTTP/payload injection; remote immediately streams SSH bytes
}
