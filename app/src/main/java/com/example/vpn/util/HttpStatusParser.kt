package com.example.vpn.util

import java.io.InputStream
import java.util.Locale

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

        val upper = payload.uppercase(Locale.ROOT)
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

    /**
     * Consumes a complete single HTTP response (Status-Line, Headers, and Body if Content-Length/Chunked).
     * Returns structured metadata about the consumed response, leaving the InputStream cleanly positioned
     * at the next byte boundary.
     */
    fun consumeSingleResponse(inStream: InputStream): ParsedHttpResponse? {
        // Skip any leading blank/whitespace lines (e.g. leftover CRLF)
        var statusLine = ""
        while (true) {
            val line = readLine(inStream) ?: return null
            if (line.isNotBlank()) {
                statusLine = line
                break
            }
        }

        val statusCode = parseStatusCode(statusLine)
        val headers = mutableMapOf<String, String>()

        // Read all headers until empty line
        while (true) {
            val line = readLine(inStream) ?: break
            if (line.isBlank()) break
            val colonIdx = line.indexOf(':')
            if (colonIdx > 0) {
                val name = line.substring(0, colonIdx).trim().lowercase(Locale.ROOT)
                val value = line.substring(colonIdx + 1).trim()
                headers[name] = value
            }
        }

        var bodyLength = 0

        // If status is 101, 204, 304, or 1xx/2xx CONNECT, there is no body
        val isNoBodyStatus = statusCode == 101 || statusCode == 204 || statusCode == 304 || (statusCode != null && statusCode in 100..199)

        if (!isNoBodyStatus) {
            val contentLengthStr = headers["content-length"]
            val transferEncoding = headers["transfer-encoding"]?.lowercase(Locale.ROOT)

            if (contentLengthStr != null) {
                val len = contentLengthStr.toIntOrNull() ?: 0
                if (len > 0) {
                    val consumed = inStream.readNBytesCompat(len)
                    bodyLength = consumed.size
                }
            } else if (transferEncoding?.contains("chunked") == true) {
                // Chunked transfer encoding consumption
                while (true) {
                    val sizeLine = readLine(inStream) ?: break
                    val chunkSize = sizeLine.trim().split(";")[0].toIntOrNull(16) ?: 0
                    if (chunkSize <= 0) {
                        // Trailing headers until blank line
                        while (true) {
                            val trailer = readLine(inStream) ?: break
                            if (trailer.isBlank()) break
                        }
                        break
                    }
                    val chunkData = inStream.readNBytesCompat(chunkSize)
                    bodyLength += chunkData.size
                    // Consume trailing CRLF of chunk
                    readLine(inStream)
                }
            }
        }

        return ParsedHttpResponse(
            statusLine = statusLine,
            statusCode = statusCode,
            headers = headers,
            bodyLength = bodyLength
        )
    }

    /**
     * Reads a line terminated by CRLF or LF.
     */
    fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        var b: Int
        var readAny = false
        while (input.read().also { b = it } != -1) {
            readAny = true
            if (b == '\n'.code) break
            if (b != '\r'.code) {
                sb.append(b.toChar())
            }
        }
        return if (!readAny) null else sb.toString()
    }

    private fun InputStream.readNBytesCompat(n: Int): ByteArray {
        val buf = ByteArray(n)
        var total = 0
        while (total < n) {
            val read = read(buf, total, n - total)
            if (read == -1) break
            total += read
        }
        return if (total == n) buf else buf.copyOf(total)
    }
}

data class ParsedHttpResponse(
    val statusLine: String,
    val statusCode: Int?,
    val headers: Map<String, String>,
    val bodyLength: Int
)

enum class PayloadMode {
    NONE,
    WEBSOCKET,                  // Expects 101 Switching Protocols + activates RFC 6455 framing
    PAYLOAD_WITH_HTTP_RESPONSE, // Expects 200 OK + consumes response headers
    PAYLOAD_ONLY                // Sends raw HTTP/payload injection; remote immediately streams SSH bytes
}
