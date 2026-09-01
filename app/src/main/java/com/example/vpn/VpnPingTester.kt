package com.example.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import kotlin.system.measureTimeMillis

object VpnPingTester {

    /**
     * Measures real latency to the destination host:port via TCP socket or HTTP HEAD.
     * Returns elapsed milliseconds (e.g. 45), or -1 if unreachable/timeout.
     * Never returns fake or randomized values.
     */
    suspend fun ping(host: String, port: Int, timeoutMs: Int = 2500): Int = withContext(Dispatchers.IO) {
        val cleanHost = host.trim()
        if (cleanHost.isBlank()) return@withContext -1

        // 1. Try real TCP Socket connect
        try {
            val validPort = if (port in 1..65535) port else 443
            var elapsedMs = -1L
            Socket().use { socket ->
                elapsedMs = measureTimeMillis {
                    socket.connect(InetSocketAddress(cleanHost, validPort), timeoutMs)
                }
            }
            if (elapsedMs in 1..15000) {
                return@withContext elapsedMs.toInt()
            }
        } catch (_: Exception) {
            // TCP connect failed or filtered, fallback to HTTP check
        }

        // 2. Fallback to HTTP/HTTPS ping
        try {
            val urlString = if (port == 443) "https://$cleanHost" else "http://$cleanHost:$port"
            var elapsedMs = -1L
            val url = URL(urlString)
            val connection = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "HEAD"
                instanceFollowRedirects = false
            }
            elapsedMs = measureTimeMillis {
                connection.connect()
                connection.responseCode
            }
            connection.disconnect()
            if (elapsedMs in 1..15000) {
                return@withContext elapsedMs.toInt()
            }
        } catch (_: Exception) {
            // Unreachable or timeout
        }

        return@withContext -1
    }

    /**
     * Resolves the real Public IP via HTTP request through the established tunnel.
     */
    suspend fun fetchPublicIp(): String = withContext(Dispatchers.IO) {
        try {
            val url = URL("https://api.ipify.org")
            val connection = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 4000
                readTimeout = 4000
                requestMethod = "GET"
            }
            val ip = connection.inputStream.bufferedReader().readText().trim()
            connection.disconnect()
            if (ip.isNotBlank()) ip else "Unknown"
        } catch (_: Exception) {
            try {
                val url = URL("http://checkip.amazonaws.com")
                val connection = (url.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 4000
                    readTimeout = 4000
                    requestMethod = "GET"
                }
                val ip = connection.inputStream.bufferedReader().readText().trim()
                connection.disconnect()
                if (ip.isNotBlank()) ip else "Unknown"
            } catch (_: Exception) {
                "Unknown"
            }
        }
    }
}
