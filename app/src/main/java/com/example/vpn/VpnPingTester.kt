package com.example.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import kotlin.system.measureTimeMillis

object VpnPingTester {

    suspend fun ping(host: String, port: Int, timeoutMs: Int = 2000): Int = withContext(Dispatchers.IO) {
        if (host.isBlank()) return@withContext -1

        // 1. Try TCP Socket connect
        try {
            val validPort = if (port in 1..65535) port else 443
            var elapsedMs = -1L
            Socket().use { socket ->
                elapsedMs = measureTimeMillis {
                    socket.connect(InetSocketAddress(host, validPort), timeoutMs)
                }
            }
            if (elapsedMs in 1..10000) {
                return@withContext elapsedMs.toInt()
            }
        } catch (e: Exception) {
            // TCP connect failed or filtered, fallback to HTTP check
        }

        // 2. Fallback to HTTP/HTTPS ping
        try {
            val urlString = if (port == 443) "https://$host" else "http://$host:$port"
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
            if (elapsedMs in 1..10000) {
                return@withContext elapsedMs.toInt()
            }
        } catch (e: Exception) {
            // Ping failed
        }

        // Real check failed or host unreachable
        return@withContext -1
    }
}
