package com.example.model

import androidx.compose.ui.graphics.Color

enum class VpnProtocol(
    val displayName: String,
    val description: String,
    val badgeColorHex: Long
) {
    TROJAN("Trojan", "TLS Encrypted Proxy", 0xFF00E676),
    VLESS("VLESS (Xray)", "Lightweight V2Ray Next-Gen", 0xFF00E5FF),
    VMESS("VMess (V2Ray)", "Full Encrypted Protocol", 0xFF7C4DFF),
    SHADOWSOCKS("Shadowsocks", "High-Performance SOCKS5", 0xFFFF9100),
    SSH("SSH Tunnel", "Custom Payload & SSL SNI", 0xFFFF5252),
    SOCKS5("SOCKS5 Proxy", "Standard TCP/UDP Proxy", 0xFF607D8B);

    val badgeColor: Color
        get() = Color(badgeColorHex)

    companion object {
        fun fromString(value: String): VpnProtocol {
            return entries.firstOrNull { 
                it.name.equals(value, ignoreCase = true) || 
                it.displayName.contains(value, ignoreCase = true)
            } ?: TROJAN
        }
    }
}

enum class VpnConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    RECONNECTING,
    ERROR
}

data class VpnMetrics(
    val downloadSpeedBytesPerSec: Long = 0L,
    val uploadSpeedBytesPerSec: Long = 0L,
    val totalDownloadBytes: Long = 0L,
    val totalUploadBytes: Long = 0L,
    val durationSeconds: Long = 0L,
    val pingMs: Int = -1,
    val publicIp: String = "104.28.19.42",
    val isp: String = "Cloudflare Warp CDN",
    val country: String = "Singapore",
    val city: String = "Jurong West"
)

enum class LogLevel {
    INFO,
    CONN,
    HANDSHAKE,
    TLS,
    ROUTING,
    DATA,
    WARN,
    ERROR
}

data class VpnLogEntry(
    val timestamp: Long = System.currentTimeMillis(),
    val level: LogLevel = LogLevel.INFO,
    val tag: String,
    val message: String
)

data class DnsServer(
    val id: String,
    val name: String,
    val primaryIp: String,
    val secondaryIp: String,
    val description: String
) {
    companion object {
        val PRESETS = listOf(
            DnsServer("cloudflare", "Cloudflare DNS", "1.1.1.1", "1.0.0.1", "Fastest & privacy focused"),
            DnsServer("google", "Google Public DNS", "8.8.8.8", "8.8.4.4", "Global reliability"),
            DnsServer("adguard", "AdGuard DNS", "94.140.14.14", "94.140.15.15", "Blocks ads and trackers"),
            DnsServer("quad9", "Quad9 DNS", "9.9.9.9", "149.112.112.112", "Malware blocking"),
            DnsServer("custom", "Custom DNS", "1.1.1.1", "8.8.8.8", "User configured DNS")
        )
    }
}
