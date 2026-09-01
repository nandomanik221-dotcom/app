package com.example.model

data class VpnProfile(
    val id: Long = 0L,
    val name: String,
    val protocol: VpnProtocol,
    val server: String,
    val port: Int,
    val username: String = "",           // Username for SSH, Shadowsocks, or general authentication
    val password: String = "",           // Password for Trojan / SS / SSH or UUID for VMess / VLESS
    val method: String = "chacha20-poly1305", // Cipher/Security method (VMess scy, SS cipher)
    val network: String = "ws",          // "tcp", "ws", "grpc", "httpupgrade"
    val security: String = "tls",        // "tls", "reality", "none"
    val sni: String = "",                // Custom SNI / Server Name / Bug Host
    val path: String = "/ws",            // WebSocket / HTTPUpgrade path
    val host: String = "",               // HTTP Host header
    val realityPublicKey: String = "",   // For Xray Reality
    val realityShortId: String = "",
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshPayload: String = "",         // Custom HTTP / WebSocket payload
    val sshDirectSsl: Boolean = true,

    // Remote Proxy ("Proxy Jarak Jauh") Configuration
    val remoteProxyEnabled: Boolean = false,
    val remoteProxyType: String = "HTTP",      // "HTTP" or "SOCKS5"
    val remoteProxyHost: String = "",
    val remoteProxyPort: Int = 8080,
    val remoteProxyUsername: String? = null,
    val remoteProxyPassword: String? = null,

    val countryCode: String = "SG",      // Country flag ISO code (SG, ID, US, JP, DE, NL, HK, etc.)
    val lastPingMs: Int = -1,
    val isPreset: Boolean = false,
    val isFavorite: Boolean = false,
    val rawUri: String = "",
    val createdAt: Long = System.currentTimeMillis()
) {
    // Backward compatibility aliases
    val proxyEnabled: Boolean get() = remoteProxyEnabled
    val proxyType: String get() = remoteProxyType
    val proxyHost: String get() = remoteProxyHost
    val proxyPort: Int get() = remoteProxyPort
    val proxyUsername: String get() = remoteProxyUsername ?: ""
    val proxyPassword: String get() = remoteProxyPassword ?: ""

    val isTls: Boolean
        get() = security.equals("tls", ignoreCase = true) || security.equals("reality", ignoreCase = true)

    val wsHost: String
        get() = host

    val wsPath: String
        get() = path

    val customPayload: String
        get() = sshPayload

    val effectiveSshUsername: String
        get() = sshUsername.ifBlank { username }

    val effectiveSshPassword: String
        get() = sshPassword.ifBlank { password }

    val displayFlag: String
        get() = when (countryCode.uppercase()) {
            "SG" -> "🇸🇬"
            "ID" -> "🇮🇩"
            "US" -> "🇲🇨" // Fallback / Indonesia
            "US" -> "🇺🇸"
            "JP" -> "🇯🇵"
            "DE" -> "🇩🇪"
            "NL" -> "🇳🇱"
            "HK" -> "🇭🇰"
            "GB", "UK" -> "🇬🇧"
            "AU" -> "🇦🇺"
            "CA" -> "🇨🇦"
            "KR" -> "🇰🇷"
            "MY" -> "🇲🇾"
            "TH" -> "🇹🇭"
            "VN" -> "🇻🇳"
            else -> "🌐"
        }

    val displayAddress: String
        get() = "$server:$port"

    val displaySecurityInfo: String
        get() = buildString {
            append(protocol.displayName)
            if (network.isNotBlank() && protocol != VpnProtocol.SSH && protocol != VpnProtocol.SHADOWSOCKS) {
                append(" • ")
                append(network.uppercase())
            }
            if (security.isNotBlank() && security != "none") {
                append(" • ")
                append(security.uppercase())
            }
            if (protocol == VpnProtocol.SSH) {
                if (sshDirectSsl) append(" • SSL/TLS") else append(" • Direct")
                if (remoteProxyEnabled) append(" • Proxy ($remoteProxyType)")
                if (sni.isNotBlank()) append(" • SNI")
            }
        }
}
