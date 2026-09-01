package com.example.parser

import android.net.Uri
import android.util.Base64
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import org.json.JSONObject
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

object VpnConfigParser {

    fun parse(rawInput: String): List<VpnProfile> {
        val results = mutableListOf<VpnProfile>()
        val lines = rawInput.trim().split("\r\n", "\n", "\r")
        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isBlank() || trimmed.startsWith("#")) continue
            try {
                when {
                    trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)?.let { results.add(it) }
                    trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)?.let { results.add(it) }
                    trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)?.let { results.add(it) }
                    trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)?.let { results.add(it) }
                    trimmed.startsWith("ssh://", ignoreCase = true) -> parseSsh(trimmed)?.let { results.add(it) }
                    trimmed.startsWith("socks5://", ignoreCase = true) -> parseSocks5(trimmed)?.let { results.add(it) }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        return results
    }

    /**
     * trojan://password@host:port?security=tls&headerType=none&type=ws&sni=sni.domain&path=%2Ftrojan-ws#Singapore-Trojan
     */
    fun parseTrojan(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val password = uri.userInfo ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 443
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "Trojan Server"
            val sni = uri.getQueryParameter("sni") ?: uri.getQueryParameter("peer") ?: host
            val type = uri.getQueryParameter("type") ?: "tcp"
            val security = uri.getQueryParameter("security") ?: "tls"
            val path = uri.getQueryParameter("path")?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: ""
            val httpHost = uri.getQueryParameter("host") ?: ""

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.TROJAN,
                server = host,
                port = port,
                password = password,
                network = type,
                security = security,
                sni = sni,
                path = path,
                host = httpHost,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * vless://uuid@host:port?type=ws&security=tls&path=%2Fvless-ws&host=domain&sni=domain#VLESS-SG
     */
    fun parseVless(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val uuid = uri.userInfo ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 443
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "VLESS Server"
            val type = uri.getQueryParameter("type") ?: "ws"
            val security = uri.getQueryParameter("security") ?: "tls"
            val sni = uri.getQueryParameter("sni") ?: host
            val path = uri.getQueryParameter("path")?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "/ws"
            val httpHost = uri.getQueryParameter("host") ?: ""
            val pbk = uri.getQueryParameter("pbk") ?: ""
            val sid = uri.getQueryParameter("sid") ?: ""

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.VLESS,
                server = host,
                port = port,
                password = uuid,
                network = type,
                security = security,
                sni = sni,
                path = path,
                host = httpHost,
                realityPublicKey = pbk,
                realityShortId = sid,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * vmess://base64(json)
     */
    fun parseVmess(uriString: String): VpnProfile? {
        return try {
            val base64Data = uriString.substringAfter("vmess://").trim()
            val decodedJson = String(decodeBase64Safe(base64Data), StandardCharsets.UTF_8)
            val json = JSONObject(decodedJson)

            val remark = json.optString("ps", "VMess Server")
            val host = json.optString("add", "")
            val port = json.optString("port").toIntOrNull() ?: json.optInt("port", 443)
            val id = json.optString("id", "")
            val aid = json.optString("aid").toIntOrNull() ?: json.optInt("aid", 0)
            val scy = json.optString("scy", "auto")
            val net = json.optString("net", "ws")
            val type = json.optString("type", "none")
            val httpHost = json.optString("host", "")
            val path = json.optString("path", "/ws")
            val tls = json.optString("tls", "tls")
            val sni = json.optString("sni", if (httpHost.isNotBlank()) httpHost else host)

            if (host.isBlank() || id.isBlank()) return null

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.VMESS,
                server = host,
                port = port,
                password = id,
                method = scy,
                network = net,
                security = if (tls.equals("tls", ignoreCase = true)) "tls" else "none",
                sni = sni,
                path = path,
                host = httpHost,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * ss://base64(method:password@host:port)#remark
     * or ss://base64(method:password)@host:port#remark
     */
    fun parseShadowsocks(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "Shadowsocks Server"
            var method = "chacha20-ietf-poly1305"
            var password = ""
            var host = ""
            var port = 8388

            if (uri.userInfo != null && uri.host != null) {
                // Format: ss://base64(method:password)@host:port
                val decodedUserInfo = try {
                    String(decodeBase64Safe(uri.userInfo ?: ""), StandardCharsets.UTF_8)
                } catch (e: Exception) {
                    uri.userInfo ?: ""
                }
                val parts = decodedUserInfo.split(":", limit = 2)
                if (parts.size == 2) {
                    method = parts[0]
                    password = parts[1]
                }
                host = uri.host ?: ""
                port = if (uri.port != -1) uri.port else 8388
            } else {
                // Format: ss://base64(method:password@host:port)#remark
                val rawEncoded = uriString.substringAfter("ss://").substringBefore("#")
                val decoded = String(decodeBase64Safe(rawEncoded), StandardCharsets.UTF_8)
                val atIndex = decoded.lastIndexOf('@')
                if (atIndex != -1) {
                    val userPart = decoded.substring(0, atIndex)
                    val serverPart = decoded.substring(atIndex + 1)

                    val userParts = userPart.split(":", limit = 2)
                    if (userParts.size == 2) {
                        method = userParts[0]
                        password = userParts[1]
                    }

                    val serverParts = serverPart.split(":", limit = 2)
                    if (serverParts.size == 2) {
                        host = serverParts[0]
                        port = serverParts[1].toIntOrNull() ?: 8388
                    }
                }
            }

            if (host.isBlank() || password.isBlank()) return null

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.SHADOWSOCKS,
                server = host,
                port = port,
                password = password,
                method = method,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * ssh://user:password@host:port#remark
     */
    fun parseSsh(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val username = uri.userInfo?.substringBefore(":") ?: "root"
            val password = uri.userInfo?.substringAfter(":", "") ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 22
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "SSH Tunnel"
            val sni = uri.getQueryParameter("sni") ?: ""
            val payload = uri.getQueryParameter("payload")?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: ""

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.SSH,
                server = host,
                port = port,
                username = username,
                password = password,
                sni = sni,
                sshPayload = payload,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    fun parseSocks5(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val username = uri.userInfo?.substringBefore(":") ?: ""
            val password = uri.userInfo?.substringAfter(":", "") ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 1080
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "SOCKS5 Proxy"

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.SOCKS5,
                server = host,
                port = port,
                username = username,
                password = password,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    fun exportToUri(profile: VpnProfile): String {
        return when (profile.protocol) {
            VpnProtocol.VMESS -> {
                val json = JSONObject().apply {
                    put("v", "2")
                    put("ps", profile.name)
                    put("add", profile.server)
                    put("port", profile.port)
                    put("id", profile.password)
                    put("aid", 0)
                    put("scy", profile.method.ifBlank { "auto" })
                    put("net", profile.network.ifBlank { "ws" })
                    put("type", "none")
                    put("host", profile.host)
                    put("path", profile.path.ifBlank { "/ws" })
                    put("tls", if (profile.isTls) "tls" else "none")
                    put("sni", profile.sni)
                }
                "vmess://${Base64.encodeToString(json.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)}"
            }
            VpnProtocol.VLESS -> {
                val encodedPath = URLEncoder.encode(profile.path, StandardCharsets.UTF_8.name())
                val remark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                "vless://${profile.password}@${profile.server}:${profile.port}?type=${profile.network}&security=${profile.security}&path=$encodedPath&host=${profile.host}&sni=${profile.sni}&pbk=${profile.realityPublicKey}&sid=${profile.realityShortId}#$remark"
            }
            VpnProtocol.TROJAN -> {
                val encodedPath = URLEncoder.encode(profile.path, StandardCharsets.UTF_8.name())
                val remark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                "trojan://${profile.password}@${profile.server}:${profile.port}?security=${profile.security}&type=${profile.network}&sni=${profile.sni}&path=$encodedPath&host=${profile.host}#$remark"
            }
            VpnProtocol.SHADOWSOCKS -> {
                val userPass = "${profile.method}:${profile.password}"
                val encoded = Base64.encodeToString(userPass.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
                val remark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                "ss://$encoded@${profile.server}:${profile.port}#$remark"
            }
            VpnProtocol.SSH -> {
                val remark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                "ssh://${profile.username}:${profile.password}@${profile.server}:${profile.port}?sni=${profile.sni}#$remark"
            }
            VpnProtocol.SOCKS5 -> {
                val remark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                if (profile.username.isNotBlank()) {
                    "socks5://${profile.username}:${profile.password}@${profile.server}:${profile.port}#$remark"
                } else {
                    "socks5://${profile.server}:${profile.port}#$remark"
                }
            }
        }
    }

    private fun decodeBase64Safe(input: String): ByteArray {
        var clean = input.trim().replace("\n", "").replace("\r", "").replace(" ", "")
        while (clean.length % 4 != 0) {
            clean += "="
        }
        return try {
            java.util.Base64.getDecoder().decode(clean)
        } catch (e: Exception) {
            try {
                java.util.Base64.getUrlDecoder().decode(clean)
            } catch (e2: Exception) {
                Base64.decode(clean, Base64.DEFAULT or Base64.URL_SAFE)
            }
        }
    }

    private fun detectCountry(name: String, host: String): String {
        val lower = "${name.lowercase()} ${host.lowercase()}"
        return when {
            lower.contains("sg") || lower.contains("singapore") -> "SG"
            lower.contains("id") || lower.contains("indonesia") || lower.contains("jakarta") -> "ID"
            lower.contains("us") || lower.contains("united states") || lower.contains("america") -> "US"
            lower.contains("jp") || lower.contains("japan") || lower.contains("tokyo") -> "JP"
            lower.contains("de") || lower.contains("germany") || lower.contains("frankfurt") -> "DE"
            lower.contains("nl") || lower.contains("netherlands") || lower.contains("amsterdam") -> "NL"
            lower.contains("hk") || lower.contains("hong kong") -> "HK"
            lower.contains("au") || lower.contains("australia") || lower.contains("sydney") -> "AU"
            lower.contains("ca") || lower.contains("canada") || lower.contains("toronto") -> "CA"
            else -> "US"
        }
    }
}
