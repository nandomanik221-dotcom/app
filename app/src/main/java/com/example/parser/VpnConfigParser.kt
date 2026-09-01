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
            val base64Data = uriString.substringAfter("vmess://")
            val decodedJson = String(Base64.decode(base64Data, Base64.DEFAULT), StandardCharsets.UTF_8)
            val json = JSONObject(decodedJson)

            val remark = json.optString("ps", "VMess Server")
            val host = json.optString("add", "")
            val port = json.optInt("port", 443)
            val id = json.optString("id", "")
            val aid = json.optInt("aid", 0)
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
                    String(Base64.decode(uri.userInfo, Base64.NO_WRAP or Base64.URL_SAFE), StandardCharsets.UTF_8)
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
                // Format: ss://base64(method:password@host:port)
                val rawEncoded = uriString.substringAfter("ss://").substringBefore("#")
                val decoded = String(Base64.decode(rawEncoded, Base64.NO_WRAP or Base64.URL_SAFE), StandardCharsets.UTF_8)
                // decoded = method:password@host:port
                val atSplit = decoded.split("@", limit = 2)
                if (atSplit.size == 2) {
                    val auth = atSplit[0].split(":", limit = 2)
                    if (auth.size == 2) {
                        method = auth[0]
                        password = auth[1]
                    }
                    val addr = atSplit[1].split(":", limit = 2)
                    host = addr[0]
                    if (addr.size == 2) {
                        port = addr[1].toIntOrNull() ?: 8388
                    }
                }
            }

            if (host.isBlank()) return null

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.SHADOWSOCKS,
                server = host,
                port = port,
                password = password,
                method = method,
                security = "none",
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * ssh://username:password@host:port?sni=bug.com&payload=...#SSH-ID
     */
    fun parseSsh(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val userInfo = uri.userInfo?.split(":", limit = 2)
            val username = userInfo?.getOrNull(0) ?: "root"
            val password = userInfo?.getOrNull(1) ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port != -1) uri.port else 22
            val remark = uri.fragment?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: "SSH Tunnel Server"
            val sni = uri.getQueryParameter("sni") ?: host
            val payload = uri.getQueryParameter("payload")?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) } ?: ""
            val isSsl = uri.getQueryParameter("ssl")?.toBoolean() ?: true

            VpnProfile(
                name = remark,
                protocol = VpnProtocol.SSH,
                server = host,
                port = port,
                sshUsername = username,
                sshPassword = password,
                sni = sni,
                sshPayload = payload,
                sshDirectSsl = isSsl,
                countryCode = detectCountry(remark, host),
                rawUri = uriString
            )
        } catch (e: Exception) {
            null
        }
    }

    fun exportToUri(profile: VpnProfile): String {
        return when (profile.protocol) {
            VpnProtocol.TROJAN -> {
                val encRemark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                val encPath = URLEncoder.encode(profile.path, StandardCharsets.UTF_8.name())
                "trojan://${profile.password}@${profile.server}:${profile.port}?security=${profile.security}&type=${profile.network}&sni=${profile.sni}&path=$encPath&host=${profile.host}#$encRemark"
            }
            VpnProtocol.VLESS -> {
                val encRemark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                val encPath = URLEncoder.encode(profile.path, StandardCharsets.UTF_8.name())
                "vless://${profile.password}@${profile.server}:${profile.port}?type=${profile.network}&security=${profile.security}&sni=${profile.sni}&path=$encPath&host=${profile.host}#$encRemark"
            }
            VpnProtocol.VMESS -> {
                val json = JSONObject().apply {
                    put("v", "2")
                    put("ps", profile.name)
                    put("add", profile.server)
                    put("port", profile.port)
                    put("id", profile.password)
                    put("aid", 0)
                    put("scy", profile.method)
                    put("net", profile.network)
                    put("type", "none")
                    put("host", profile.host)
                    put("path", profile.path)
                    put("tls", profile.security)
                    put("sni", profile.sni)
                }
                val base64 = Base64.encodeToString(json.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
                "vmess://$base64"
            }
            VpnProtocol.SHADOWSOCKS -> {
                val auth = "${profile.method}:${profile.password}@${profile.server}:${profile.port}"
                val base64 = Base64.encodeToString(auth.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP or Base64.URL_SAFE)
                val encRemark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                "ss://$base64#$encRemark"
            }
            VpnProtocol.SSH -> {
                val encRemark = URLEncoder.encode(profile.name, StandardCharsets.UTF_8.name())
                val encPayload = URLEncoder.encode(profile.sshPayload, StandardCharsets.UTF_8.name())
                "ssh://${profile.sshUsername}:${profile.sshPassword}@${profile.server}:${profile.port}?sni=${profile.sni}&ssl=${profile.sshDirectSsl}&payload=$encPayload#$encRemark"
            }
            else -> {
                "socks5://${profile.server}:${profile.port}"
            }
        }
    }

    private fun detectCountry(remark: String, host: String): String {
        val combined = "$remark $host".uppercase()
        return when {
            combined.contains("SG") || combined.contains("SINGAPORE") -> "SG"
            combined.contains("ID") || combined.contains("INDONESIA") || combined.contains("JAKARTA") -> "ID"
            combined.contains("US") || combined.contains("USA") || combined.contains("UNITED STATES") -> "US"
            combined.contains("JP") || combined.contains("JAPAN") || combined.contains("TOKYO") -> "JP"
            combined.contains("DE") || combined.contains("GERMANY") || combined.contains("FRANKFURT") -> "DE"
            combined.contains("NL") || combined.contains("NETHERLAND") || combined.contains("AMSTERDAM") -> "NL"
            combined.contains("HK") || combined.contains("HONG KONG") -> "HK"
            combined.contains("UK") || combined.contains("GB") || combined.contains("LONDON") -> "GB"
            combined.contains("MY") || combined.contains("MALAYSIA") -> "MY"
            else -> "SG"
        }
    }
}
