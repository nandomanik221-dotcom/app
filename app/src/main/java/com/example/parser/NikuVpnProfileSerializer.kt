package com.example.parser

import android.util.Base64
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Serializer and Deserializer for the official V2Tunnel .nikuvpn.tl configuration format.
 *
 * Features:
 * - Versioned structured JSON format
 * - Supports SSH, Trojan, VLESS, VMess, Shadowsocks, SOCKS5
 * - Remote Proxy ("Proxy Jarak Jauh") serialization
 * - Obfuscates/encrypts credentials using AES-GCM so passwords are not exposed in plaintext
 * - Full backward and forward compatibility
 */
object NikuVpnProfileSerializer {

    const val FORMAT_IDENTIFIER = "nikuvpn"
    const val CURRENT_VERSION = 1
    const val FILE_EXTENSION = ".nikuvpn.tl"

    private const val SECRET_SEED = "V2Tunnel_NikuVpn_SecureProfile_v1_SaltKey_2026"

    /**
     * Serializes a [VpnProfile] into a `.nikuvpn.tl` structured JSON string.
     */
    fun serialize(profile: VpnProfile): String {
        val root = JSONObject()
        root.put("format", FORMAT_IDENTIFIER)
        root.put("version", CURRENT_VERSION)
        root.put("type", profile.protocol.name.lowercase())
        root.put("createdAt", System.currentTimeMillis())

        val profObj = JSONObject().apply {
            put("name", profile.name)
            put("protocol", profile.protocol.name)
            put("server", profile.server)
            put("port", profile.port)
            put("sni", profile.sni)
            put("network", profile.network)
            put("security", profile.security)
            put("path", profile.path)
            put("host", profile.host)
            put("countryCode", profile.countryCode)

            // SSH specific fields
            put("sshDirectSsl", profile.sshDirectSsl)
            put("sshPayload", profile.sshPayload)
            put("sshTransport", profile.sshTransport)
            put("sniVersion", profile.sniVersion)
            put("allowInsecure", profile.allowInsecure)
            put("sshPayloadEnabled", profile.sshPayloadEnabled)
            put("sshMethod", profile.sshMethod)

            // Remote Proxy fields
            put("remoteProxyEnabled", profile.remoteProxyEnabled)
            put("remoteProxyType", profile.remoteProxyType)
            put("remoteProxyHost", profile.remoteProxyHost)
            put("remoteProxyPort", profile.remoteProxyPort)

            // Encryption method (for Shadowsocks)
            put("method", profile.method)

            // Encrypted credentials container
            val authObj = JSONObject().apply {
                val effectiveUser = profile.effectiveSshUsername
                val effectivePass = profile.effectiveSshPassword
                val effectiveProxyUser = profile.remoteProxyUsername ?: ""
                val effectiveProxyPass = profile.remoteProxyPassword ?: ""

                put("u", effectiveUser)
                put("p_enc", encryptSecret(effectivePass))
                put("pu", effectiveProxyUser)
                put("pp_enc", encryptSecret(effectiveProxyPass))
                put("pbk", profile.realityPublicKey)
                put("sid", profile.realityShortId)
            }
            put("auth", authObj)
        }

        root.put("profile", profObj)
        return root.toString(2)
    }

    /**
     * Deserializes a `.nikuvpn.tl` structured JSON string back into a [VpnProfile].
     */
    fun deserialize(jsonString: String): VpnProfile? {
        return try {
            val root = JSONObject(jsonString)
            val format = root.optString("format", "")
            if (!format.equals(FORMAT_IDENTIFIER, ignoreCase = true)) {
                return null
            }

            val profObj = root.optJSONObject("profile") ?: return null
            val protoStr = profObj.optString("protocol", "SSH")
            val protocol = VpnProtocol.fromString(protoStr)

            val name = profObj.optString("name", "${protocol.displayName} Server")
            val server = profObj.optString("server", "")
            val port = profObj.optInt("port", 443)
            val sni = profObj.optString("sni", "")
            val network = profObj.optString("network", "ws")
            val security = profObj.optString("security", "tls")
            val path = profObj.optString("path", "/ws")
            val host = profObj.optString("host", "")
            val countryCode = profObj.optString("countryCode", "SG")
            val method = profObj.optString("method", "chacha20-poly1305")

            val sshDirectSsl = profObj.optBoolean("sshDirectSsl", true)
            val sshPayload = profObj.optString("sshPayload", "")
            val sshTransport = profObj.optString("sshTransport", "STANDARD")
            val sniVersion = profObj.optString("sniVersion", "Default")
            val allowInsecure = profObj.optBoolean("allowInsecure", false)
            val sshPayloadEnabled = profObj.optBoolean("sshPayloadEnabled", true)
            val sshMethod = profObj.optString("sshMethod", if (sshDirectSsl) "TLS" else "Enhanced")

            val remoteProxyEnabled = profObj.optBoolean("remoteProxyEnabled", profObj.optBoolean("proxyEnabled", false))
            val remoteProxyType = profObj.optString("remoteProxyType", profObj.optString("proxyType", "HTTP"))
            val remoteProxyHost = profObj.optString("remoteProxyHost", profObj.optString("proxyHost", ""))
            val remoteProxyPort = profObj.optInt("remoteProxyPort", profObj.optInt("proxyPort", 8080))

            // Parse auth container
            val authObj = profObj.optJSONObject("auth")
            var username = ""
            var password = ""
            var proxyUsername = ""
            var proxyPassword = ""
            var realityPublicKey = ""
            var realityShortId = ""

            if (authObj != null) {
                username = authObj.optString("u", "")
                val pEnc = authObj.optString("p_enc", "")
                password = if (pEnc.isNotBlank()) decryptSecret(pEnc) else authObj.optString("p", "")

                proxyUsername = authObj.optString("pu", "")
                val ppEnc = authObj.optString("pp_enc", "")
                proxyPassword = if (ppEnc.isNotBlank()) decryptSecret(ppEnc) else authObj.optString("pp", "")

                realityPublicKey = authObj.optString("pbk", "")
                realityShortId = authObj.optString("sid", "")
            }

            if (server.isBlank()) return null

            VpnProfile(
                name = name,
                protocol = protocol,
                server = server,
                port = port,
                username = username,
                password = password,
                method = method,
                network = network,
                security = security,
                sni = sni,
                path = path,
                host = host,
                realityPublicKey = realityPublicKey,
                realityShortId = realityShortId,
                sshUsername = username,
                sshPassword = password,
                sshPayload = sshPayload,
                sshDirectSsl = sshDirectSsl,
                sshTransport = sshTransport,
                sniVersion = sniVersion,
                allowInsecure = allowInsecure,
                sshPayloadEnabled = sshPayloadEnabled,
                sshMethod = sshMethod,
                remoteProxyEnabled = remoteProxyEnabled,
                remoteProxyType = remoteProxyType,
                remoteProxyHost = remoteProxyHost,
                remoteProxyPort = remoteProxyPort,
                remoteProxyUsername = proxyUsername.ifBlank { null },
                remoteProxyPassword = proxyPassword.ifBlank { null },
                countryCode = countryCode,
                rawUri = jsonString
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Checks whether raw input starts with or contains a valid .nikuvpn.tl JSON structure.
     */
    fun isNikuVpnConfig(input: String): Boolean {
        val trimmed = input.trim()
        return (trimmed.startsWith("{") && trimmed.contains("\"format\"") && trimmed.contains("\"nikuvpn\""))
    }

    // --- Credential Encryption Utilities ---

    private fun getKeySpec(): SecretKeySpec {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha256.digest(SECRET_SEED.toByteArray(StandardCharsets.UTF_8))
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun encryptSecret(plaintext: String): String {
        if (plaintext.isBlank()) return ""
        return try {
            val key = getKeySpec()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(12) { (it * 7 + 13).toByte() } // Deterministic 12-byte IV for profile portability
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
            val cipherText = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
            Base64.encodeToString(cipherText, Base64.NO_WRAP)
        } catch (e: Exception) {
            // Fallback to obfuscated base64
            Base64.encodeToString(plaintext.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
        }
    }

    private fun decryptSecret(ciphertext: String): String {
        if (ciphertext.isBlank()) return ""
        return try {
            val key = getKeySpec()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = ByteArray(12) { (it * 7 + 13).toByte() }
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
            val rawBytes = Base64.decode(ciphertext, Base64.NO_WRAP)
            val plainBytes = cipher.doFinal(rawBytes)
            String(plainBytes, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            // Try fallback plain base64 decode
            try {
                String(Base64.decode(ciphertext, Base64.NO_WRAP), StandardCharsets.UTF_8)
            } catch (e2: Exception) {
                ""
            }
        }
    }
}
