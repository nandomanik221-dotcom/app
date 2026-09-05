package com.example.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.example.model.VpnProfile
import com.example.model.VpnProtocol

@Entity(tableName = "vpn_profiles")
data class VpnProfileEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0L,
    val name: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val username: String = "",
    val password: String = "",
    val method: String = "chacha20-poly1305",
    val network: String = "ws",
    val security: String = "tls",
    val sni: String = "",
    val path: String = "/ws",
    val host: String = "",
    val realityPublicKey: String = "",
    val realityShortId: String = "",
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshPayload: String = "",
    val sshDirectSsl: Boolean = true,
    val sshTransport: String = "STANDARD",
    val sniVersion: String = "Default",
    val allowInsecure: Boolean = false,
    val sshPayloadEnabled: Boolean = true,
    val sshMethod: String = "TLS",

    // Remote Proxy fields
    val remoteProxyEnabled: Boolean = false,
    val remoteProxyType: String = "HTTP",
    val remoteProxyHost: String = "",
    val remoteProxyPort: Int = 8080,
    val remoteProxyUsername: String? = null,
    val remoteProxyPassword: String? = null,

    val countryCode: String = "SG",
    val lastPingMs: Int = -1,
    val isPreset: Boolean = false,
    val isFavorite: Boolean = false,
    val rawUri: String = "",
    val createdAt: Long = System.currentTimeMillis()
) {
    fun toDomain(): VpnProfile {
        val effectiveUsername = username.ifBlank { sshUsername }
        val effectivePassword = password.ifBlank { sshPassword }
        return VpnProfile(
            id = id,
            name = name,
            protocol = VpnProtocol.fromString(protocol),
            server = server,
            port = port,
            username = effectiveUsername,
            password = effectivePassword,
            method = method,
            network = network,
            security = security,
            sni = sni,
            path = path,
            host = host,
            realityPublicKey = realityPublicKey,
            realityShortId = realityShortId,
            sshUsername = sshUsername.ifBlank { effectiveUsername },
            sshPassword = sshPassword.ifBlank { effectivePassword },
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
            remoteProxyUsername = remoteProxyUsername,
            remoteProxyPassword = remoteProxyPassword,
            countryCode = countryCode,
            lastPingMs = lastPingMs,
            isPreset = isPreset,
            isFavorite = isFavorite,
            rawUri = rawUri,
            createdAt = createdAt
        )
    }

    companion object {
        fun fromDomain(domain: VpnProfile): VpnProfileEntity {
            val effectiveUsername = domain.username.ifBlank { domain.sshUsername }
            val effectivePassword = domain.password.ifBlank { domain.sshPassword }
            return VpnProfileEntity(
                id = domain.id,
                name = domain.name,
                protocol = domain.protocol.name,
                server = domain.server,
                port = domain.port,
                username = effectiveUsername,
                password = effectivePassword,
                method = domain.method,
                network = domain.network,
                security = domain.security,
                sni = domain.sni,
                path = domain.path,
                host = domain.host,
                realityPublicKey = domain.realityPublicKey,
                realityShortId = domain.realityShortId,
                sshUsername = domain.sshUsername.ifBlank { effectiveUsername },
                sshPassword = domain.sshPassword.ifBlank { effectivePassword },
                sshPayload = domain.sshPayload,
                sshDirectSsl = domain.sshDirectSsl,
                sshTransport = domain.sshTransport,
                sniVersion = domain.sniVersion,
                allowInsecure = domain.allowInsecure,
                sshPayloadEnabled = domain.sshPayloadEnabled,
                sshMethod = domain.sshMethod,
                remoteProxyEnabled = domain.remoteProxyEnabled,
                remoteProxyType = domain.remoteProxyType,
                remoteProxyHost = domain.remoteProxyHost,
                remoteProxyPort = domain.remoteProxyPort,
                remoteProxyUsername = domain.remoteProxyUsername,
                remoteProxyPassword = domain.remoteProxyPassword,
                countryCode = domain.countryCode,
                lastPingMs = domain.lastPingMs,
                isPreset = domain.isPreset,
                isFavorite = domain.isFavorite,
                rawUri = domain.rawUri,
                createdAt = domain.createdAt
            )
        }
    }
}
