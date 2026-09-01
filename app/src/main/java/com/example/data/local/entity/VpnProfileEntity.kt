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
    val countryCode: String = "SG",
    val lastPingMs: Int = -1,
    val isPreset: Boolean = false,
    val isFavorite: Boolean = false,
    val rawUri: String = "",
    val createdAt: Long = System.currentTimeMillis()
) {
    fun toDomain(): VpnProfile {
        val effectiveUsername = username.ifBlank { sshUsername }
        return VpnProfile(
            id = id,
            name = name,
            protocol = VpnProtocol.fromString(protocol),
            server = server,
            port = port,
            username = effectiveUsername,
            password = password,
            method = method,
            network = network,
            security = security,
            sni = sni,
            path = path,
            host = host,
            realityPublicKey = realityPublicKey,
            realityShortId = realityShortId,
            sshUsername = sshUsername.ifBlank { effectiveUsername },
            sshPassword = sshPassword.ifBlank { password },
            sshPayload = sshPayload,
            sshDirectSsl = sshDirectSsl,
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
                sshUsername = effectiveUsername,
                sshPassword = effectivePassword,
                sshPayload = domain.sshPayload,
                sshDirectSsl = domain.sshDirectSsl,
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
