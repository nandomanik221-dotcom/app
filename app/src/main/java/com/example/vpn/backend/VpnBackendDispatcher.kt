package com.example.vpn.backend

import android.net.VpnService
import com.example.model.LogLevel
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.vpn.VpnLogManager
import com.example.vpn.shadowsocks.ShadowsocksTunnelClient
import com.example.vpn.socks.Socks5TunnelClient
import com.example.vpn.ssh.SshTunnelClient
import com.example.vpn.trojan.TrojanTunnelClient
import com.example.vpn.xray.VlessTunnelClient
import com.example.vpn.xray.XrayVmessClient

/**
 * Protocol-aware VPN Connection Dispatcher.
 * 
 * Strict routing guarantee:
 * - If protocol == SSH -> ONLY SSH backend is instantiated and executed.
 * - If protocol == VMESS -> ONLY Xray VMess backend is instantiated and executed.
 * - If protocol == VLESS -> ONLY VLESS backend is instantiated and executed.
 * - If protocol == TROJAN -> ONLY Trojan backend is instantiated and executed.
 * - If protocol == SHADOWSOCKS -> ONLY Shadowsocks backend is instantiated and executed.
 * - If protocol == SOCKS5 -> ONLY SOCKS5 backend is instantiated and executed.
 * 
 * Never mixes protocol backends or assumes protocols from ports (80/443).
 */
object VpnBackendDispatcher {

    fun dispatch(vpnService: VpnService, profile: VpnProfile): ITunnelBackend {
        // Diagnostic profile logging
        VpnLogManager.log(
            LogLevel.INFO,
            "PROFILE",
            "[PROFILE]\nid=${profile.id}\nname=${profile.name}\nprotocol=${profile.protocol.name}\nhost=${profile.server}\nport=${profile.port}"
        )

        return when (profile.protocol) {
            VpnProtocol.SSH -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=SSH\nbackend=SSH")
                SshTunnelClient(vpnService, profile)
            }
            VpnProtocol.VMESS -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=VMESS\nbackend=XrayVmessClient")
                XrayVmessClient(vpnService, profile)
            }
            VpnProtocol.VLESS -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=VLESS\nbackend=VlessTunnelClient")
                VlessTunnelClient(vpnService, profile)
            }
            VpnProtocol.TROJAN -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=TROJAN\nbackend=TrojanTunnelClient")
                TrojanTunnelClient(vpnService, profile)
            }
            VpnProtocol.SHADOWSOCKS -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=SHADOWSOCKS\nbackend=ShadowsocksTunnelClient")
                ShadowsocksTunnelClient(vpnService, profile)
            }
            VpnProtocol.SOCKS5 -> {
                VpnLogManager.log(LogLevel.INFO, "DISPATCH", "[DISPATCH]\nprotocol=SOCKS5\nbackend=Socks5TunnelClient")
                Socks5TunnelClient(vpnService, profile)
            }
        }
    }
}
