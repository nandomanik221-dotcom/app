package com.example.vpn.backend

import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

/**
 * Common abstraction for all VPN protocol backend engines.
 * Decouples protocol dispatching (SSH, VMess, VLESS, Trojan, Shadowsocks, SOCKS5)
 * from the Local SOCKS5 listener and Tun2Socks packet router.
 */
interface ITunnelBackend {
    val backendName: String
    val totalBytesSent: AtomicLong
    val totalBytesReceived: AtomicLong

    /**
     * Verifies the protocol-specific outbound handshake against the remote server.
     */
    suspend fun verifyHandshake(): Result<Unit>

    /**
     * Creates a new tunneled TCP socket to the specified target host and port
     * through this protocol backend.
     */
    fun createTunnelSocket(targetHost: String, targetPort: Int): Socket

    /**
     * Stops the backend engine and releases all associated sockets and resources.
     */
    fun stop()
}
