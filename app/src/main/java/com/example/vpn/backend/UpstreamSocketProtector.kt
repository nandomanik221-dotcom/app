package com.example.vpn.backend

import java.net.DatagramSocket
import java.net.Socket

/**
 * Abstraction for protecting outbound sockets from VPN routing loops.
 * Verifies that the upstream transport socket bypasses the Android TUN interface.
 */
interface UpstreamSocketProtector {
    /**
     * Protects a TCP socket from being routed back into the VPN TUN interface.
     * Must be called before connecting the socket.
     */
    fun protect(socket: Socket): Boolean

    /**
     * Protects a UDP DatagramSocket from being routed back into the VPN TUN interface.
     */
    fun protect(socket: DatagramSocket): Boolean = false

    /**
     * Returns true if the underlying Android TUN interface is currently established and active.
     */
    fun isVpnInterfaceActive(): Boolean = false
}
