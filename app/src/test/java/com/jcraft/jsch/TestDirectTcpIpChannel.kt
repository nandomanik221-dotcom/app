package com.jcraft.jsch

import java.io.InputStream
import java.io.OutputStream

class TestDirectTcpIpChannel(
    private val inStream: InputStream,
    private val outStream: OutputStream
) : ChannelDirectTCPIP() {

    var isDisconnected = false

    init {
        this.connected = true
    }

    override fun isConnected(): Boolean = connected && !isDisconnected

    override fun isClosed(): Boolean = isDisconnected

    override fun getInputStream(): InputStream = inStream

    override fun getOutputStream(): OutputStream = outStream

    override fun disconnect() {
        isDisconnected = true
        connected = false
    }
}
