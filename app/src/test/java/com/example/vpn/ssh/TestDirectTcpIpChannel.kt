package com.example.vpn.ssh

import java.io.InputStream
import java.io.OutputStream

class TestDirectTcpIpChannel(
    val inStream: InputStream,
    val outStream: OutputStream
) {

    var isDisconnected = false
    var connected = true

    val isConnected: Boolean get() = connected && !isDisconnected

    val isClosed: Boolean get() = isDisconnected

    val inputStream: InputStream get() = inStream

    val outputStream: OutputStream get() = outStream

    fun disconnect() {
        isDisconnected = true
        connected = false
    }
}
