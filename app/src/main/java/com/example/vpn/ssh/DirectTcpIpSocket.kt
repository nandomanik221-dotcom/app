package com.example.vpn.ssh

import com.jcraft.jsch.ChannelDirectTCPIP
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Socket wrapper representing an active SSH `direct-tcpip` port-forwarding channel.
 *
 * Implements standard java.net.Socket stream operations over the underlying SSH channel,
 * ensuring accurate real-time byte counters and proper channel lifecycle teardown.
 */
class DirectTcpIpSocket(
    val channel: ChannelDirectTCPIP,
    val targetHost: String,
    val targetPort: Int,
    private val totalBytesSent: AtomicLong,
    private val totalBytesReceived: AtomicLong
) : Socket() {

    private val closed = AtomicBoolean(false)
    private val inStream by lazy {
        CountingInputStream(channel.inputStream, totalBytesReceived)
    }
    private val outStream by lazy {
        CountingOutputStream(channel.outputStream, totalBytesSent)
    }

    override fun getInputStream(): InputStream = inStream

    override fun getOutputStream(): OutputStream = outStream

    override fun isConnected(): Boolean = channel.isConnected && !closed.get()

    override fun isClosed(): Boolean = closed.get() || channel.isClosed || !channel.isConnected

    override fun getRemoteSocketAddress(): SocketAddress = InetSocketAddress(targetHost, targetPort)

    override fun getLocalSocketAddress(): SocketAddress = InetSocketAddress("127.0.0.1", 0)

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try {
                channel.disconnect()
            } catch (_: Exception) {}
        }
    }

    private class CountingInputStream(
        private val delegate: InputStream,
        private val counter: AtomicLong
    ) : InputStream() {

        override fun read(): Int {
            val b = delegate.read()
            if (b != -1) {
                counter.incrementAndGet()
            }
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val count = delegate.read(b, off, len)
            if (count > 0) {
                counter.addAndGet(count.toLong())
            }
            return count
        }

        override fun available(): Int = delegate.available()

        override fun close() {
            delegate.close()
        }
    }

    private class CountingOutputStream(
        private val delegate: OutputStream,
        private val counter: AtomicLong
    ) : OutputStream() {

        override fun write(b: Int) {
            delegate.write(b)
            counter.incrementAndGet()
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            delegate.write(b, off, len)
            if (len > 0) {
                counter.addAndGet(len.toLong())
            }
        }

        override fun flush() {
            delegate.flush()
        }

        override fun close() {
            delegate.close()
        }
    }
}
