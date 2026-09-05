package com.example.vpn.ssh

import com.trilead.ssh2.LocalStreamForwarder
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Socket wrapper representing an active SSH `direct-tcpip` port-forwarding channel
 * backed by Trilead SSH-2's [LocalStreamForwarder] or underlying streams.
 *
 * Implements standard java.net.Socket stream operations over the underlying SSH channel,
 * ensuring accurate real-time byte counters and proper channel lifecycle teardown.
 */
class DirectTcpIpSocket(
    private val inStreamRaw: InputStream,
    private val outStreamRaw: OutputStream,
    val targetHost: String,
    val targetPort: Int,
    private val totalBytesSent: AtomicLong,
    private val totalBytesReceived: AtomicLong,
    private val onClose: (() -> Unit)? = null
) : Socket() {

    constructor(
        forwarder: LocalStreamForwarder,
        targetHost: String,
        targetPort: Int,
        totalBytesSent: AtomicLong,
        totalBytesReceived: AtomicLong
    ) : this(
        inStreamRaw = forwarder.inputStream,
        outStreamRaw = forwarder.outputStream,
        targetHost = targetHost,
        targetPort = targetPort,
        totalBytesSent = totalBytesSent,
        totalBytesReceived = totalBytesReceived,
        onClose = {
            try {
                forwarder.close()
            } catch (_: Exception) {}
        }
    )

    private val closed = AtomicBoolean(false)
    private val inStream by lazy {
        CountingInputStream(inStreamRaw, totalBytesReceived)
    }
    private val outStream by lazy {
        CountingOutputStream(outStreamRaw, totalBytesSent)
    }

    override fun getInputStream(): InputStream = inStream

    override fun getOutputStream(): OutputStream = outStream

    override fun isConnected(): Boolean = !closed.get()

    override fun isClosed(): Boolean = closed.get()

    override fun getRemoteSocketAddress(): SocketAddress = InetSocketAddress(targetHost, targetPort)

    override fun getLocalSocketAddress(): SocketAddress = InetSocketAddress("127.0.0.1", 0)

    override fun setSoTimeout(timeout: Int) {
        // No-op for forwarder stream
    }

    override fun getSoTimeout(): Int = 0

    override fun setTcpNoDelay(on: Boolean) {
        // No-op for forwarder stream
    }

    override fun getTcpNoDelay(): Boolean = true

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try {
                inStreamRaw.close()
            } catch (_: Exception) {}
            try {
                outStreamRaw.close()
            } catch (_: Exception) {}
            onClose?.invoke()
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
