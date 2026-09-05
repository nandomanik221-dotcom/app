package com.example.vpn.ssh

import com.example.model.LogLevel
import com.example.vpn.VpnLogManager
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.net.SocketAddress
import java.security.SecureRandom

/**
 * An RFC 6455 compliant WebSocket socket wrapper.
 *
 * Encapsulates raw stream writes into masked WebSocket binary frames (Opcode 0x02)
 * and unwraps incoming WebSocket frames (Opcode 0x02, 0x01, 0x00, 0x09/0x0A Ping/Pong, 0x08 Close)
 * into a transparent raw byte stream for SSH / TCP tunneling.
 */
class WebSocketFramedSocket(
    private val delegate: Socket,
    customIn: InputStream? = null
) : Socket() {

    private val random = SecureRandom()
    private val framedIn = WebSocketInputStream(customIn ?: delegate.getInputStream(), delegate.getOutputStream(), random)
    private val framedOut = WebSocketOutputStream(delegate.getOutputStream(), random)

    override fun getInputStream(): InputStream = framedIn
    override fun getOutputStream(): OutputStream = framedOut

    override fun isConnected(): Boolean = delegate.isConnected
    override fun isClosed(): Boolean = delegate.isClosed
    override fun close() {
        try {
            framedOut.sendClose()
        } catch (_: Exception) {}
        delegate.close()
    }

    override fun getRemoteSocketAddress(): SocketAddress = delegate.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress = delegate.localSocketAddress
    override fun setSoTimeout(timeout: Int) {
        delegate.soTimeout = timeout
    }
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun setTcpNoDelay(on: Boolean) {
        delegate.tcpNoDelay = on
    }

    private class WebSocketOutputStream(
        private val rawOut: OutputStream,
        private val random: SecureRandom
    ) : OutputStream() {

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return

            // RFC 6455 Binary Frame: FIN=1, RSV=0, Opcode=0x02 -> 0x82
            val header = mutableListOf<Byte>()
            header.add(0x82.toByte())

            val maskBit: Byte = 0x80.toByte() // Client-to-server must be masked

            when {
                len <= 125 -> {
                    header.add((maskBit.toInt() or len).toByte())
                }
                len <= 65535 -> {
                    header.add((maskBit.toInt() or 126).toByte())
                    header.add(((len shr 8) and 0xFF).toByte())
                    header.add((len and 0xFF).toByte())
                }
                else -> {
                    header.add((maskBit.toInt() or 127).toByte())
                    for (i in 7 downTo 0) {
                        header.add(((len.toLong() shr (i * 8)) and 0xFF).toByte())
                    }
                }
            }

            // 4-byte random masking key
            val mask = ByteArray(4)
            random.nextBytes(mask)
            for (m in mask) {
                header.add(m)
            }

            // Mask payload
            val maskedPayload = ByteArray(len)
            for (i in 0 until len) {
                maskedPayload[i] = (b[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            }

            synchronized(rawOut) {
                rawOut.write(header.toByteArray())
                rawOut.write(maskedPayload)
                rawOut.flush()
            }

            VpnLogManager.log(
                LogLevel.CONN,
                "SSH STREAM",
                "[SSH STREAM] direction=outbound bytes=$len transport=websocket ws_opcode=0x02 ws_fin=true frame_payload_length=$len"
            )
        }

        fun sendClose() {
            val frame = byteArrayOf(0x88.toByte(), 0x80.toByte(), 0x00, 0x00, 0x00, 0x00)
            synchronized(rawOut) {
                rawOut.write(frame)
                rawOut.flush()
            }
        }

        override fun flush() {
            synchronized(rawOut) {
                rawOut.flush()
            }
        }

        override fun close() {
            rawOut.close()
        }
    }

    private class WebSocketInputStream(
        private val rawIn: InputStream,
        private val rawOut: OutputStream,
        private val random: SecureRandom
    ) : InputStream() {

        private var buffer = ByteArray(0)
        private var bufferPos = 0

        override fun available(): Int {
            return (buffer.size - bufferPos) + rawIn.available()
        }

        override fun read(): Int {
            val single = ByteArray(1)
            val count = read(single, 0, 1)
            return if (count == -1) -1 else (single[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len <= 0) return 0

            while (bufferPos >= buffer.size) {
                val nextPayload = readNextFramePayload() ?: return -1
                buffer = nextPayload
                bufferPos = 0
            }

            val available = buffer.size - bufferPos
            val toCopy = minOf(available, len)
            System.arraycopy(buffer, bufferPos, b, off, toCopy)
            bufferPos += toCopy
            return toCopy
        }

        private fun readNextFramePayload(): ByteArray? {
            while (true) {
                val b0 = rawIn.read()
                if (b0 == -1) return null

                val b1 = rawIn.read()
                if (b1 == -1) return null

                val opcode = b0 and 0x0F
                val fin = (b0 and 0x80) != 0
                val isMasked = (b1 and 0x80) != 0
                var payloadLen: Long = (b1 and 0x7F).toLong()

                if (payloadLen == 126L) {
                    val lenBytes = rawIn.readExact(2) ?: return null
                    payloadLen = ((lenBytes[0].toInt() and 0xFF) shl 8 or (lenBytes[1].toInt() and 0xFF)).toLong()
                } else if (payloadLen == 127L) {
                    val lenBytes = rawIn.readExact(8) ?: return null
                    payloadLen = 0L
                    for (i in 0..7) {
                        payloadLen = (payloadLen shl 8) or (lenBytes[i].toLong() and 0xFF)
                    }
                }

                val mask = if (isMasked) {
                    rawIn.readExact(4) ?: return null
                } else {
                    null
                }

                if (payloadLen > 10 * 1024 * 1024) {
                    throw IllegalStateException("WebSocket frame too large: $payloadLen bytes")
                }

                val payload = rawIn.readExact(payloadLen.toInt()) ?: return null

                if (mask != null) {
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                    }
                }

                when (opcode) {
                    0x01, 0x02, 0x00 -> {
                        // Text, Binary, or Continuation frame
                        VpnLogManager.log(
                            LogLevel.CONN,
                            "SSH STREAM",
                            "[SSH STREAM] direction=inbound bytes=${payload.size} transport=websocket ws_opcode=0x%02X ws_fin=$fin frame_payload_length=${payload.size}".format(opcode)
                        )
                        return payload
                    }
                    0x08 -> {
                        // Close frame
                        return null
                    }
                    0x09 -> {
                        // Ping frame -> reply with Pong (Opcode 0x0A)
                        sendPong(payload)
                    }
                    0x0A -> {
                        // Pong frame -> ignore and continue
                    }
                }
            }
        }

        private fun sendPong(payload: ByteArray) {
            try {
                val header = mutableListOf<Byte>()
                header.add(0x8A.toByte()) // FIN=1, Opcode=0x0A
                val maskBit = 0x80.toByte()
                header.add((maskBit.toInt() or (payload.size and 0x7F)).toByte())
                val mask = ByteArray(4)
                random.nextBytes(mask)
                for (m in mask) header.add(m)

                val masked = ByteArray(payload.size)
                for (i in payload.indices) {
                    masked[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                }

                synchronized(rawOut) {
                    rawOut.write(header.toByteArray())
                    rawOut.write(masked)
                    rawOut.flush()
                }
            } catch (_: Exception) {}
        }

        private fun InputStream.readExact(size: Int): ByteArray? {
            val buf = ByteArray(size)
            var total = 0
            while (total < size) {
                val read = this.read(buf, total, size - total)
                if (read == -1) return null
                total += read
            }
            return buf
        }

        override fun close() {
            rawIn.close()
        }
    }
}
