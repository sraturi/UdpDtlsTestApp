package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.DatagramTransport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

class DatagramChanelTransport(private val channel: DatagramChannel, private val address: InetSocketAddress) : DatagramTransport {
    override fun getReceiveLimit(): Int {
        return channel.socket().receiveBufferSize
    }

    override fun receive(buf: ByteArray, off: Int, len: Int, waitMillis: Int): Int {
        val buffer = ByteBuffer.wrap(buf, off, len)
        channel.receive(buffer)
        return buffer.position()
    }

    override fun getSendLimit(): Int {
        return channel.socket().sendBufferSize
    }

    override fun send(buf: ByteArray, off: Int, len: Int) {
        channel.send(ByteBuffer.wrap(buf, off, len), address)
    }

    override fun close() {
        channel.close()
    }
}
