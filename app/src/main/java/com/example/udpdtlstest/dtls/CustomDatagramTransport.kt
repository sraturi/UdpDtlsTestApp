package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.DatagramTransport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

fun datagramTransport(channel: DatagramChannel) = object : DatagramTransport {
    override fun getReceiveLimit(): Int {
        return 1024
    }

    override fun receive(buf: ByteArray, off: Int, len: Int, waitMillis: Int): Int {
        val receiveBuffer = ByteBuffer.wrap(buf, off, len)
        println("wating to receive")
        val senderAddress = channel.receive(receiveBuffer)
        println("recieved")
        return if (senderAddress != null) receiveBuffer.position() else 0
    }

    override fun getSendLimit(): Int {
        return 1024
    }

    override fun send(buf: ByteArray, off: Int, len: Int) {
        println("sending buf: $buf")
        channel.send(ByteBuffer.wrap(buf, off, len), InetSocketAddress("localhost", 8080))
    }

    override fun close() {
        channel.close()
    }
}
