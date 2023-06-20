package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.DatagramTransport
import org.bouncycastle.tls.UDPTransport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

fun serverDatagramTransport(channel: DatagramChannel) = object : DatagramTransport {

    override fun getReceiveLimit(): Int {
        return 1024
    }

    override fun receive(buf: ByteArray, off: Int, len: Int, waitMillis: Int): Int {
        val receiveBuffer = ByteBuffer.wrap(buf, off, len)
        println("wating to receive")
        val senderAddress = channel.receive(receiveBuffer)
        println("recieved: ${receiveBuffer.duplicate().array().map { it.toInt() }}")
        return if (senderAddress != null) receiveBuffer.position() else 0
    }

    override fun getSendLimit(): Int {
        return 1024
    }

    override fun send(buf: ByteArray, off: Int, len: Int) {
        val data = ByteBuffer.wrap(buf, off, len)
        println("sending buf: ${data.array().map { it.toInt() }}")
        channel.send(data, InetSocketAddress("localhost", 8080))
    }

    override fun close() {
        channel.close()
    }
}

// TODO why does channel not work properly with client??
class ClientDatagramTransport(channel: DatagramChannel, mtu: Int) : UDPTransport(channel.socket(), mtu) {
    override fun receive(buf: ByteArray?, off: Int, len: Int, waitMillis: Int): Int {
        val x = super.receive(buf, off, len, waitMillis)
        println("client recved")
        return x
    }
    override fun send(buf: ByteArray, off: Int, len: Int) {
        println("sending bytes: ${buf.map { it.toInt() }} ")
        super.send(buf, off, len)
    }
}
