package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.UDPTransport
import java.nio.channels.DatagramChannel
// TODO why does channel not work properly with client??
class BumpDatagramTransport(channel: DatagramChannel, mtu: Int) : UDPTransport(channel.socket(), mtu) {
    override fun receive(buf: ByteArray, off: Int, len: Int, waitMillis: Int): Int {
        val x = super.receive(buf, off, len, waitMillis)
        println("client recved")
        return x
    }
    override fun send(buf: ByteArray, off: Int, len: Int) {
        println("sending bytes: ${buf.map { it.toInt() }} ")
        super.send(buf, off, len)
    }
}
