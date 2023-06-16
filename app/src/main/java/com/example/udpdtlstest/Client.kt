package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.DtlsCryto
import com.example.udpdtlstest.dtls.DummyTlsClient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSClientProtocol
import org.bouncycastle.tls.DTLSTransport
import org.bouncycastle.tls.DatagramTransport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.security.Security

fun clientMessage(msg: String): String {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    println("Creating channel")

    val dtlsClientProtocol = DTLSClientProtocol()
    println("created dtls protocol")

    val socketAddress = InetSocketAddress("localhost", 8080)
    val transport: DTLSTransport = try {
        dtlsClientProtocol.connect(DummyTlsClient(DtlsCryto()), datagramTransport(channel))
    } catch (e: Throwable) {
        e.printStackTrace()
        throw e
    }
    println("connected to server, sending data")

    val buffer = ByteBuffer.wrap(msg.toByteArray())
    channel.send(ByteBuffer.wrap(msg.toByteArray()), socketAddress)

    println("waiting to receive data on client")
    buffer.clear()
    val senderAddress = channel.receive(buffer)
    buffer.flip()

    val msg = if (senderAddress != null) {
        val receivedData = ByteArray(buffer.remaining())
        buffer.get(receivedData)
        // Process or display the received data as needed
        println("Received data: ${String(receivedData)}")
        String(receivedData)
    } else {
        println("No data received")
        "No msg recieved"
    }

    transport.close()
    channel.close()
    return msg
}

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
