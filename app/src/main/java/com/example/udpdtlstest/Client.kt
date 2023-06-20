package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.ClientDatagramTransport
import com.example.udpdtlstest.dtls.DummyTlsClient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSClientProtocol
import org.bouncycastle.tls.DTLSTransport
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.security.SecureRandom
import java.security.Security

fun main() {
    sendClientMessage("Hello!")
}
fun sendClientMessage(msg: String): String {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    println("client created channel")

    val dtlsClientProtocol = DTLSClientProtocol()
    println("client created dtls protocol")

    val socketAddress = InetSocketAddress("localhost", 8080)
    channel.socket().connect(socketAddress)
    val trans = ClientDatagramTransport(channel, 1500)

    val transport: DTLSTransport = try {
        dtlsClientProtocol.connect(
            DummyTlsClient(BcTlsCrypto(SecureRandom())),
            trans,
        )
    } catch (e: Throwable) {
        e.printStackTrace()
        throw e
    }
    println("client connected to server, sending data")

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
        "client No msg recieved"
    }

    transport.close()
    channel.close()
    return msg
}
