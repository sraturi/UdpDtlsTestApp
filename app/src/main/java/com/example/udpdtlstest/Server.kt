package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.DummyTlsServer
import com.example.udpdtlstest.dtls.serverDatagramTransport
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSServerProtocol
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.Security

fun main() {
    server()
}
fun server() {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    channel.bind(InetSocketAddress(8080))
    println("Server UDP channel is created and bound to port 8080")
    val dtlsProtocol = DTLSServerProtocol()
    val crypto = BcTlsCrypto(SecureRandom())
    while (true) {
        try {
            val receiveBuffer = ByteBuffer.allocate(1024)
            val receiveAddress = channel.receive(receiveBuffer)
            receiveBuffer.flip()
            val receivedData = ByteArray(receiveBuffer.remaining())
            receiveBuffer.get(receivedData)
            println("Server Received init request from: $receiveAddress, ${receivedData.map { it.toInt() }}")

            val server = DummyTlsServer(crypto)
            val transport = serverDatagramTransport(channel)

            val dtlsServer = dtlsProtocol.accept(server, transport)
            println("Server Sending back response")
            dtlsServer.send("Hello from server".toByteArray(Charset.defaultCharset()), 0, 20)
        } catch (th: Throwable) {
            throw th
        }
    }
}
