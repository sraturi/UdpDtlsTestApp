package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.DummyTlsServer
import com.example.udpdtlstest.dtls.datagramTransport
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
    channel.socket().bind(InetSocketAddress(8080))
    println("Server UDP channel is created and bound to port 8080")
    val dtlsProtocol = DTLSServerProtocol()

    while (true) {
        try {
            val receiveBuffer = ByteBuffer.allocate(1024)
            val receiveAddress = channel.receive(receiveBuffer)
            receiveBuffer.flip()
            val receivedData = ByteArray(receiveBuffer.remaining())
            receiveBuffer.get(receivedData)
            println("Server Received init request from: $receiveAddress, $receivedData")

            // TODO the accept function takes in a third param called DTLSRequest,
            // need to figure out how to extract it.
            // Otherwise I think the problem is that Client has sent a handshake hello message but
            // server is not reading it so server is just waiting to receive it.

            val dtlsServer = dtlsProtocol.accept(
                DummyTlsServer(BcTlsCrypto(SecureRandom())),
                datagramTransport(channel),
            )
            println("Server Sending back response")
            dtlsServer.send("Hello from server".toByteArray(Charset.defaultCharset()), 0, 20)
        } catch (th: Throwable) {
            throw th
        }
    }
}
