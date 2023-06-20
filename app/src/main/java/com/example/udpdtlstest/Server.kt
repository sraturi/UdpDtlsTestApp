package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.BumpDtlsServer
import com.example.udpdtlstest.dtls.DatagramChanelTransport
import org.bouncycastle.tls.DTLSRequest
import org.bouncycastle.tls.DTLSServerProtocol
import org.bouncycastle.tls.DTLSVerifier
import org.bouncycastle.tls.DatagramSender
import org.bouncycastle.tls.DatagramTransport
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.security.SecureRandom

fun main() {
    server()
}
fun server() {
    val mtu = 1500
    val serverCrypto = BcTlsCrypto(SecureRandom())
    val channel = DatagramChannel.open()
    channel.bind(InetSocketAddress(8080))

    val (initialDTLSRequest, address) = waitForConnection(channel, serverCrypto, mtu)

    println("Accepting connection from ${address.address.hostAddress}:${address.port}")
    channel.connect(address)

    val transport: DatagramTransport = DatagramChanelTransport(channel, address)
    val server = BumpDtlsServer(serverCrypto)
    val serverProtocol = DTLSServerProtocol()
    val dtlsServer = serverProtocol.accept(server, transport, initialDTLSRequest)

    val buf = ByteArray(dtlsServer.receiveLimit)
    while (!channel.socket().isClosed) {
        try {
            println("Waiting to receive!")
            val length = dtlsServer.receive(buf, 0, buf.size, 5000)
            if (length >= 0) {
                val msg = String(buf, 0,length)
                println("Received from client: ${String(buf, 0,length)}")
                val newMsg = "Server received: $msg".toByteArray()
                dtlsServer.send(newMsg, 0, newMsg.size)
            }
        } catch (th: Throwable) {
            throw th
        }
    }
    dtlsServer.close()
}

private fun waitForConnection(
    channel: DatagramChannel,
    serverCrypto: BcTlsCrypto,
    mtu: Int,
): Pair<DTLSRequest, InetSocketAddress> {
    var dtlsRequest: DTLSRequest? = null
    val verifier = DTLSVerifier(serverCrypto)
    val buffer = ByteBuffer.allocate(1024)
    var address: InetSocketAddress? = null
    while (dtlsRequest == null) {
        println("Server waiting for initial connection request")
        buffer.clear()
        address = channel.receive(buffer) as InetSocketAddress
        buffer.flip()
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        println("Server received initial request from address: ${address} port:${address.port} data: ${data.map { it.toInt() }}")
        dtlsRequest = verifier.verifyRequest(
            address.address.address,
            data,
            0,
            data.size,
            object : DatagramSender {
                override fun getSendLimit(): Int = mtu - 28

                override fun send(buf: ByteArray, off: Int, len: Int) {
                    channel.send(ByteBuffer.wrap(buf, off, len), address)
                }
            },
        )
    }
    return Pair(dtlsRequest, address!!)
}
