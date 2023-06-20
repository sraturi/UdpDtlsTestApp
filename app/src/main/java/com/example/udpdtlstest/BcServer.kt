package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.BumpDtlsServer
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.DTLSRequest
import org.bouncycastle.tls.DTLSServerProtocol
import org.bouncycastle.tls.DTLSVerifier
import org.bouncycastle.tls.DatagramSender
import org.bouncycastle.tls.DatagramTransport
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.UDPTransport
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.channels.DatagramChannel
import java.security.SecureRandom

fun main() {
    val mtu = 1500
    val serverCrypto = BcTlsCrypto(SecureRandom())
    val channel = DatagramChannel.open()
    val packet = DatagramPacket(ByteArray(mtu), mtu)
    channel.bind(InetSocketAddress(8080))
    val initialDTLSRequest = waitForConnection(channel, packet, serverCrypto, mtu)

    println("Accepting connection from ${packet.address.hostAddress}:${packet.port}")
    channel.connect(packet.socketAddress)

    val transport: DatagramTransport = UDPTransport(channel.socket(), mtu)
    val server = BumpDtlsServer(serverCrypto)
    val serverProtocol = DTLSServerProtocol()
    val dtlsServer = serverProtocol.accept(server, transport, initialDTLSRequest)

    val buf = ByteArray(dtlsServer.receiveLimit)
    while (!channel.socket().isClosed) {
        try {
            println("Waiting to receive!")
            val length = dtlsServer.receive(buf, 0, buf.size, 60000)
            if (length >= 0) {
                System.out.write(buf, 0, length)
                dtlsServer.send(buf, 0, length)
            }
        } catch (ste: SocketTimeoutException) {
        }
    }
    dtlsServer.close()
}

private fun waitForConnection(
    channel: DatagramChannel,
    packet: DatagramPacket,
    serverCrypto: BcTlsCrypto,
    mtu: Int,
): DTLSRequest {
    var dtlsRequest: DTLSRequest? = null
    val verifier = DTLSVerifier(serverCrypto)
    while (dtlsRequest == null) {
        channel.socket().receive(packet)
        dtlsRequest = verifier.verifyRequest(
            packet.address.address,
            packet.data,
            packet.offset,
            packet.length,
            object : DatagramSender {
                override fun getSendLimit(): Int = mtu - 28

                override fun send(buf: ByteArray, off: Int, len: Int) {
                    if (len > sendLimit) {
                        throw TlsFatalAlert(AlertDescription.internal_error)
                    }
                    channel.socket().send(DatagramPacket(buf, off, len, packet.address, packet.port))
                }
            },
        )
    }
    return dtlsRequest
}
