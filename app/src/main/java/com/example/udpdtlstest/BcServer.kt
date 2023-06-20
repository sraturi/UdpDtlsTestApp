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
import java.net.DatagramSocket
import java.net.SocketTimeoutException
import java.security.SecureRandom

fun main() {
    val port = 8080
    val mtu = 1500
    val serverCrypto = BcTlsCrypto(SecureRandom())

    val socket = DatagramSocket(port)
    val packet = DatagramPacket(ByteArray(mtu), mtu)

    val initialDTLSRequest = waitForConnection(socket, packet, serverCrypto, mtu)

    println("Accepting connection from ${packet.address.hostAddress}:${packet.port}")
    socket.connect(packet.address, packet.port)

    val transport: DatagramTransport = UDPTransport(socket, mtu)
    val server = BumpDtlsServer(serverCrypto)
    val serverProtocol = DTLSServerProtocol()
    val dtlsServer = serverProtocol.accept(server, transport, initialDTLSRequest)

    val buf = ByteArray(dtlsServer.receiveLimit)
    while (!socket.isClosed) {
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
    socket: DatagramSocket,
    packet: DatagramPacket,
    serverCrypto: BcTlsCrypto,
    mtu: Int,
): DTLSRequest {
    var dtlsRequest: DTLSRequest? = null
    val verifier = DTLSVerifier(serverCrypto)
    while (dtlsRequest == null) {
        socket.receive(packet)
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
                    socket.send(DatagramPacket(buf, off, len, packet.address, packet.port))
                }
            },
        )
    }
    return dtlsRequest
}
