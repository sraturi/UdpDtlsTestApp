package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.BumpDatagramTransport
import com.example.udpdtlstest.dtls.BumpDtlsServer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSRequest
import org.bouncycastle.tls.DTLSServerProtocol
import org.bouncycastle.tls.DTLSVerifier
import org.bouncycastle.tls.DatagramSender
import org.bouncycastle.tls.UDPTransport
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.DatagramPacket
import java.net.InetSocketAddress
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
    val address = InetSocketAddress(8080)
    println("Server UDP channel is created and bound to port 8080")
    val crypto = BcTlsCrypto(SecureRandom())
    val mtu = 1500

    val request = waitforRequest(channel, mtu, crypto, address)

    println("Accepting connection")
    channel.connect(address)
    val server = BumpDtlsServer(crypto)
    val transport = BumpDatagramTransport(channel, mtu)
    val dtlsProtocol = DTLSServerProtocol()
    val dtlsServer = dtlsProtocol.accept(server, transport, request)
    println("Connected to client")
    while (!channel.socket().isClosed) {
        try {
            val dataArr = ByteArray(1024)
            dtlsServer.receive(dataArr, 0, dataArr.size, 5000)
            val msg = dataArr.toString(Charset.defaultCharset())
            println("Server recived mssg: $msg")
            dtlsServer.send("Server Recieved: ${msg.trim()}".toByteArray(Charset.defaultCharset()), 0, 20)
        } catch (th: Throwable) {
            throw th
        }
    }
}

fun waitforRequest(channel: DatagramChannel, mtu: Int, crypto: TlsCrypto, address: InetSocketAddress): DTLSRequest {
    var request: DTLSRequest? = null
    val data = ByteArray(mtu)
    val packet = DatagramPacket(data, data.size)
    channel.bind(address)
    while (request == null) {
        println("waiting for a connection recv")
        channel.socket().receive(packet)
        println("Server Received init request from: $address, ${packet.data.map { it.toInt() }}")
        request = DTLSVerifier(crypto).verifyRequest(
            packet.address.address,
            packet.data,
            0,
            packet.data.size,
            object : DatagramSender {
                override fun getSendLimit(): Int {
                    return mtu - 28
                }

                override fun send(buf: ByteArray, off: Int, len: Int) {
                    println("Trying to send via verify req")
                    channel.socket().send(DatagramPacket(buf, off, len, packet.address, packet.port))
                }
            },
        )
        println("end while loop: $request")
    }
    println("Init request finished!")
    return request
}
