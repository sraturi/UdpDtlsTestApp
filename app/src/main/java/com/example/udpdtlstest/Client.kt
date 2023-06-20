package com.example.udpdtlstest

import com.example.udpdtlstest.dtls.BumpTlsClient
import com.example.udpdtlstest.dtls.BumpDatagramTransport
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSClientProtocol
import org.bouncycastle.tls.DTLSTransport
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.Security

fun main() {
    sendClientMessage("Hello!")
}
fun sendClientMessage(msg: String, testWithoutEncrypt: Boolean = false): String {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    println("client created channel")

    val socketAddress = InetSocketAddress(8080)
    channel.connect(socketAddress)
    // this is how we communicate i.e send/recv
    val dtlsTransport: DTLSTransport = try {
        val dtlsClientProtocol = DTLSClientProtocol()
        println("client created dtls protocol")
        dtlsClientProtocol.connect(BumpTlsClient(BcTlsCrypto(SecureRandom())), BumpDatagramTransport(channel, 1500))
    } catch (e: Throwable) {
        e.printStackTrace()
        throw e
    }
    println("client connected to server, sending data")
    // This should be encrypted!..............!
    dtlsTransport.send(msg.toByteArray(), 0, msg.toByteArray().size)

    println("waiting to receive data on client")
    // if I recieve using channel, i get bunch of giberish
    if (testWithoutEncrypt) {
        val buff = ByteBuffer.allocate(1024)
        channel.receive(buff)
        buff.flip()
        val data = ByteArray(buff.remaining())
        buff.get(data)
        val recvMsg = data.toString(Charset.defaultCharset())
        println("Recieved from server using normal channell: $recvMsg")
        dtlsTransport.close()
        channel.close()
        return recvMsg
    } else {
        val dataArr = ByteArray(dtlsTransport.receiveLimit)
        dtlsTransport.receive(dataArr, 0, dataArr.size, 500)
        val recvMsg = dataArr.toString(Charset.defaultCharset())
        // TODO this prints the message plus all extra bit of the array
        println("received from the server! : $recvMsg")
        dtlsTransport.close()
        channel.close()
        return recvMsg
    }
}
