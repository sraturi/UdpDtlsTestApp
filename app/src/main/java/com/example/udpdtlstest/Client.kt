package com.example.udpdtlstest

import KeysUtils
import android.content.res.Resources
import com.example.udpdtlstest.dtls.BumpTlsClient
import com.example.udpdtlstest.dtls.DatagramChanelTransport
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
    sendClientMessage("Hello server!")
}
fun sendClientMessage(msg: String, testWithoutEncrypt: Boolean = false, resource: Resources? = null): String {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    println("client created channel")

    val socketAddress = InetSocketAddress(8080)
    channel.connect(socketAddress)
    // this is how we communicate i.e send/recv
    val dtlsTransport: DTLSTransport = try {
        val dtlsClientProtocol = DTLSClientProtocol()
        println("client created dtls protocol")
        dtlsClientProtocol.connect(BumpTlsClient(BcTlsCrypto(SecureRandom()), KeysUtils(resource)), DatagramChanelTransport(channel, socketAddress))
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
        val len = dtlsTransport.receive(dataArr, 0, dataArr.size, 5000)
        val recvMsg = String(dataArr, 0, len)
        println("received from the server! : $recvMsg")
        dtlsTransport.close()
        channel.close()
        return recvMsg
    }
}
