package com.example.udpdtlstest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import com.example.udpdtlstest.dtls.DtlsCryto
import com.example.udpdtlstest.dtls.DummyTlsServer
import com.example.udpdtlstest.ui.theme.UdpDtlsTestTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.tls.DTLSServerProtocol
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.charset.Charset
import java.security.Security
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.random.Random

val logger = Logger.getLogger("Main")
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            UdpDtlsTestTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    Greeting("Android")
                }
            }
        }

        Thread {
            main()
        }
    }
}
suspend fun sendMessage(message: String): String {
    val clientSocket = DatagramSocket()
    try {
        logger.info("created datagram socket")
        val sendData = message.toByteArray()
        val serverAddress = InetAddress.getByName("192.168.1.190")
        val sendPacket = DatagramPacket(sendData, sendData.size, serverAddress, 8080)
        logger.info("SENDING PACKET ")
        clientSocket.send(sendPacket)
        val receiveData = ByteArray(1024)
        val receivePacket = DatagramPacket(receiveData, receiveData.size)
        logger.info("Waiting to recieve packet")
        withTimeout(5000) {
            clientSocket.receive(receivePacket)
        }
        val receivedMessage = String(receivePacket.data, 0, receivePacket.length)
        logger.info("Recieved packet: $receivedMessage")
        clientSocket.close()
        return receivedMessage
    } catch (e: Exception) {
        logger.log(Level.SEVERE, e.message, e)
        clientSocket.close()
        return e.message!!
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    var text by remember {
        mutableStateOf("Click to send")
    }

    Column(
        Modifier
            .fillMaxWidth(1f)
            .fillMaxSize(1f),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = text,
            modifier = modifier,
            overflow = TextOverflow.Visible,
        )
        Button(onClick = {
            text = "abc"
            GlobalScope.launch(Dispatchers.IO) {
                text = clientMessage("Hello ${Random.nextInt()}")
            }
        }) {
            Text(text = "Click to send")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    UdpDtlsTestTheme {
        Greeting("Android")
    }
}

// fun main() {
//    val PORT = 8080
//    val bufferSize = 1024
//    val receiveData = ByteArray(bufferSize)
//
//    try {
//        val serverSocket = DatagramSocket(PORT)
//        println("UDP Server is running on port $PORT")
//
//        while (true) {
//            val receivePacket = DatagramPacket(receiveData, receiveData.size)
//            serverSocket.receive(receivePacket)
//
//            val clientMessage = String(receivePacket.data, 0, receivePacket.length)
//            println("Received from client: $clientMessage")
//
//            val responseMessage = "Server received: $clientMessage"
//            val sendData = responseMessage.toByteArray()
//
//            val sendPacket = DatagramPacket(sendData, sendData.size, receivePacket.address, receivePacket.port)
//            serverSocket.send(sendPacket)
//        }
//    } catch (e: Exception) {
//        e.printStackTrace()
//    }
// }

fun main() {
    Security.addProvider(BouncyCastleProvider())

    val channel = DatagramChannel.open()
    channel.socket().bind(InetSocketAddress(8080))
    println("UDP channel is created and bound to port 8080")
    val dtlsProtocol = DTLSServerProtocol()

    while (true) {
        try {
            val receiveBuffer = ByteBuffer.allocate(1024)
            val receiveAddress = channel.receive(receiveBuffer)
            receiveBuffer.flip()
            val receivedData = ByteArray(receiveBuffer.remaining())
            receiveBuffer.get(receivedData)
            println("Received init request from: $receiveAddress, $receivedData")

            val dtlsServer = dtlsProtocol.accept(
                DummyTlsServer(DtlsCryto()),
                datagramTransport(channel),
            )
            println("Sending back response")
            dtlsServer.send("Hellosss".toByteArray(Charset.defaultCharset()), 0, 20)
        } catch (th: Throwable) {
            throw th
        }
    }
}
