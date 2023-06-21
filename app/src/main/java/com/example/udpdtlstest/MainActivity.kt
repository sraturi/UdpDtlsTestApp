package com.example.udpdtlstest

import android.content.res.Resources
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import com.example.udpdtlstest.ui.theme.UdpDtlsTestTheme
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
                    Greeting("Android", resources)
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, resources: Resources, modifier: Modifier = Modifier) {
    var text by remember {
        mutableStateOf("Click to send")
    }
    var useWithoutEncrypt by remember {
        mutableStateOf(false)
    }

    Column(
        Modifier
            .fillMaxWidth(1f)
            .fillMaxSize(1f),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceEvenly,
    ) {
        Text(
            text = text,
            modifier = modifier,
            overflow = TextOverflow.Visible,
        )
        Button(onClick = {
            // start server
            val server = Thread {
                logger.info("starting server!!!!!!")
                server(resources)
            }
            server.start()

            val client = Thread {
                text = sendClientMessage(
                    "Hello ${Random.nextInt()}",
                    // set this to true, we should get bunch of gibberish
                    testWithoutEncrypt = useWithoutEncrypt,
                    resources,
                )
            }
            client.start()
            client.join()
        }) {
            Text(text = "Click to send")
        }

        Row (verticalAlignment = Alignment.CenterVertically){
            Text(text = "Base channel to receive data?      ")
            Switch(checked = useWithoutEncrypt, onCheckedChange = {
                useWithoutEncrypt = it
            })
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    UdpDtlsTestTheme {
        Greeting("Android", LocalContext.current.resources)
    }
}
