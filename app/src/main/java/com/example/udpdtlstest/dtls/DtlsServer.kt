package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.AbstractTlsServer
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CertificateStatus
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.NewSessionTicket
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.TlsCloseable
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsHeartbeat
import org.bouncycastle.tls.TlsKeyExchangeFactory
import org.bouncycastle.tls.TlsPSKExternal
import org.bouncycastle.tls.TlsPSKIdentityManager
import org.bouncycastle.tls.TlsSRPLoginParameters
import org.bouncycastle.tls.TlsServer
import org.bouncycastle.tls.TlsServerContext
import org.bouncycastle.tls.TlsSession
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.TlsDHConfig
import org.bouncycastle.tls.crypto.TlsECConfig
import java.util.Hashtable
import java.util.Vector

class DummyTlsServer(tlsCrypto: TlsCrypto) : AbstractTlsServer(tlsCrypto) {
    val time = System.currentTimeMillis()
    override fun getSupportedCipherSuites(): IntArray {
        return intArrayOf(
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        )
    }

    override fun getCredentials(): TlsCredentials {
        return TlsCredentials {
            TODO("Not yet implemented")
        }
    }

    override fun notifyHandshakeBeginning() {
        super.notifyHandshakeBeginning()
        println("Server notify handshake beginning ${System.currentTimeMillis() - time}")
    }

    override fun notifyCloseHandle(closeHandle: TlsCloseable?) {
        super.notifyCloseHandle(closeHandle)
        println("Server notify handle closed ${System.currentTimeMillis() - time}")
    }
}
