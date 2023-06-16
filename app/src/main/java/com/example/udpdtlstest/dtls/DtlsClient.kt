package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.AbstractTlsClient
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsCloseable
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.TlsCrypto

class DummyTlsClient(tlsCrypto: TlsCrypto) : AbstractTlsClient(tlsCrypto) {
    val time = System.currentTimeMillis()
    override fun getSupportedCipherSuites(): IntArray {
        return intArrayOf(
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        )
    }

    override fun getSupportedVersions(): Array<ProtocolVersion> {
        return arrayOf(ProtocolVersion.DTLSv12)
    }

    override fun getAuthentication(): TlsAuthentication {
        return object : TlsAuthentication {
            override fun notifyServerCertificate(serverCertificate: TlsServerCertificate?) {
                TODO("Not yet implemented")
            }

            override fun getClientCredentials(certificateRequest: CertificateRequest?): TlsCredentials {
                TODO("Not yet implemented")
            }
        }
    }

    override fun notifyCloseHandle(closeHandle: TlsCloseable?) {
        super.notifyCloseHandle(closeHandle)
        println("notify close handle ${System.currentTimeMillis() - time}")
    }

    override fun notifyHandshakeBeginning() {
        super.notifyHandshakeBeginning()
        println("notify handshake beginning ${System.currentTimeMillis() - time}")
    }
}
