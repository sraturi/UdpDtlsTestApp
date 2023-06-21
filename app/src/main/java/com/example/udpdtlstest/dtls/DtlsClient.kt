package com.example.udpdtlstest.dtls

import KeysUtils
import org.bouncycastle.asn1.x509.Certificate
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.ClientCertificateType
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAlgorithm
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.TlsSession
import org.bouncycastle.tls.crypto.TlsCrypto

class BumpTlsClient(tlsCrypto: TlsCrypto, val utils: KeysUtils) : DefaultTlsClient(tlsCrypto) {
    val time = System.currentTimeMillis()
    lateinit var session: TlsSession
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
        println("clinet inside get authentication")
        return object : TlsAuthentication {
            override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                // TODO this is where we verify certificate
                val chain = serverCertificate.certificate.certificateList
                println("DTLS client got certificates ${chain.size}")
                chain.forEach {
                    val entry = Certificate.getInstance(it.encoded)
                    println("dtls fingerprint: ${entry.subject}")
                }
                if (chain.isEmpty()) {
                    error("client certificates cannot be empty")
                }
                // TODO need to make sure they are trusted
            }

            override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials {
                println("Client in get client credentials")
                val certTypes = certificateRequest.certificateTypes
                if (!certTypes.contains(ClientCertificateType.rsa_sign)) {
                    error("no client cert type for rsa ")
                }
                return utils.loadSignerCredentials(
                    context,
                    certificateRequest.supportedSignatureAlgorithms,
                    SignatureAlgorithm.rsa,
                    "x509-client-rsa.pem",
                    "x509-client-key-rsa.pem",
                )
            }
        }
    }

    override fun notifyHandshakeBeginning() {
        super.notifyHandshakeBeginning()
        println("Client notify handshake beginning ${System.currentTimeMillis() - time}")
    }

    override fun notifyHandshakeComplete() {
        println("Client handshake complete")
        super.notifyHandshakeComplete()
        val protocolName = context.securityParametersConnection.applicationProtocol
        if (protocolName != null) {
            println("protocaol name: ${protocolName.utf8Decoding}")
        }
        val session = context.session
        if (session != null) {
            if (session.isResumable) {
                this.session = session
            }
        }
    }

    override fun getProtocolVersions(): Array<ProtocolVersion> {
        return ProtocolVersion.DTLSv12.only()
    }
    override fun notifyServerVersion(serverVersion: ProtocolVersion) {
        println("Server using version: ${serverVersion.name}")
        super.notifyServerVersion(serverVersion)
    }
}
