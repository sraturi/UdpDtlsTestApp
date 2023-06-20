package com.example.udpdtlstest.dtls

import KeysUtils
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.ClientCertificateType
import org.bouncycastle.tls.DefaultTlsServer
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAlgorithm
import org.bouncycastle.tls.TlsCredentialedDecryptor
import org.bouncycastle.tls.TlsCredentialedSigner
import org.bouncycastle.tls.TlsUtils
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.util.Hashtable
import java.util.Vector

class BumpDtlsServer(bcCrypto: BcTlsCrypto,private val utils: KeysUtils) : DefaultTlsServer(bcCrypto) {
    val time = System.currentTimeMillis()
    override fun getSupportedCipherSuites(): IntArray {
        return intArrayOf(
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        )
    }

    override fun getProtocolVersions(): Array<ProtocolVersion> {
        return arrayOf(ProtocolVersion.DTLSv12)
    }

    override fun notifyHandshakeBeginning() {
        super.notifyHandshakeBeginning()
        println("Server notify handshake beginning ${System.currentTimeMillis() }")
    }

    override fun getCertificateRequest(): CertificateRequest {
        super.getCertificateRequest()
        println("Server in get certificate request")
        val certsType = shortArrayOf(
            ClientCertificateType.rsa_sign,
            ClientCertificateType.rsa_fixed_dh,
        )
        val serverSigAlgs = if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.serverVersion)) {
            TlsUtils.getDefaultSupportedSignatureAlgorithms(context)
        } else {
            null
        }
        val authorities = Vector(listOf(X500Name("CN=BouncyCastle TLS Test CA")))
        return CertificateRequest(certsType, serverSigAlgs, authorities)
    }

    override fun notifyClientCertificate(clientCertificate: Certificate) {
        println("Server in notify client certificate")
        val chain = clientCertificate.certificateList
        if (chain.isEmpty()) {
            println("empty certificate list in notify client certificate")
            return
        }
        chain.forEach {
            val entry = org.bouncycastle.asn1.x509.Certificate.getInstance(it.encoded)
            println(" got fingerprint  ${entry.issuer}: ${entry.subjectPublicKeyInfo.algorithm.algorithm.id}")
        }
    }

    override fun getRSAEncryptionCredentials(): TlsCredentialedDecryptor {
        println("Server is in get rsa encryption creds")
        return super.getRSAEncryptionCredentials()
    }

    override fun getRSASignerCredentials(): TlsCredentialedSigner {
        println("Server is in get rsa signer creds")
        val clientSigAlgs = context.securityParametersHandshake.clientSigAlgs
        return utils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa)
    }

    override fun processClientExtensions(clientExtensions: Hashtable<*, *>?) {
        println("Server in processClientExtensions")
        super.processClientExtensions(clientExtensions)
    }

    override fun getServerExtensions(): Hashtable<*, *> {
        println("Server in getserverextentions")
        return super.getServerExtensions()
    }

    override fun getServerExtensionsForConnection(serverExtensions: Hashtable<*, *>?) {
        println("Server in getServerextensionForConnection")
        super.getServerExtensionsForConnection(serverExtensions)
    }
}
