package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.CompressionMethod
import org.bouncycastle.tls.SessionParameters
import org.bouncycastle.tls.TlsSession
import org.bouncycastle.tls.TlsUtils
import org.bouncycastle.tls.crypto.TlsEncryptor
import org.bouncycastle.tls.crypto.TlsSecret

class DmmySessionParam {

    companion object {
        fun getParam(): TlsSession {
            val sessionId: ByteArray = byteArrayOf(0x01, 0x02, 0x03, 0x04)
            val cipherSuite: Int = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            val compressionMethod: Short = CompressionMethod._null

            val masterSecret: ByteArray = byteArrayOf(0x11, 0x22, 0x33, 0x44)
            val extendedMasterSecret = true

            // Create DTLS session parameters using the builder pattern
            return TlsUtils.importSession(
                sessionId,
                SessionParameters.Builder()
                    .setCipherSuite(cipherSuite)
                    .setCompressionAlgorithm(compressionMethod)
                    .setMasterSecret(DummyTlsSecret(masterSecret))
                    .setExtendedMasterSecret(extendedMasterSecret)
                    .build(),
            )
        }
    }

    class DummyTlsSecret(private val secret: ByteArray) : TlsSecret {
        override fun calculateHMAC(
            cryptoHashAlgorithm: Int,
            buf: ByteArray?,
            off: Int,
            len: Int,
        ): ByteArray {
            TODO("Not yet implemented")
        }

        override fun deriveUsingPRF(
            prfAlgorithm: Int,
            label: String?,
            seed: ByteArray?,
            length: Int,
        ): TlsSecret {
            TODO("Not yet implemented")
        }

        override fun destroy() {
            TODO("Not yet implemented")
        }

        override fun encrypt(encryptor: TlsEncryptor): ByteArray {
            return encryptor.encrypt(secret, 0, secret.size)
        }

        override fun extract(): ByteArray {
            return secret
        }

        override fun hkdfExpand(
            cryptoHashAlgorithm: Int,
            info: ByteArray?,
            length: Int,
        ): TlsSecret {
            TODO("Not yet implemented")
        }

        override fun hkdfExtract(cryptoHashAlgorithm: Int, ikm: TlsSecret?): TlsSecret {
            TODO("Not yet implemented")
        }

        override fun isAlive(): Boolean {
            return true
        }
    }
}
