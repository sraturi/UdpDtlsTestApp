package com.example.udpdtlstest.dtls

import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCipher
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.TlsDHConfig
import org.bouncycastle.tls.crypto.TlsDHDomain
import org.bouncycastle.tls.crypto.TlsECConfig
import org.bouncycastle.tls.crypto.TlsECDomain
import org.bouncycastle.tls.crypto.TlsEncryptor
import org.bouncycastle.tls.crypto.TlsHMAC
import org.bouncycastle.tls.crypto.TlsHash
import org.bouncycastle.tls.crypto.TlsNonceGenerator
import org.bouncycastle.tls.crypto.TlsSRP6Client
import org.bouncycastle.tls.crypto.TlsSRP6Server
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator
import org.bouncycastle.tls.crypto.TlsSRPConfig
import org.bouncycastle.tls.crypto.TlsSecret
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.experimental.xor

class DtlsCryto : TlsCrypto {

    private val random = SecureRandom()
    override fun hasAllRawSignatureAlgorithms(): Boolean {
        return false
    }

    override fun hasDHAgreement(): Boolean {
        return false
    }

    override fun hasECDHAgreement(): Boolean {
        return false
    }

    override fun hasEncryptionAlgorithm(encryptionAlgorithm: Int): Boolean {
        return false
    }

    override fun hasCryptoHashAlgorithm(cryptoHashAlgorithm: Int): Boolean {
        return false
    }

    override fun hasCryptoSignatureAlgorithm(cryptoSignatureAlgorithm: Int): Boolean {
        return false
    }

    override fun hasMacAlgorithm(macAlgorithm: Int): Boolean {
        return false
    }

    override fun hasNamedGroup(namedGroup: Int): Boolean {
        return false
    }

    override fun hasRSAEncryption(): Boolean {
        return false
    }

    override fun hasSignatureAlgorithm(signatureAlgorithm: Short): Boolean {
        return false
    }

    override fun hasSignatureAndHashAlgorithm(sigAndHashAlgorithm: SignatureAndHashAlgorithm?): Boolean {
        return false
    }

    override fun hasSignatureScheme(signatureScheme: Int): Boolean {
        return false
    }

    override fun hasSRPAuthentication(): Boolean {
        return false
    }

    override fun createSecret(data: ByteArray?): TlsSecret {
        return object : TlsSecret {
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

            override fun encrypt(encryptor: TlsEncryptor?): ByteArray {
                TODO("Not yet implemented")
            }

            override fun extract(): ByteArray {
                TODO("Not yet implemented")
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
                TODO("Not yet implemented")
            }
        }
    }

    override fun generateRSAPreMasterSecret(clientVersion: ProtocolVersion?): TlsSecret {
        val secret = ByteArray(48)
        random.nextBytes(secret)
        return createSecret(secret)
    }

    override fun getSecureRandom(): SecureRandom {
        return random
    }

    override fun createCertificate(encoding: ByteArray?): TlsCertificate {
        TODO("Not yet implemented")
    }

    override fun createCipher(
        cryptoParams: TlsCryptoParameters?,
        encryptionAlgorithm: Int,
        macAlgorithm: Int,
    ): TlsCipher {
        TODO("Not yet implemented")
    }

    override fun createDHDomain(dhConfig: TlsDHConfig?): TlsDHDomain {
        TODO("Not yet implemented")
    }

    override fun createECDomain(ecConfig: TlsECConfig?): TlsECDomain {
        TODO("Not yet implemented")
    }

    override fun adoptSecret(secret: TlsSecret): TlsSecret {
        return secret
    }

    override fun createHash(cryptoHashAlgorithm: Int): TlsHash {
        TODO("Not yet implemented")
    }

    override fun createHMAC(macAlgorithm: Int): TlsHMAC {
        TODO("Not yet implemented")
    }

    override fun createHMACForHash(cryptoHashAlgorithm: Int): TlsHMAC {
        TODO("Not yet implemented")
    }

    override fun createNonceGenerator(additionalSeedMaterial: ByteArray): TlsNonceGenerator {
        return TlsNonceGenerator { size ->
            val seed = additionalSeedMaterial ?: ByteArray(0)
            val nonce = ByteArray(size)
            random.nextBytes(nonce)
            for (i in 0 until size) {
                nonce[i] = nonce[i] xor seed[i % seed.size]
            }
            nonce
        }
    }

    override fun createSRP6Client(srpConfig: TlsSRPConfig?): TlsSRP6Client {
        TODO("Not yet implemented")
    }

    override fun createSRP6Server(
        srpConfig: TlsSRPConfig?,
        srpVerifier: BigInteger?,
    ): TlsSRP6Server {
        TODO("Not yet implemented")
    }

    override fun createSRP6VerifierGenerator(srpConfig: TlsSRPConfig?): TlsSRP6VerifierGenerator {
        TODO("Not yet implemented")
    }

    override fun hkdfInit(cryptoHashAlgorithm: Int): TlsSecret {
        TODO("Not yet implemented")
    }
}

