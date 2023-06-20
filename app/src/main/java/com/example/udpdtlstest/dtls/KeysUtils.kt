
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.CertificateEntry
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAlgorithm
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.TlsContext
import org.bouncycastle.tls.TlsCredentialedSigner
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsUtils
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.Hashtable
import java.util.Vector

// bunch of util methods copied from bouncy castle lib
class KeysUtils() {

    fun getResourceName(signatureAlgorithm: Short): String {
        return when (signatureAlgorithm) {
            SignatureAlgorithm.rsa, SignatureAlgorithm.rsa_pss_rsae_sha256, SignatureAlgorithm.rsa_pss_rsae_sha384, SignatureAlgorithm.rsa_pss_rsae_sha512 -> "rsa"
            SignatureAlgorithm.dsa -> "dsa"
            SignatureAlgorithm.ecdsa -> "ecdsa"
            SignatureAlgorithm.ed25519 -> "ed25519"
            SignatureAlgorithm.ed448 -> "ed448"
            SignatureAlgorithm.rsa_pss_pss_sha256 -> "rsa_pss_256"
            SignatureAlgorithm.rsa_pss_pss_sha384 -> "rsa_pss_384"
            SignatureAlgorithm.rsa_pss_pss_sha512 -> "rsa_pss_512"
            else -> throw TlsFatalAlert(AlertDescription.internal_error)
        }
    }

    fun loadSignerCredentials(
        cryptoParams: TlsCryptoParameters,
        crypto: TlsCrypto,
        certResources: Array<String?>,
        keyResource: String?,
        signatureAndHashAlgorithm: SignatureAndHashAlgorithm?,
    ): TlsCredentialedSigner {
        val certificate = loadCertificateChain(cryptoParams.serverVersion, crypto, certResources)

        // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key (as raw data)
        if (crypto is BcTlsCrypto) {
            val privateKey = loadBcPrivateKeyResource(keyResource)
            return BcDefaultTlsCredentialedSigner(
                cryptoParams,
                crypto,
                privateKey,
                certificate,
                signatureAndHashAlgorithm,
            )
        } else {
            error("invalid crpto type")
        }
    }

    fun loadSignerCredentials(
        context: TlsContext,
        certResources: Array<String?>,
        keyResource: String?,
        signatureAndHashAlgorithm: SignatureAndHashAlgorithm?,
    ): TlsCredentialedSigner {
        val crypto = context.crypto
        val cryptoParams = TlsCryptoParameters(context)
        return loadSignerCredentials(
            cryptoParams,
            crypto,
            certResources,
            keyResource,
            signatureAndHashAlgorithm,
        )
    }

    fun loadSignerCredentials(
        context: TlsContext,
        supportedSignatureAlgorithms: Vector<*>?,
        signatureAlgorithm: Short,
        certResource: String?,
        keyResource: String?,
    ): TlsCredentialedSigner {
        var supportedSignatureAlgorithms = supportedSignatureAlgorithms
        var signatureAndHashAlgorithm: SignatureAndHashAlgorithm? = null
        if (supportedSignatureAlgorithms == null) {
            supportedSignatureAlgorithms =
                TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm)
        }
        for (i in supportedSignatureAlgorithms!!.indices) {
            val alg = supportedSignatureAlgorithms.elementAt(i) as SignatureAndHashAlgorithm
            if (alg.signature == signatureAlgorithm) {
                // Just grab the first one we find
                signatureAndHashAlgorithm = alg
                break
            }
        }
        return if (signatureAndHashAlgorithm == null) {
            error("errrrrrrrr")
        } else {
            loadSignerCredentials(
                context,
                arrayOf(certResource),
                keyResource,
                signatureAndHashAlgorithm,
            )
        }
    }

    fun loadSignerCredentialsServer(
        context: TlsContext,
        supportedSignatureAlgorithms: Vector<*>?,
        signatureAlgorithm: Short,
    ): TlsCredentialedSigner {
        var sigName = getResourceName(signatureAlgorithm)
        when (signatureAlgorithm) {
            SignatureAlgorithm.rsa, SignatureAlgorithm.rsa_pss_rsae_sha256, SignatureAlgorithm.rsa_pss_rsae_sha384, SignatureAlgorithm.rsa_pss_rsae_sha512 -> sigName += "-sign"
        }
        val certResource = "x509-server-$sigName.pem"
        val keyResource = "x509-server-key-$sigName.pem"
        return loadSignerCredentials(
            context,
            supportedSignatureAlgorithms,
            signatureAlgorithm,
            certResource,
            keyResource,
        )
    }

    fun loadCertificateChain(
        protocolVersion: ProtocolVersion?,
        crypto: TlsCrypto,
        resources: Array<String?>,
    ): org.bouncycastle.tls.Certificate {
        if (TlsUtils.isTLSv13(protocolVersion)) {
            val certificateEntryList = arrayOfNulls<CertificateEntry>(resources.size)
            for (i in resources.indices) {
                val certificate = loadCertificateResource(crypto, resources[i])

                // TODO[tls13] Add possibility of specifying e.g. CertificateStatus
                val extensions: Hashtable<*, *>? = null
                certificateEntryList[i] = CertificateEntry(certificate, extensions)
            }

            // TODO[tls13] Support for non-empty request context
            val certificateRequestContext = TlsUtils.EMPTY_BYTES
            return org.bouncycastle.tls.Certificate(certificateRequestContext, certificateEntryList)
        } else {
            val chain = arrayOfNulls<TlsCertificate>(resources.size)
            for (i in resources.indices) {
                chain[i] = loadCertificateResource(crypto, resources[i])
            }
            return org.bouncycastle.tls.Certificate(chain)
        }
    }

    fun loadCertificateResource(crypto: TlsCrypto, resource: String?): TlsCertificate {
        val pem = loadPemResource(resource)
        if (pem.type.endsWith("CERTIFICATE")) {
            return crypto.createCertificate(pem.content)
        }
        throw IllegalArgumentException("'resource' doesn't specify a valid certificate")
    }

    fun loadBcPrivateKeyResource(resource: String?): AsymmetricKeyParameter {
        val pem = loadPemResource(resource)
        if ((pem.type == "PRIVATE KEY")) {
            return PrivateKeyFactory.createKey(pem.content)
        }
        if ((pem.type == "ENCRYPTED PRIVATE KEY")) {
            throw UnsupportedOperationException("Encrypted PKCS#8 keys not supported")
        }
        if ((pem.type == "RSA PRIVATE KEY")) {
            val rsa = RSAPrivateKey.getInstance(pem.content)
            return RSAPrivateCrtKeyParameters(
                rsa.modulus,
                rsa.publicExponent,
                rsa.privateExponent,
                rsa.prime1,
                rsa.prime2,
                rsa.exponent1,
                rsa.exponent2,
                rsa.coefficient,
            )
        }
        if ((pem.type == "EC PRIVATE KEY")) {
            val pKey = ECPrivateKey.getInstance(pem.content)
            val algId =
                AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.parametersObject)
            val privInfo = PrivateKeyInfo(algId, pKey)
            return PrivateKeyFactory.createKey(privInfo)
        }
        throw IllegalArgumentException("'resource' doesn't specify a valid private key")
    }

    fun loadPemResource(resource: String?): PemObject {
        val s: InputStream =
            FileInputStream("app/src/main/res/$resource")
        PemReader(InputStreamReader(s))
        val p = PemReader(InputStreamReader(s))
        val o = p.readPemObject()
        p.close()
        return o
    }
}


val keyPair = RSAKeyPairGenerator().apply {
    init(RSAKeyGenerationParameters(BigInteger.valueOf(67889), SecureRandom(), 2048, 80))
}.generateKeyPair()!!
fun generateCertificate(): X509Certificate? {
    val subjectName = X500Name("CN=sachin, o=raturi")
    val certBuilder = X509v1CertificateBuilder(
        subjectName,
        BigInteger.valueOf(System.currentTimeMillis()),
        Date.from(Instant.now()),
        Date.from(Instant.now().plus(Duration.ofDays(10))),
        subjectName,
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.public),
    )
    val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")

    // Convert the certificate holder to X509Certificate
    val holder = certBuilder.build(
        BcRSAContentSignerBuilder(
            sigAlgId,
            DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId),
        ).build(keyPair.private),
    )

    return JcaX509CertificateConverter().getCertificate(holder)
}

