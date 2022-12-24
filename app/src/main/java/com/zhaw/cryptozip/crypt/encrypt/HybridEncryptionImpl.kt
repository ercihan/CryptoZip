package com.zhaw.cryptozip.crypt.encrypt

import com.zhaw.cryptozip.crypt.FileHeader
import com.zhaw.cryptozip.crypt.Helpers
import com.zhaw.cryptozip.crypt.Helpers.getCipherName
import com.zhaw.cryptozip.crypt.Helpers.getIVLength
import com.zhaw.cryptozip.crypt.Helpers.hasIV
import java.io.IOException
import java.io.InputStream
import java.security.Key
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
class HybridEncryptionImpl : HybridEncryption() {
    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    override fun generateSecretKey(cipherAlgorithm: String?, keyLength: Int): ByteArray? {
        try {
            val keyGen =
                KeyGenerator.getInstance(getCipherName(cipherAlgorithm!!))
            keyGen.init(keyLength)
            val key = keyGen.generateKey()
            return key.encoded
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     * the public key for encryption can be read
     * @return The encrypted secret key
     */
    override fun encryptSecretKey(
        secretKey: ByteArray?,
        certificateEncrypt: InputStream?
    ): ByteArray {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            var certificate: Certificate? = null
            certificate = cf.generateCertificate(certificateEncrypt)
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            cipher.init(Cipher.ENCRYPT_MODE, certificate)
            cipher.doFinal(secretKey)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    /**
     * Creates a file header object and fills it with the cipher algorithm name,
     * the authentication and integrity protection type and name, and the
     * encrypted secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param authIntType The type to use for authentication and integrity
     * protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The algorithm to use for authentication and
     * integrity protection
     * @param certificateVerify An input stream from which the certificate for
     * signature verification can be read
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    override fun generateFileHeader(
        cipherAlgorithm: String?,
        authIntType: Char, authIntAlgorithm: String?,
        certificateVerify: InputStream?, encryptedSecretKey: ByteArray?
    ): FileHeader {
        val fileHeader = FileHeader()
        fileHeader.cipherAlgorithm = cipherAlgorithm
        if (hasIV(cipherAlgorithm!!)) { //Check if the algorithm uses an initialization vector
            val iv =
                ByteArray(getIVLength(cipherAlgorithm!!)) //set an individual length of the
            //initialization vector depending on which algorithm is in usage
            val random = SecureRandom()
            random.nextBytes(iv)
            fileHeader.iV = iv
        } else {
            fileHeader.iV = "".toByteArray()
        }
        if (authIntType == Helpers.MAC || authIntType == Helpers.SIGNATURE) {
            fileHeader.authIntType = authIntType
            fileHeader.authIntAlgorithm = authIntAlgorithm
        } else {
            fileHeader.authIntType = Helpers.NONE
            fileHeader.authIntAlgorithm = ""
        }
        try {
            if (Objects.nonNull(certificateVerify) && authIntType == Helpers.SIGNATURE) {
                fileHeader.certificate = certificateVerify!!.readBytes()
            } else {
                fileHeader.certificate = "".toByteArray()
            }
        } catch (ex: IOException) {
            ex.printStackTrace()
        }
        fileHeader.encryptedSecretKey = encryptedSecretKey!!
        return fileHeader
    }

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    override fun encryptDocument(
        document: InputStream?,
        fileHeader: FileHeader?, secretKey: ByteArray?
    ): ByteArray {
        return try {
            val iv = fileHeader!!.iV
            val algo = Cipher.getInstance(fileHeader.cipherAlgorithm)
            val algoName: String =
                Helpers.getCipherName(fileHeader.cipherAlgorithm!!)
            val secretKeySpec = SecretKeySpec(secretKey, algoName)
            if (Helpers.isGCM(fileHeader.cipherAlgorithm!!)) {
                val gcmParam = GCMParameterSpec(128, iv) //Tagsize =128
                algo.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParam)
                algo.updateAAD(fileHeader.encode())
            }
            else {
                // Other modes -> do not need an IV
                algo.init(Cipher.ENCRYPT_MODE, secretKeySpec)
            }
            algo.doFinal(Helpers.inputStreamToByteArray(document!!))
        } catch (e: Exception) {
            throw RuntimeException("Exception thrown during encryption ...$e")
        }
    }

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    override fun computeMAC(
        dataToProtect: ByteArray?, macAlgorithm: String?,
        password: ByteArray?
    ): ByteArray? {
        try {
            val mac = Mac.getInstance(macAlgorithm)
            val key: Key = SecretKeySpec(password, macAlgorithm)
            mac.init(key)
            return mac.doFinal(dataToProtect)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign An input stream from which the private key to sign
     * can be read
     * @return The byte array that contains the signature
     */
    override fun computeSignature(
        dataToProtect: ByteArray?,
        signatureAlgorithm: String?, privateKeySign: InputStream?
    ): ByteArray? {
        try {
            val signature = Signature.getInstance(signatureAlgorithm)
            val key = PKCS8EncodedKeySpec(
                Helpers.inputStreamToByteArray(privateKeySign!!)//,signatureAlgorithm
            )
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(key)
            signature.initSign(privateKey)
            signature.update(dataToProtect)
            return signature.sign()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }
}