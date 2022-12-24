package com.zhaw.cryptozip.crypt.encrypt

import com.zhaw.cryptozip.crypt.FileHeader
import com.zhaw.cryptozip.crypt.Helpers
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.NoSuchAlgorithmException
import javax.crypto.NoSuchPaddingException

/**
 * The abstract HybridEncryption class allows encrypting a document using hybrid
 * encryption and producing a MAC over a file header and the encrypted document.
 * GCM is also supported, but in this case, no MAC is created as this is
 * integrated in GCM. To use the class, a subclass must implement the five
 * abstract methods.
 */
abstract class HybridEncryption {
    /**
     * Encrypts a document that is available from an InputStream.
     *
     * @param document The document to encrypt
     * @param certificateEncrypt The certificate of which the public key is used
     * to encrypt the document
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length to use
     * @param authIntType The type to use for authentication and integrity
     * protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The algorithm to use for authentication and
     * integrity protection
     * @param macPassword The password to use for the MAC
     * @param privateKeySign The private key to create the signature
     * @param certificateVerify The certificate for signature verification
     * @return The encrypted and authenticated/integrity protected document
     * including the file header.
     */
    fun encryptDocumentStream(
        document: InputStream?,
        certificateEncrypt: InputStream?, cipherAlgorithm: String?, keyLength: Int,
        authIntType: Char, authIntAlgorithm: String?, macPassword: ByteArray?,
        privateKeySign: InputStream?, certificateVerify: InputStream?
    ): ByteArray? {

        // Generate a new random secret key
        var secretKey: ByteArray? = ByteArray(0)
        secretKey = try {
            generateSecretKey(cipherAlgorithm, keyLength)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }

        // Encrypt the secret key with the public key in the certificate
        val encryptedSecretKey = encryptSecretKey(secretKey, certificateEncrypt)

        // Generate the file header using the encrypted secret key
        val fileHeader: FileHeader = generateFileHeader(
            cipherAlgorithm, authIntType,
            authIntAlgorithm, certificateVerify, encryptedSecretKey
        )

        // Encrypt the document
        val encryptedDocument = encryptDocument(
            document, fileHeader,
            secretKey
        )

        // Prepend the file header
        val headerEncryptedDocument = concatByteArrays(
            fileHeader.encode(),
            encryptedDocument
        )

        // Check authIntType in the file header
        var headerEncryptedDocumentAuthInt: ByteArray? = null
        when (authIntType) {
            Helpers.MAC -> {

                // Compute the MAC and append it
                val hmac = computeMAC(
                    headerEncryptedDocument,
                    authIntAlgorithm, macPassword
                )!!
                headerEncryptedDocumentAuthInt = concatByteArrays(headerEncryptedDocument, hmac)
            }
            Helpers.SIGNATURE -> {

                // Compute the Signature and append it
                val signature = computeSignature(
                    headerEncryptedDocument,
                    authIntAlgorithm, privateKeySign
                )
                headerEncryptedDocumentAuthInt =
                    concatByteArrays(headerEncryptedDocument, signature)
            }
            Helpers.NONE ->
                // Don't append anything
                headerEncryptedDocumentAuthInt = headerEncryptedDocument
            else -> {}
        }

        // Return the completely protected document
        return headerEncryptedDocumentAuthInt
    }

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    protected abstract fun generateSecretKey(
        cipherAlgorithm: String?,
        keyLength: Int
    ): ByteArray?

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     * the public key for encryption can be read
     * @return The encrypted secret key
     */
    protected abstract fun encryptSecretKey(
        secretKey: ByteArray?,
        certificateEncrypt: InputStream?
    ): ByteArray

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
    protected abstract fun generateFileHeader(
        cipherAlgorithm: String?,
        authIntType: Char, authIntAlgorithm: String?,
        certificateVerify: InputStream?, encryptedSecretKey: ByteArray?
    ): FileHeader

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    protected abstract fun encryptDocument(
        document: InputStream?,
        fileHeader: FileHeader?, secretKey: ByteArray?
    ): ByteArray

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    protected abstract fun computeMAC(
        dataToProtect: ByteArray?,
        macAlgorithm: String?, password: ByteArray?
    ): ByteArray?

    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign An input stream from which the private key to sign
     * can be read
     * @return The byte array that contains the signature
     */
    protected abstract fun computeSignature(
        dataToProtect: ByteArray?,
        signatureAlgorithm: String?, privateKeySign: InputStream?
    ): ByteArray?

    private fun concatByteArrays(first: ByteArray?, second: ByteArray?): ByteArray? {
        try {
            val outputStream = ByteArrayOutputStream()
            outputStream.write(first)
            outputStream.write(second)
            return outputStream.toByteArray()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }
}