package com.zhaw.cryptozip.crypt.decrypt

import com.zhaw.cryptozip.crypt.FileHeader
import com.zhaw.cryptozip.crypt.Helpers
import com.zhaw.cryptozip.crypt.InvalidFormatException
import com.zhaw.cryptozip.crypt.Helpers.getMACSize
import com.zhaw.cryptozip.crypt.Helpers.inputStreamToByteArray
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPublicKey
import java.util.*

/**
 * The abstract HybridDecryption class allows hybrid decryption of a document.
 * It provides implemented functionality to decrypt the document based on a
 * hybrid encrypted document and a private key (both available as InputStreams).
 * It also checks the MAC over the decrypted document. To use the class, a
 * subclass must implement the getFileHeader, getDecryptedSecretKey,
 * decryptDocument, and checkMAC methods.
 */
abstract class HybridDecryption {
    enum class AutIntState {
        valid, invalid
    }

    /**
     * Decrypts an encrypted document that is available from an InputStream.
     *
     * @param input The document to decrypt
     * @param privateKeyDecrypt An input stream from which the private key to
     * sign can be read
     * @param macPassword The password to use for the MAC
     * @return The decrypted document
     */
    @Throws(CertificateException::class)
    fun decryptDocumentStream(
        input: InputStream?,
        privateKeyDecrypt: InputStream?,
        macPassword: ByteArray?
    ): DecryptedDocument {
        val decryptedDocument = DecryptedDocument()

        // Get the entire encrypted data structure and the file header
        val headerEncryptedDocumentAuthInt = inputStreamToByteArray(
            input!!
        )
        val fileHeader = getFileHeader(headerEncryptedDocumentAuthInt)

        // Check used the authentication and integrity protection type
        val authIntType = fileHeader.authIntType
        var headerEncryptedDocument: ByteArray? = null
        when (authIntType) {
            Helpers.MAC -> {
                decryptedDocument.authIntType = Helpers.MAC

                // Get the MAC algorithm
                val macAlgorithm = fileHeader.authIntAlgorithm

                // Get headerEncryptedDocument and MAC
                val macLength = getMACSize(macAlgorithm!!)
                headerEncryptedDocument = Arrays.copyOfRange(
                    headerEncryptedDocumentAuthInt, 0,
                    headerEncryptedDocumentAuthInt!!.size - macLength
                )
                val macReceived = Arrays.copyOfRange(
                    headerEncryptedDocumentAuthInt,
                    headerEncryptedDocumentAuthInt.size - macLength,
                    headerEncryptedDocumentAuthInt.size
                )
                decryptedDocument.authIntReceived = macReceived

                // Check the MAC
                if (checkMAC(
                        decryptedDocument, headerEncryptedDocument,
                        macAlgorithm, macReceived, macPassword
                    )
                ) {
                    decryptedDocument.authIntState = AutIntState.valid
                } else {
                    decryptedDocument.authIntState = AutIntState.invalid
                }
            }
            Helpers.SIGNATURE -> {
                decryptedDocument.authIntType = Helpers.SIGNATURE

                // Get the signature algorithm
                val signatureAlgorithm = fileHeader.authIntAlgorithm

                // Get the certificate from the file header, create certificate
                // object and get public key length
                val certificateRaw = fileHeader.certificate
                val cf = CertificateFactory.getInstance("X.509")
                val `in`: InputStream = ByteArrayInputStream(certificateRaw)
                val certificate = cf.generateCertificate(`in`)
                val signatureLength =
                    (certificate.publicKey as RSAPublicKey).modulus.bitLength() / 8

                // Get headerEncryptedDocument and signature and check the signature
                headerEncryptedDocument = Arrays.copyOfRange(
                    headerEncryptedDocumentAuthInt, 0,
                    headerEncryptedDocumentAuthInt!!.size - signatureLength
                )
                val signatureReceived = Arrays.copyOfRange(
                    headerEncryptedDocumentAuthInt,
                    headerEncryptedDocumentAuthInt.size - signatureLength,
                    headerEncryptedDocumentAuthInt.size
                )
                decryptedDocument.authIntReceived = signatureReceived

                // Check the signature
                if (checkSignature(
                        decryptedDocument, headerEncryptedDocument,
                        signatureAlgorithm, signatureReceived, certificate
                    )
                ) {
                    decryptedDocument.authIntState = AutIntState.valid
                } else {
                    decryptedDocument.authIntState = AutIntState.invalid
                }
            }
            Helpers.NONE -> {
                decryptedDocument.authIntType = Helpers.NONE

                // No MAC
                headerEncryptedDocument = headerEncryptedDocumentAuthInt
            }
            else -> throw Exception("[AuthIntType] AuthIntType $authIntType not supported")
        }

        // Remove header from headerEncryptedDocument
        val headerLength = fileHeader.encode().size
        val encryptedDocument = Arrays.copyOfRange(
            headerEncryptedDocument,
            headerLength, headerEncryptedDocument!!.size
        )

        // Get the secret key from the file header and decrypt it
        val secretKey = getDecryptedSecretKey(fileHeader, privateKeyDecrypt)

        // Decrypt the document with the secret key
        val document = decryptDocument(encryptedDocument, fileHeader, secretKey)
        decryptedDocument.document = document

        // Set the fields in decryptedDocument and return it
        decryptedDocument.cipherName = fileHeader.cipherAlgorithm
        decryptedDocument.authIntName = fileHeader.authIntAlgorithm
        decryptedDocument.iv = fileHeader.iV
        decryptedDocument.secretKey = secretKey
        return decryptedDocument
    }

    /**
     * Gets the file header object.
     *
     * @param headerEncryptedDocument The encrypted document, including the file
     * header
     * @return The file header object
     */
    @Throws(Exception::class)
    protected abstract fun getFileHeader(headerEncryptedDocument: ByteArray?): FileHeader

    /**
     * Checks the HMAC over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param expectedMAC The expected MAC
     * @return true if the MAC is correct, false otherwise
     */
    @Throws(Exception::class)
    abstract fun checkMAC(
        decryptedDocument: DecryptedDocument?,
        input: ByteArray?, macAlgorithm: String?, expectedMAC: ByteArray?,
        password: ByteArray?
    ): Boolean

    /**
     * Checks the Signature over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to check the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param signature The signature
     * @param certificate The certificate to verify the signature
     * @return true if the MAC is correct, false otherwise
     */
    @Throws(Exception::class)
    abstract fun checkSignature(
        decryptedDocument: DecryptedDocument?,
        input: ByteArray?,
        signatureAlgorithm: String?,
        signature: ByteArray?,
        certificate: Certificate?
    ): Boolean

    /**
     * Gets the decrypted secret key.
     *
     * @param fileHeader The file header
     * @param privateKey The private key to decrypt the secret key
     * @return The decrypted secret key
     */
    @Throws(Exception::class)
    protected abstract fun getDecryptedSecretKey(
        fileHeader: FileHeader?,
        privateKey: InputStream?
    ): ByteArray

    /**
     * Decrypts the document.
     *
     * @param encryptedDocument The document to decrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key to decrypt the document
     * @return The decrypted document
     */
    @Throws(Exception::class)
    protected abstract fun decryptDocument(
        encryptedDocument: ByteArray?,
        fileHeader: FileHeader?,
        secretKey: ByteArray?
    ): ByteArray
}
