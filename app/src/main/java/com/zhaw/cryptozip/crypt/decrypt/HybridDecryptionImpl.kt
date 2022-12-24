package com.zhaw.cryptozip.crypt.decrypt

import com.zhaw.cryptozip.crypt.Helpers
import com.zhaw.cryptozip.crypt.InvalidFormatException
import com.zhaw.cryptozip.crypt.FileHeader
import java.io.IOException
import java.io.InputStream
import java.security.*
import java.security.cert.Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class HybridDecryptionImpl : HybridDecryption() {
    /**
     * Gets the file header object.
     *
     * @param headerEncryptedDocument The encrypted document, including the file
     * header
     * @return The file header object
     */
    @Throws(InvalidFormatException::class)
    override fun getFileHeader(headerEncryptedDocument: ByteArray?): FileHeader {
        return FileHeader(headerEncryptedDocument)
    }

    /**
     * Checks the HMAC over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param expectedMAC The expected MAC
     * @return true if the MAC is correct, false otherwise
     */
    @Throws(InvalidFormatException::class)
    override fun checkMAC(
        decryptedDocument: DecryptedDocument?, input: ByteArray?,
        macAlgorithm: String?, expectedMAC: ByteArray?, password: ByteArray?
    ): Boolean {
        return try {
            val keySpec = SecretKeySpec(password, macAlgorithm)
            val hmac = Mac.getInstance(keySpec.algorithm)
            hmac.init(keySpec)
            val computedMAC = hmac.doFinal(input)
            decryptedDocument!!.authIntComp = computedMAC
            Arrays.equals(computedMAC, expectedMAC)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidFormatException("[MAC] No such algorithm: " + e.message)
        } catch (e: IllegalArgumentException) {
            throw InvalidFormatException("[MAC] Empty Key: " + e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidFormatException("[MAC] Invalid Key: " + e.message)
        }
    }

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
    @Throws(InvalidFormatException::class)
    override fun checkSignature(
        decryptedDocument: DecryptedDocument?,
        input: ByteArray?, signatureAlgorithm: String?, signature: ByteArray?,
        certificate: Certificate?
    ): Boolean {
        return try {
            val signing = Signature.getInstance(signatureAlgorithm)
            signing.initVerify(certificate)
            signing.update(input)
            signing.verify(signature)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidFormatException("[Signature] No such algorithm: " + e.message)
        } catch (e: SignatureException) {
            throw InvalidFormatException("[Signature] Signature cannot be checked: " + e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidFormatException("[Signature] Invalid Key: " + e.message)
        }
    }

    /**
     * Gets the decrypted secret key.
     *
     * @param fileHeader The file header
     * @param privateKeyDecrypt An input stream from which the private key to
     * decrypt the secret key can be read
     * @return The decrypted secret key
     */
    @Throws(InvalidFormatException::class)
    override fun getDecryptedSecretKey(
        fileHeader: FileHeader?,
        privateKeyDecrypt: InputStream?
    ): ByteArray {
        return try {
            // Read the private key and generate a privateKey object
            //val keySpecString = privateKeyDecrypt!!.bufferedReader().use { it.readText() }  // defaults to UTF-8
            //ORIGINAL: PKCS8EncodedKeySpec(privateKeyDecrypt!!.readAllBytes())

            //on 106 should be the alternative
            val keySpec: KeySpec = PKCS8EncodedKeySpec(privateKeyDecrypt!!.readBytes())


            val kf = KeyFactory.getInstance("RSA")
            val privateKey = kf.generatePrivate(keySpec)

            // Create the RSA cipher with the private key
            val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            // Decrypt and return the header
            cipher.doFinal(fileHeader!!.encryptedSecretKey)
        } catch (e: IOException) {
            throw InvalidFormatException("[Private Key] Cannot read: " + e.message)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidFormatException("[Secret Key] No such algorithm: " + e.message)
        } catch (e: NoSuchPaddingException) {
            throw InvalidFormatException("[Secret Key] No such padding: " + e.message)
        } catch (e: InvalidKeySpecException) {
            throw InvalidFormatException("[Secret Key] Invalid key spec: " + e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidFormatException("[Secret Key] Invalid key: " + e.message)
        } catch (e: IllegalBlockSizeException) {
            throw InvalidFormatException("[Secret Key] Illegal block size: " + e.message)
        } catch (e: BadPaddingException) {
            throw InvalidFormatException("[Secret Key] Bad padding: " + e.message)
        }
    }

    /**
     * Decrypts the document.
     *
     * @param encryptedDocument The document to decrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key to decrypt the document
     * @return The decrypted document
     */
    @Throws(InvalidFormatException::class)
    override fun decryptDocument(
        encryptedDocument: ByteArray?,
        fileHeader: FileHeader?, secretKey: ByteArray?
    ): ByteArray {
        return try {
            // Get the used cipher and create the Cipher object
            val cipherName = fileHeader!!.cipherAlgorithm
            val cipher = Cipher.getInstance(cipherName)
            val skeySpec = SecretKeySpec(
                secretKey,
                Helpers.getCipherName(fileHeader.cipherAlgorithm!!)
            )

            // Initialize the cipher correctly, depending on the mode
            val iv = fileHeader.iV
            if (Helpers.isGCM(fileHeader.cipherAlgorithm!!)) {

                // GCM, use an IV, an auth tag length, and add the file header as additional
                // authenticated data
                val gcmParameterSpec = GCMParameterSpec(Helpers.AUTH_TAG_LENGTH, iv)
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, gcmParameterSpec)
                cipher.updateAAD(fileHeader.encode())
            } else if (Helpers.hasIV(fileHeader.cipherAlgorithm!!)) {

                // IV is used, but neither CHACHA20 nor GCM mode
                val ivParameterSpec = IvParameterSpec(iv)
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec)
            } else {

                // Other modes (e.g. stream ciphers), don't use an IV
                cipher.init(Cipher.DECRYPT_MODE, skeySpec)
            }

            // Decrypt the document and return the plaintext
            cipher.doFinal(encryptedDocument)
        } catch (e: NoSuchAlgorithmException) {
            throw InvalidFormatException("[Document] No such algorithm: " + e.message)
        } catch (e: NoSuchPaddingException) {
            throw InvalidFormatException("[Document] No such padding: " + e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidFormatException("[Document] Invalid key: " + e.message)
        } catch (e: InvalidAlgorithmParameterException) {
            throw InvalidFormatException("[Document] Invalid algorithm parameter: " + e.message)
        } catch (e: BadPaddingException) {
            throw InvalidFormatException("[Document] Bad padding: " + e.message)
        } catch (e: IllegalBlockSizeException) {
            throw InvalidFormatException("[Document] Illegal block size: " + e.message)
        }
    }
}