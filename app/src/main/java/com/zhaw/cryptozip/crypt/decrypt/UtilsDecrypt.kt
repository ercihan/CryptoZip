package com.zhaw.cryptozip.crypt.decrypt

import com.zhaw.cryptozip.crypt.Helpers
import com.zhaw.cryptozip.crypt.Helpers.asHex
import java.io.*
import java.nio.charset.Charset
import javax.security.cert.CertificateException

class UtilsDecrypt {

    fun sLDecrypt(
        inFilename: String, outFilename: String,
        privateKeyDecrypt: InputStream, macPassword: String
    ) {
        var `in`: FileInputStream? = null
        var out: FileOutputStream? = null
        try {
            // Create streams for all files to read/write
            val inFile = File(inFilename)
            `in` = FileInputStream(inFile)
            val outFile = File(outFilename)
            out = FileOutputStream(outFile)

            // Decrypt the document
            decrypt(`in`, out, privateKeyDecrypt, macPassword)
        } catch (e: FileNotFoundException) {
            System.out.println("File not found: " + e.printStackTrace())
        }
         catch (e: IOException) {
            System.out.println("I/O error: " + e.printStackTrace())
        } catch (e: CertificateException) {
            System.out.println("Certificate error: " + e.printStackTrace())
        } catch (e: Exception) {
            println("Error decrypting file! " + e.message)
        } finally {

            // close the streams
            if (`in` != null) {
                try {
                    `in`.close()
                } catch (e: IOException) {
                }
            }
            if (out != null) {
                try {
                    out.close()
                } catch (e: IOException) {
                }
            }
            if (privateKeyDecrypt != null) {
                try {
                    privateKeyDecrypt.close()
                } catch (e: IOException) {
                }
            }
        }
    }

    /**
     * Hybrid decrypts a document.
     *
     * @param in The InputStream from which to read the encrypted document
     * @param out The OutputStream to which to write the decrypted document
     * @param privateKeyDecrypt The InputStream from which to read the private
     * key for decryption
     * @param macPassword The password to use for computing the HMAC
     * @throws IOException
     */
    @Throws(
        Exception::class,
        IOException::class,
        CertificateException::class
    )
    private fun decrypt(
        `in`: FileInputStream?,
        out: FileOutputStream?,
        privateKeyDecrypt: InputStream?,
        macPassword: String
    ) {

        // Hybrid decrypt the document
        val hd: HybridDecryption = HybridDecryptionImpl()
        val document: DecryptedDocument = hd.decryptDocumentStream(
            `in`, privateKeyDecrypt,
            macPassword.toByteArray(Charset.forName("UTF-8"))
        )

        // Display information depending on authentication and integrity protection type
        println("")
        if (document.authIntType === Helpers.MAC) {
            System.out.println("MAC algorithm:        " + document.authIntName)
            println("MAC received:         " + asHex(document.authIntReceived!!))
            println("MAC computed:         " + asHex(document.authIntComp!!))
            if (document.authIntState === HybridDecryption.AutIntState.valid) {
                println("=> MAC successfully verified")
            } else if (document.authIntState!! === HybridDecryption.AutIntState.invalid) {
                println("=> Error, wrong MAC!")
            }
        } else if (document.authIntType === Helpers.SIGNATURE) {
            System.out.println("Signature algorithm:  " + document.authIntName)
            println("Signature received:   " + asHex(document.authIntReceived!!))
            if (document.authIntState === HybridDecryption.AutIntState.valid) {
                println("=> Signature successfully verified")
            } else if (document.authIntState === HybridDecryption.AutIntState.invalid) {
                println("=> Error, signature could not be verified!")
            }
        } else if (document.authIntType === Helpers.NONE) {
            println("=> Neither MAC nor Signature included to verify authentication and integrity")
        }

        // Display information about algorithm, key and IV
        println("")
        System.out.println("Cipher algorithm:     " + document.cipherName)
        System.out.println("Key length:           " + document.secretKey!!.size * 8)
        println("Key:                  " + asHex(document.secretKey!!))
        println("IV:                   " + asHex(document.iv!!))

        // Display information about plaintext
        println("")
        System.out.print("Plaintext (" + document.document!!.size.toString() + " bytes): ")
        if (document.document!!.size <= 1000) {
            println(String(document.document!!))
        } else {
            println(String(document.document!!, 0, 1000))
        }

        // Save the decrypted document
        out?.write(document.document!!)
    }
}