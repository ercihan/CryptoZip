package com.zhaw.cryptozip.crypt.encrypt

import com.zhaw.cryptozip.Utils
import java.io.*
import java.nio.charset.Charset

class UtilsEncrypt : Utils() {
    fun encryptFile(inFilename: String, outFilename: String,
                    certificateEncrypt: InputStream, cipherAlgorithm: String,
                    keyLength: Int, authIntType: Char, authIntAlgorithm: String,
                    macPassword: String, privateKeySign: InputStream?, certificateVerify: InputStream?){
        var `in`: FileInputStream? = null
        var out: FileOutputStream? = null

        try {
            // Create streams for all files to read/write
            val inFile = File(inFilename)
            `in` = FileInputStream(inFile)
            val outFile = File(outFilename)
            out = FileOutputStream(outFile)

            // Encrypt the document
            encrypt(
                `in`, out, certificateEncrypt, cipherAlgorithm, keyLength,
                authIntType, authIntAlgorithm, macPassword, privateKeySign!!,
                certificateVerify!!
            )
        } catch (e: FileNotFoundException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {

            // Close the streams
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
            if (certificateEncrypt != null) {
                try {
                    certificateEncrypt.close()
                } catch (e: IOException) {
                }
            }
            if (privateKeySign != null) {
                try {
                    privateKeySign.close()
                } catch (e: IOException) {
                }
            }
            if (certificateVerify != null) {
                try {
                    certificateVerify.close()
                } catch (e: IOException) {
                }
            }
        }

    }

    @Throws(IOException::class)
    private fun encrypt(
        `in`: InputStream, out: OutputStream,
        certificateEncrypt: InputStream, cipherAlgorithm: String, keyLength: Int,
        authIntType: Char, authIntAlgorithm: String, macPassword: String?,
        privateKeySign: InputStream, certificateVerify: InputStream
    ) {

        // Hybrid encrypt the document
        val he: HybridEncryption = HybridEncryptionImpl()
        var macPasswordBytes: ByteArray? = null
        if (macPassword != null) {
            macPasswordBytes = macPassword.toByteArray(Charset.forName("UTF-8"))
        }
        val encrypted: ByteArray? = he.encryptDocumentStream(
            `in`, certificateEncrypt,
            cipherAlgorithm, keyLength, authIntType, authIntAlgorithm,
            macPasswordBytes, privateKeySign, certificateVerify
        )

        // Save the encrypted document
        out.write(encrypted)
    }
}