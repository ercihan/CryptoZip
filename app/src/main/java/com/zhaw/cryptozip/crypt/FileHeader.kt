package com.zhaw.cryptozip.crypt

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.Charset
import java.util.*

/**
 * The FileHeader class supports encoding and decoding of file headers. Encoding
 * means that the file header is built based on the version and encrypted
 * secret key. Decoding means that a file header is read and the version and
 * encrypted secret key are extracted.
 */
class FileHeader {
    var cipherAlgorithm: String? = null
    var iV: ByteArray? = null
    var authIntType = 0.toChar()
    var authIntAlgorithm: String? = null
    var encryptedSecretKey: ByteArray? = null
    var certificate: ByteArray? = null

    /**
     * Constructor. Empty default constructor.
     */
    constructor() {}

    /**
     * Constructor. Decodes an existing file header that is stored in a byte
     * array. The values (version and encrypted secret key) are written to the
     * instance variables version and encryptedSecretKey.
     *
     * @param fileHeader The file header to decode
     * @throws InvalidFormatException
     */
    constructor(fileHeader: ByteArray?) {
        decode(ByteArrayInputStream(fileHeader))
    }

    /**
     * Constructor. Decodes an existing file header that can be read from an
     * InputStream. The values (version and encrypted secret key) are written
     * to the instance variables version and encryptedSecretKey.
     *
     * @param fileHeaderStream The stream from which the file header can be read
     * @throws InvalidFormatException
     */
    constructor(fileHeaderStream: InputStream) {
        decode(fileHeaderStream)
    }

    /**
     * Decodes a file header that can be read from an InputStream. The values
     * (version and encrypted secret key) are written to the instance variables
     * version and encryptedSecretKey.
     *
     * @param is The InputStream from which file header can be read
     * @throws InvalidFormatException
     */
    @Throws(Exception::class)
    private fun decode(`is`: InputStream) {
        var length: Int
        val formatString =
            ByteArray(com.zhaw.cryptozip.crypt.FileHeader.Companion.FORMAT_STRING.size)
        try {
            // Read SLCrypt file type
            `is`.read(formatString)
            if (!Arrays.equals(
                    com.zhaw.cryptozip.crypt.FileHeader.Companion.FORMAT_STRING,
                    formatString
                )
            ) {
                throw Exception("Not an SLCrypt file")
            }

            // Read file version
            if (`is`.read() != com.zhaw.cryptozip.crypt.FileHeader.Companion.VERSION) {
                throw Exception("Unknown file version")
            }

            // Read cipher
            length = `is`.read()
            val cipherBytes = ByteArray(length)
            `is`.read(cipherBytes)
            cipherAlgorithm = String(cipherBytes, Charset.forName("UTF-8"))

            // Read IV
            length = `is`.read()
            iV = ByteArray(length)
            `is`.read(iV)

            // Read authentication/integrity algorithm type
            authIntType = `is`.read().toChar()

            // Read authentication/integrity algorithm
            length = `is`.read()
            val macBytes = ByteArray(length)
            `is`.read(macBytes)
            authIntAlgorithm = String(macBytes, Charset.forName("UTF-8"))

            // Read certificate
            length = 256 * `is`.read() + `is`.read()
            certificate = ByteArray(length)
            `is`.read(certificate)

            // Read encrypted secret key
            length = 256 * `is`.read() + `is`.read()
            encryptedSecretKey = ByteArray(length)
            `is`.read(encryptedSecretKey)
        } catch (e: IOException) {
            throw Exception("Invalid format")
        }
    }

    /**
     * Encodes the file header using the currently stored values from the
     * instance variables.
     *
     * @return The file header
     */
    fun encode(): ByteArray {
        val os = ByteArrayOutputStream()
        try {
            os.write(com.zhaw.cryptozip.crypt.FileHeader.Companion.FORMAT_STRING)
            os.write(com.zhaw.cryptozip.crypt.FileHeader.Companion.VERSION)
            os.write(cipherAlgorithm!!.length and 0xff)
            os.write(cipherAlgorithm!!.toByteArray(Charset.forName("UTF-8")))
            os.write(iV!!.size and 0xff)
            os.write(iV)
            os.write(authIntType.code)
            os.write(authIntAlgorithm!!.length and 0xff)
            os.write(authIntAlgorithm!!.toByteArray(Charset.forName("UTF-8")))
            os.write((certificate!!.size shr 8 and 0xff).toByte().toInt())
            os.write((certificate!!.size and 0xff).toByte().toInt())
            os.write(certificate)
            os.write((encryptedSecretKey!!.size shr 8 and 0xff).toByte().toInt())
            os.write((encryptedSecretKey!!.size and 0xff).toByte().toInt())
            os.write(encryptedSecretKey)
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return os.toByteArray()
    }

    companion object {
        private val FORMAT_STRING = byteArrayOf(
            'S'.code.toByte(),
            'L'.code.toByte(),
            'C'.code.toByte(),
            'R'.code.toByte(),
            'Y'.code.toByte(),
            'P'.code.toByte(),
            'T'.code.toByte()
        )
        private const val VERSION = 1
    }
}