package com.zhaw.cryptozip.crypt

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.*

/**
 * The Helpers class contains a collection of useful helpers.
 */
object Helpers {
    const val AUTH_TAG_LENGTH = 128
    const val MAC = 'M'
    const val SIGNATURE = 'S'
    const val NONE = 'N'

    /**
     * Returns the hexadecimal representation of the elements in a byte array.
     *
     * @param buf The byte array to convert
     * @return The hexadecimal representation as a String
     */
    fun asHex(buf: ByteArray): String {
        val strbuf = StringBuffer(buf.size * 2)
        var i: Int
        i = 0
        while (i < buf.size) {
            if (buf[i].toInt() and 0xff < 0x10) {
                strbuf.append("0")
            }
            strbuf.append(java.lang.Long.toString((buf[i].toInt() and 0xff).toLong(), 16))
            i++
        }
        return strbuf.toString()
    }

    /**
     * Converts an input stream to a byte array
     *
     * @param input The input stream
     * @return A byte array containing the data
     */
    fun inputStreamToByteArray(input: InputStream): ByteArray? {
        val buffer = ByteArray(8192)
        var bytesRead: Int
        val output = ByteArrayOutputStream()
        try {
            while (input.read(buffer).also { bytesRead = it } != -1) {
                output.write(buffer, 0, bytesRead)
            }
            return output.toByteArray()
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * returns the byte length of MAC algorithm
     *
     * @param mac The mac algorithm
     * @return The number of bytes
     */
    fun getMACSize(macAlgorithm: String): Int {
        return when (macAlgorithm.uppercase(Locale.getDefault())) {
            "HMACMD5" -> 16
            "HMACSHA1" -> 20
            "HMACSHA224" -> 28
            "HMACSHA256", "HMACSHA3-256" -> 32
            "HMACSHA512", "HMACSHA3-512" -> 64
            else -> 0
        }
    }

    /**
     * Checks if the cipher uses the CBC mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    fun isCBC(cipherAlgorithm: String): Boolean {
        return cipherAlgorithm.uppercase(Locale.getDefault()).contains("/CBC")
    }

    /**
     * Checks if the cipher uses the GCM mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    fun isGCM(cipherAlgorithm: String): Boolean {
        return cipherAlgorithm.uppercase(Locale.getDefault()).contains("/GCM")
    }

    /**
     * Checks if the cipher uses the CTR mode
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If CBC is used or not
     */
    fun isCTR(cipherAlgorithm: String): Boolean {
        return cipherAlgorithm.uppercase(Locale.getDefault()).contains("/CTR")
    }

    /**
     * Checks if the cipher is CHACHA20
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If the cipher is CHACHA20 or not
     */
    fun isCHACHA20(cipherAlgorithm: String): Boolean {
        return cipherAlgorithm.uppercase(Locale.getDefault()) == "CHACHA20"
    }

    /**
     * Checks if the cipher uses an IV
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return If an IV is used or not
     */
    public fun hasIV(cipherAlgorithm: String): Boolean {
        return isCBC(cipherAlgorithm) || isGCM(cipherAlgorithm) ||
                isCTR(cipherAlgorithm) || isCHACHA20(cipherAlgorithm)
    }

    /**
     * Returns the raw cipher name
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return The cipher name (e.g. AES)
     */
    fun getCipherName(cipherAlgorithm: String): String {
        return cipherAlgorithm.split("/".toRegex()).toTypedArray()[0]
    }

    /**
     * Returns the IV length in bytes
     *
     * @param cipherAlgorithm The cipher algorithm
     * @return The length of the IV in bytes
     */
    fun getIVLength(cipherAlgorithm: String): Int {
        return if (hasIV(cipherAlgorithm)) {
            if (getCipherName(cipherAlgorithm).uppercase(Locale.getDefault()).contains("DES")) {
                8
            } else if (isCHACHA20(cipherAlgorithm)) {
                12
            } else {
                16
            }
        } else 0
    }
}