package com.zhaw.cryptozip.crypt

/**
 * An InvalidFormatException is thrown whenever a format-related error occurs
 * during the en- or decryption process.
 *
 */
class InvalidFormatException
/**
 * Constructor. Creates an InvalidFormatException.
 *
 * @param reason The reason
 */
    (reason: String?) : Exception(reason) {
    companion object {
        private const val serialVersionUID = 5406225243905297855L
    }
}
