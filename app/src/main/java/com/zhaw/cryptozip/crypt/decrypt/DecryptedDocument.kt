package com.zhaw.cryptozip.crypt.decrypt

import com.zhaw.cryptozip.crypt.decrypt.HybridDecryption.AutIntState

/**
 * The DecryptedDocument serves to hold various information about decrypted
 * documents for informational reasons.
 */
class DecryptedDocument {
    var document: ByteArray? = null
    var cipherName: String? = null
    var secretKey: ByteArray? = null
    var iv: ByteArray? = null
    var authIntType = 0.toChar()
    var authIntName: String? = null
    var authIntReceived: ByteArray? = null
    var authIntComp: ByteArray? = null
    var authIntState: AutIntState? = null
}