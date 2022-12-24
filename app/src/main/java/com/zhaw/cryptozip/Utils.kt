package com.zhaw.cryptozip

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.*

abstract class Utils {
    @Throws(IOException::class)
    fun readUri(context: Context?, uri: Uri?): ByteArray? {
        try{
            val pdf: ParcelFileDescriptor = context?.getContentResolver()?.openFileDescriptor(uri!!, "r")!!
            assert(pdf.statSize <= Int.MAX_VALUE)
            val data = ByteArray(pdf.statSize.toInt())
            val fd: FileDescriptor = pdf.fileDescriptor
            val fileStream = FileInputStream(fd)
            fileStream.read(data)
            return data
        }
        catch (e: Exception){
            e.printStackTrace()
        }
        return null
    }
}