package com.zhaw.cryptozip

import android.util.Log
import java.io.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object UtilsZip : Utils(){
    private const val BUFFER_SIZE = 8192 //2048;
    private val TAG = UtilsZip::class.java.name.toString()
    private var parentPath = ""
    fun zip(
        sourcePath: String,
        destinationPath: String,
        destinationFileName: String,
        includeParentFolder: Boolean
    ): Boolean {
        var destinationPath = destinationPath
        File(destinationPath).mkdirs()
        val fileOutputStream: FileOutputStream
        var zipOutputStream: ZipOutputStream? = null
        try {
            if (!destinationPath.endsWith("/")) destinationPath += "/"
            val destination = destinationPath + destinationFileName
            val file = File(destination)
            if (!file.exists()) file.createNewFile()
            fileOutputStream = FileOutputStream(file)
            zipOutputStream = ZipOutputStream(BufferedOutputStream(fileOutputStream))
            if (includeParentFolder) parentPath = File(sourcePath).parent + "/" else parentPath =
                sourcePath
            zipFile(zipOutputStream, sourcePath)
        } catch (ioe: IOException) {
            Log.d(TAG, ioe.message!!)
            return false
        } finally {
            if (zipOutputStream != null) try {
                zipOutputStream.close()
            } catch (e: IOException) {
            }
        }
        return true
    }

    @Throws(IOException::class)
    private fun zipFile(zipOutputStream: ZipOutputStream, sourcePath: String) {
        val files = File(sourcePath)
        val fileList = files.listFiles()
        var input: BufferedInputStream
        if(fileList != null){
            for (file in fileList) {
                if (file.isDirectory) {
                    zipFile(zipOutputStream, file.path)
                } else {
                    writeZipFile(file, zipOutputStream)
                }
            }
        }
        else{
            writeZipFile(files, zipOutputStream)
        }

    }

    private fun writeZipFile(file: File, zipOutputStream: ZipOutputStream){
        val data = ByteArray(BUFFER_SIZE)
        val fileInputStream = FileInputStream(file.path)
        var input = BufferedInputStream(fileInputStream, BUFFER_SIZE)
        var entryPath = file.absolutePath.replace(parentPath, "")
        val entry = ZipEntry(entryPath)
        zipOutputStream.putNextEntry(entry)
        var count: Int
        while (input.read(data, 0, BUFFER_SIZE).also {
                count = it
            } != -1) {
            zipOutputStream.write(data, 0, count)
        }
        input.close()
    }

    fun unzip(sourceFile: String?, destinationFolder: String?): Boolean {
        var zis: ZipInputStream? = null
        try {
            zis = ZipInputStream(BufferedInputStream(FileInputStream(sourceFile)))
            var ze: ZipEntry
            var count: Int
            val buffer = ByteArray(BUFFER_SIZE)
            var entry : ZipEntry? = zis.nextEntry
            while (entry != null) {
                var fileName = entry.name
                fileName = fileName.substring(fileName.indexOf("/") + 1)
                val file = File(destinationFolder, fileName)
                val dir = if (entry.isDirectory) file else file.parentFile
                if (!dir.isDirectory && !dir.mkdirs()) throw FileNotFoundException("Invalid path: " + dir.absolutePath)
                if (entry.isDirectory) continue
                val fout = FileOutputStream(file)
                try {
                    while (zis.read(buffer).also { count = it } != -1) fout.write(buffer, 0, count)
                } finally {
                    fout.close()
                }
                entry = zis.nextEntry
            }
        } catch (ioe: IOException) {
            Log.d(TAG, ioe.message!!)
            return false
        } finally {
            if (zis != null) try {
                zis.close()
            } catch (e: IOException) {
            }
        }
        return true
    }
}