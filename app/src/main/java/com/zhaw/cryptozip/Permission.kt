package com.zhaw.cryptozip

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class Permission {

    private val MY_PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE = 123

    private val PERMISSIONS_STORAGE = arrayOf(
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE
    )

    fun checkPermission(context: Context?): Boolean {
        val currentAPIVersion = Build.VERSION.SDK_INT
        if (currentAPIVersion >= Build.VERSION_CODES.M) {
            if (ContextCompat.checkSelfPermission(context!!, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                if (ActivityCompat.shouldShowRequestPermissionRationale(context as Activity, Manifest.permission.WRITE_EXTERNAL_STORAGE)) {
                    val alertBuilder = AlertDialog.Builder(context)
                    alertBuilder.setCancelable(true)
                    alertBuilder.setTitle("Permission necessary as String")
                    alertBuilder.setMessage("External storage permission")
                    alertBuilder.setPositiveButton(android.R.string.yes) { dialog, which -> ActivityCompat.requestPermissions(context, PERMISSIONS_STORAGE, MY_PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE) }//arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    val alert = alertBuilder.create()
                    alert.show()
                } else {
                    ActivityCompat.requestPermissions(context, PERMISSIONS_STORAGE, MY_PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE)
                }
                return false
            } else {
                return true
            }
        } else {
            return true
        }
    }
}