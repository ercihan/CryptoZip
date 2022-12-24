package com.zhaw.cryptozip

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.DocumentsContract
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.zhaw.cryptozip.crypt.encrypt.UtilsEncrypt
import com.zhaw.cryptozip.crypt.decrypt.UtilsDecrypt
import com.zhaw.cryptozip.databinding.FragmentFirstBinding


/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 */
class FirstFragment : Fragment() {
    // Initialize variable
    var uri: Uri? = null
    var outputUri : Uri? = null
    val PICK_PDF_FILE = 2
    val CREATE_FILE = 1
    var contentResolver = getContext()?.getContentResolver()
    var utilsZip: UtilsZip = UtilsZip
    var utilsEncrypt: UtilsEncrypt = UtilsEncrypt()
    var utilsDecrypt: UtilsDecrypt = UtilsDecrypt()
    var absolutPathToDownload : String = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString()

    private var _binding: FragmentFirstBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {

        _binding = FragmentFirstBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.filePicker.setOnClickListener {
            //findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
            openFile(null)
        }

        Permission().checkPermission(context)

        this.contentResolver = context?.contentResolver;

        binding.compress.setOnClickListener {
            var fileData = utilsZip.readUri(context, uri)
            createFile(null, "zippedFile.png.zip")
        }

        binding.uncompress.setOnClickListener {
            var fileData = utilsZip.readUri(context, uri)
            utilsZip.unzip(absolutPathToDownload + "/zippedFile.png.zip", absolutPathToDownload + "/zippedFile.png")
        }

        binding.encrypt.setOnClickListener {
            val encryptCertInputStream = requireContext().resources.openRawResource(R.raw.encrypt_cert)
            val signKeyInputStream = requireContext().resources.openRawResource(R.raw.sign_key)
            val signCertInputStream = requireContext().resources.openRawResource(R.raw.sign_cert)
            utilsEncrypt.encryptFile(absolutPathToDownload + "/test_file.txt", absolutPathToDownload + "/test_file_enc.txt", encryptCertInputStream, "AES/GCM/NoPadding", 256, 'N', "", "", signKeyInputStream,signCertInputStream)
        }

        binding.decrypt.setOnClickListener {
            val encryptKeyInputStream = requireContext().resources.openRawResource(R.raw.encrypt_key)
            utilsDecrypt.sLDecrypt(absolutPathToDownload + "/test_file_enc.txt", absolutPathToDownload + "/test_file_dec.txt", encryptKeyInputStream, "supersecret")
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun createFile(pickerInitialUri: Uri?, zipName: String) {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, zipName)

            // Optionally, specify a URI for the directory that should be opened in
            // the system file picker before your app creates the document.
            putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri)
        }
        startActivityForResult(intent, CREATE_FILE)
    }

    fun openFile(pickerInitialUri: Uri?) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"

            // Optionally, specify a URI for the file that should appear in the
            // system file picker when it loads.
            putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri)
        }

        startActivityForResult(intent, PICK_PDF_FILE)
    }

    override fun onActivityResult(
        requestCode: Int, resultCode: Int, resultData: Intent?) {
        if (requestCode == PICK_PDF_FILE
            && resultCode == Activity.RESULT_OK) {
            // The result data contains a URI for the document or directory that
            // the user selected.
            resultData?.data?.also { uri ->
                // Perform operations on the document using its URI.
                this.uri = uri
                binding.textviewFirst.text = uri.toString()
            }
        }
        else if (requestCode == CREATE_FILE
            && resultCode == Activity.RESULT_OK) {
            // The result data contains a URI for the document or directory that
            // the user selected.
            resultData?.data?.also { uri ->
                // Perform operations on the document using its URI.
                this.outputUri = uri //ToDo: Strange wrong URL... How to get right one?
                //Vollstaendiger Pfad
                var abslutPathTilDownloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString()

                utilsZip.zip(abslutPathTilDownloads + "/wallpaperTest.png",abslutPathTilDownloads ,"/zippedFile.png.zip" ,false)
            }
        }
    }
}