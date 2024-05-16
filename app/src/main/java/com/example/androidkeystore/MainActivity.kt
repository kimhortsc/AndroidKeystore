package com.example.androidkeystore

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import java.security.*

class MainActivity : AppCompatActivity() {

    private lateinit var tvPlaintext: TextView
    private lateinit var btnGenKeyAgreement: Button

    @RequiresApi(Build.VERSION_CODES.S)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main_2)

        initUi()

        val androidKeyStoreRepository = AndroidKeyStoreRepository()

        btnGenKeyAgreement.setOnClickListener {
            androidKeyStoreRepository.generateKeypair()
            val secretKey = androidKeyStoreRepository.keyAgreement(application)
            tvPlaintext.text = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        }
    }


    private fun initUi() {
        tvPlaintext = findViewById(R.id.tvPlainText)
        btnGenKeyAgreement = findViewById(R.id.btnGenKeyAgreement)

    }

}