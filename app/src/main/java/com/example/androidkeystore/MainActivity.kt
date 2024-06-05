package com.example.androidkeystore

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyFactory
import java.security.Security
import java.security.Signature
import javax.crypto.Cipher


class MainActivity : AppCompatActivity() {

    private lateinit var tvSupportStrongBox: TextView
    private lateinit var tvSecurityLevel: TextView
    private lateinit var tvPlainText: TextView
    private lateinit var tvSignedText: TextView
    private lateinit var tvVerifiedText: TextView
    private lateinit var tvEncryptedText: TextView
    private lateinit var tvKeyAgreement: TextView

    private lateinit var btnSign: Button
    private lateinit var btnVerify: Button
    private lateinit var btnEcKeyEncrypt: Button
    private lateinit var btnGenKeyAgreement: Button

    companion object {
        const val TAG: String = "MAIN_ACTIVITY"

    }

    @RequiresApi(Build.VERSION_CODES.S)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main_2)

        initUi()

        val androidKeyStoreRepository = AndroidKeyStoreRepository()
        val keypair = androidKeyStoreRepository.generateKeypair()

        tvSupportStrongBox.text =
            "StrongBox Available: ${packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)}"

        val keyFactory = KeyFactory.getInstance(keypair.private.algorithm, "AndroidKeyStore")
        val keyInfo = keyFactory.getKeySpec(
            keypair.private,
            KeyInfo::class.java
        )


        when (keyInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> {
                tvSecurityLevel.text = "SECURITY LEVEL: SOFTWARE"
            }
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> {
                tvSecurityLevel.text = "SECURITY LEVEL: STRONGBOX"
            }
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> {
                tvSecurityLevel.text = "SECURITY LEVEL: TRUSTED_ENVIRONMENT"
            }
            KeyProperties.SECURITY_LEVEL_UNKNOWN -> {
                tvSecurityLevel.text = "SECURITY LEVEL: UNKNOWN"
            }
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> {
                tvSecurityLevel.text = "SECURITY LEVEL: UNKNOWN_SECURE"
            }
        }


        val builder = StringBuilder()
        for (provider in Security.getProviders()) {
            builder.append("provider: ")
                .append(provider.name)
                .append(" ")
                .append(provider.version)
                .append("(")
                .append(provider.info)
                .append(")\n")
        }
        val providers = builder.toString()
        Log.i(TAG, "=== AVAILABLE PROVIDER === \n$providers")


        val plainText = tvPlainText.text.toString()

        btnSign.setOnClickListener {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(keypair.private)
            signature.update(plainText.toByteArray())
            val sign = signature.sign()
            tvSignedText.text = Base64.encodeToString(sign, Base64.DEFAULT)
        }

        btnVerify.setOnClickListener {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(keypair.public)
            signature.update(plainText.toByteArray())
            val valid =
                signature.verify(Base64.decode(tvSignedText.text.toString(), Base64.DEFAULT))
            tvVerifiedText.text = valid.toString()
        }

        btnEcKeyEncrypt.setOnClickListener {
            val cipher = Cipher.getInstance("ECIES")
            cipher.init(Cipher.ENCRYPT_MODE, keypair.private)
            tvEncryptedText.text = Base64.encodeToString(cipher.doFinal(), Base64.DEFAULT)
        }


        btnGenKeyAgreement.setOnClickListener {
            val secretKey = androidKeyStoreRepository.keyAgreement(application)
            tvKeyAgreement.text = Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP)
        }

    }


    private fun initUi() {
        tvSupportStrongBox = findViewById(R.id.tvSupportStrongBox)
        tvSecurityLevel = findViewById(R.id.tvSecurityLevel)
        tvPlainText = findViewById(R.id.tvPlainText)
        tvSignedText = findViewById(R.id.tvSignedText)
        tvVerifiedText = findViewById(R.id.tvVerifiedText)
        tvEncryptedText = findViewById(R.id.tvEncryptedText)
        tvKeyAgreement = findViewById(R.id.tvKeyAgreement)

        btnSign = findViewById(R.id.btnSign)
        btnVerify = findViewById(R.id.btnVerify)
        btnEcKeyEncrypt = findViewById(R.id.btnEcKeyEncrypt)
        btnGenKeyAgreement = findViewById(R.id.btnGenKeyAgreement)
    }

}