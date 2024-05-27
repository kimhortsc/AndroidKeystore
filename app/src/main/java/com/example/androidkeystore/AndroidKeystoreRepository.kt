package com.example.androidkeystore

import android.app.Application
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey

class AndroidKeyStoreRepository {

    val LOCAL_KEY_PAIR = "LOCAL_PRIVATE_KEY"
    val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

    @RequiresApi(Build.VERSION_CODES.S)
    fun generateKeypair() {

        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE_PROVIDER
        )
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            LOCAL_KEY_PAIR,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                    or KeyProperties.PURPOSE_AGREE_KEY
        ).run {
            setKeySize(384)
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setRandomizedEncryptionRequired(true)
            build()
        }

        kpg.initialize(parameterSpec)

        kpg.generateKeyPair()
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun keyAgreement(application: Application): SecretKey {

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)

        val localKeypair = keyStore.getEntry(LOCAL_KEY_PAIR, null) as KeyStore.PrivateKeyEntry

        val keyAgreement: KeyAgreement = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE_PROVIDER)
        keyAgreement.init(localKeypair.privateKey)
        keyAgreement.doPhase(loadRemotePublicKey(application), true)

        return keyAgreement.generateSecret("AES[256]")
    }


    private fun loadRemotePublicKey(application: Application): PublicKey {
        val keystoreResult = loadKeyStoreFromResource(application)
        val cert = keystoreResult.getCertificate("mobileid-server.pki.camdx.io")
        return cert.publicKey
    }

    private fun loadKeyStoreFromResource(application: Application): KeyStore {
        val keystoreFileInputStream =
            application.resources.openRawResource(R.raw.debug_encryption_keystore)

        val pKCS12Keystore = KeyStore.getInstance("PKCS12")

        pKCS12Keystore.load(keystoreFileInputStream, "Passw0rd".toCharArray())

        return pKCS12Keystore
    }
}