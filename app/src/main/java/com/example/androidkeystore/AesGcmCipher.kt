

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

/**
 * Class that encapsulates KeyStore, AES key and AES-GCM cipher features.
 */
class AesGcmCipher {
    /**
     * Keystore from the application-specific Android provider.
     */
    private var mKeyStore: KeyStore? = null

    init {
        setupKeystore()
        insertKeyIntoKeystore(createAesKey())
    }

    /**
     * Load Android keystore.
     */
    private fun setupKeystore() {
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            mKeyStore?.load(null)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Insert a key into the keystore if there's none yet.
     *
     * @param key key to be inserted
     */
    private fun insertKeyIntoKeystore(key: Key) {
        try {
            if (!mKeyStore!!.containsAlias(ALIAS_KEY)) {
                mKeyStore!!.setKeyEntry(ALIAS_KEY, key, null, null)
            }
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Create an AES key for both encryption and decryption with AES-GCM cipher. The key requires
     * the device to be unlocked for decryption.
     *
     * @return a new AES key
     */
    private fun createAesKey(): Key {
        return try {
            val builder = KeyGenParameterSpec.Builder(
                ALIAS_KEY,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            builder.setKeySize(AES_KEY_SIZE)
            builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            builder.setUnlockedDeviceRequired(true)
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Encrypt a piece of text with AES-GCM cipher.
     *
     *
     * Note that the cipher can encrypt any byte sequence.
     *
     * @param plaintext text to be encrypted
     * @return concatenated nonce and cipher output
     */
    fun doEncrypt(plaintext: ByteArray, secretKey: SecretKey?): ByteArray {
        return try {
            val cipher = Cipher.getInstance(CIPHER_AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, mKeyStore!!.getKey(ALIAS_KEY, null))
            val nonce = cipher.iv
            val ciphertext = ByteArray(12 + cipher.getOutputSize(plaintext.size))
            System.arraycopy(nonce, 0, ciphertext, 0, 12)
            cipher.doFinal(plaintext, 0, plaintext.size, ciphertext, 12)
            ciphertext
        } catch (e: ShortBufferException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException(e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException(e)
        } catch (e: BadPaddingException) {
            throw RuntimeException(e)
        } catch (e: IllegalBlockSizeException) {
            throw RuntimeException(e)
        }
    }

    /**
     * Decrypt a ciphertext with AES-GCM.
     *
     * @param ciphertext concatenated nonce and encryption cipher output
     * @return plaintext
     */
    fun doDecrypt(ciphertext: ByteArray, secretKey: SecretKey?): ByteArray {
        return try {
            val cipher = Cipher.getInstance(CIPHER_AES_GCM)
            val gcmParameterSpec = GCMParameterSpec(AUTHENTICATION_TAG_SIZE, ciphertext, 0, 12)
            cipher.init(Cipher.DECRYPT_MODE, mKeyStore!!.getKey(ALIAS_KEY, null), gcmParameterSpec)
            val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size - 12))
            cipher.doFinal(ciphertext, 12, ciphertext.size - 12, plaintext, 0)
            plaintext
        } catch (e: ShortBufferException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException(e)
        } catch (e: BadPaddingException) {
            throw RuntimeException(e)
        } catch (e: IllegalBlockSizeException) {
            throw RuntimeException(e)
        }
    }

    companion object {
        /**
         * Default nonce size in bytes.
         */
        const val NONCE_SIZE = 12

        /**
         * Chosen AES key size in bits.
         */
        private const val AES_KEY_SIZE = 128

        /**
         * Default authentication tag size in bits.
         */
        private const val AUTHENTICATION_TAG_SIZE = 128

        /**
         * Android KeyStore type.
         */
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"

        /**
         * Alias for the application AES key.
         */
        private const val ALIAS_KEY = "my_key"

        /**
         * AES-GCM cipher.
         */
        private const val CIPHER_AES_GCM = "AES/GCM/NoPadding"
    }
}