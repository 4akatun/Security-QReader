package com.secure.qrreader.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Security: Secure storage using Android Keystore and EncryptedSharedPreferences.
 * All data is encrypted at rest using hardware-backed keystore (if available).
 */
class SecureStorage private constructor(context: Context) {

    private val masterKey: MasterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val sharedPreferences: SharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
    }

    init {
        // Security: Verify keystore integrity on init
        verifyKeystore()
    }

    /**
     * Security: Verify that the keystore is properly configured
     */
    private fun verifyKeystore() {
        try {
            val exists = keyStore.containsAlias(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            if (!exists) {
                // Generate a new key to ensure keystore is working
                generateKey()
            }
        } catch (e: Exception) {
            // Security: Log keystore issues (in production, handle appropriately)
            throw SecurityException("Keystore verification failed", e)
        }
    }

    /**
     * Security: Generate a new key in the keystore
     */
    private fun generateKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )

        val spec = KeyGenParameterSpec.Builder(
            MasterKey.DEFAULT_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // Set true for biometric-protected data
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    /**
     * Security: Store a string value encrypted
     */
    fun putString(key: String, value: String?) {
        if (value == null) {
            remove(key)
            return
        }
        // Security: Additional layer - encode before encryption
        val encoded = value.encodeToByteArray().toBase64()
        sharedPreferences.edit().putString(key, encoded).apply()
    }

    /**
     * Security: Retrieve an encrypted string value
     */
    fun getString(key: String, defaultValue: String? = null): String? {
        val encoded = sharedPreferences.getString(key, null) ?: return defaultValue
        return try {
            encoded.decodeBase64().decodeToString()
        } catch (e: Exception) {
            // Security: Return default on decoding failure
            defaultValue
        }
    }

    /**
     * Security: Store a boolean value encrypted
     */
    fun putBoolean(key: String, value: Boolean) {
        sharedPreferences.edit().putString(key, value.toString()).apply()
    }

    /**
     * Security: Retrieve an encrypted boolean value
     */
    fun getBoolean(key: String, defaultValue: Boolean = false): Boolean {
        return sharedPreferences.getString(key, null)?.toBoolean() ?: defaultValue
    }

    /**
     * Security: Store a long value encrypted
     */
    fun putLong(key: String, value: Long) {
        sharedPreferences.edit().putString(key, value.toString()).apply()
    }

    /**
     * Security: Retrieve an encrypted long value
     */
    fun getLong(key: String, defaultValue: Long = 0L): Long {
        return sharedPreferences.getString(key, null)?.toLongOrNull() ?: defaultValue
    }

    /**
     * Security: Remove a value
     */
    fun remove(key: String) {
        sharedPreferences.edit().remove(key).apply()
    }

    /**
     * Security: Clear all values
     */
    fun clear() {
        sharedPreferences.edit().clear().apply()
    }

    /**
     * Security: Check if a key exists
     */
    fun contains(key: String): Boolean {
        return sharedPreferences.contains(key)
    }

    /**
     * Security: Get all keys (values remain encrypted)
     */
    fun getAllKeys(): Set<String> {
        return sharedPreferences.all.keys
    }

    /**
     * Security: Verify data integrity
     */
    fun verifyDataIntegrity(key: String, expectedValue: String): Boolean {
        return getString(key) == expectedValue
    }

    companion object {
        private const val PREFS_NAME = "secure_prefs"

        @Volatile
        private var instance: SecureStorage? = null

        fun getInstance(context: Context): SecureStorage {
            return instance ?: synchronized(this) {
                instance ?: SecureStorage(context.applicationContext).also {
                    instance = it
                }
            }
        }
    }
}

// Base64 helpers
private fun ByteArray.toBase64(): String = android.util.Base64.encodeToString(this, android.util.Base64.NO_WRAP)
private fun String.decodeBase64(): ByteArray = android.util.Base64.decode(this, android.util.Base64.NO_WRAP)
