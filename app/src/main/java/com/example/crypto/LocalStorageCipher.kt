package com.example.crypto

import android.util.Base64
import com.google.crypto.tink.subtle.AesGcmJce

/**
 * Encrypts sensitive Room database fields (message bodies, wrapped group keys, device notes)
 * at rest using a 256-bit AES-GCM key sealed by Android Keystore.
 * Private keys are NEVER stored in Room at all.
 */
class LocalStorageCipher(
    private val identityKeyManager: IdentityKeyManager
) {
    @Volatile
    private var cachedCipher: AesGcmJce? = null

    private fun cipher(): AesGcmJce {
        cachedCipher?.let { return it }
        synchronized(this) {
            cachedCipher?.let { return it }
            val key = identityKeyManager.getLocalDatabaseKey()
            return AesGcmJce(key).also {
                key.fill(0)
                cachedCipher = it
            }
        }
    }

    fun encryptField(plaintext: String, associatedContext: String): String {
        if (plaintext.isEmpty()) return ""
        val ct = cipher().encrypt(
            plaintext.toByteArray(Charsets.UTF_8),
            associatedContext.toByteArray(Charsets.UTF_8)
        )
        return PREFIX + Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    fun decryptField(storedValue: String, associatedContext: String): String {
        if (storedValue.isEmpty()) return ""
        if (!storedValue.startsWith(PREFIX)) return storedValue
        val raw = Base64.decode(storedValue.removePrefix(PREFIX), Base64.NO_WRAP)
        return runCatching {
            String(cipher().decrypt(raw, associatedContext.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)
        }.getOrElse { "[Unable to decrypt local record]" }
    }

    fun clearCachedKey() {
        cachedCipher = null
    }

    companion object {
        private const val PREFIX = "mc_loc_v1:"
    }
}
