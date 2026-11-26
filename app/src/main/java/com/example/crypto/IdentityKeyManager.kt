package com.example.crypto

import android.content.Context
import android.util.Base64
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.X25519
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

@Serializable
data class DevicePublicIdentity(
    val deviceId: String,
    val displayName: String,
    val x25519PublicKeyBase64: String,
    val ed25519PublicKeyBase64: String,
    val fingerprintHex: String,
    val safetyNumber: String,
    val keyEpoch: Int,
    val createdAtMillis: Long,
    val lastRotatedAtMillis: Long
)

@Serializable
private data class SealedIdentityRecord(
    val deviceId: String,
    val displayName: String,
    val x25519PublicKeyBase64: String,
    val ed25519PublicKeyBase64: String,
    val x25519PrivateKeySealedBase64: String,
    val ed25519PrivateKeySealedBase64: String,
    val localDbKeySealedBase64: String,
    val keyEpoch: Int,
    val createdAtMillis: Long,
    val lastRotatedAtMillis: Long
)

/**
 * Manages the device's cryptographic identity:
 * - X25519 key pair for ECDH key agreement
 * - Ed25519 key pair for digital signatures
 * - Unique Device ID & SHA-256 Public Key Fingerprint
 * - Private keys are NEVER stored in plaintext or in Room; they are sealed via Android Keystore.
 */
class IdentityKeyManager(
    private val context: Context,
    private val keyProtector: KeyProtector = AndroidKeystoreProtector()
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val identityFile: File
        get() = File(context.filesDir, "mesh_identity_sealed_v1.json")

    private val lock = Any()

    fun hasIdentity(): Boolean = synchronized(lock) { identityFile.exists() }

    fun getOrCreateIdentity(defaultName: String = "Mesh Node"): DevicePublicIdentity =
        synchronized(lock) {
            loadSealedRecord()?.toPublicIdentity() ?: createNewIdentity(defaultName)
        }

    fun registerIdentity(displayName: String): DevicePublicIdentity = synchronized(lock) {
        val existing = loadSealedRecord()
        if (existing != null) {
            val updated = existing.copy(displayName = displayName.trim().ifEmpty { existing.displayName })
            saveSealedRecord(updated)
            updated.toPublicIdentity()
        } else {
            createNewIdentity(displayName.trim().ifEmpty { "Mesh Node" })
        }
    }

    fun updateDisplayName(newName: String): DevicePublicIdentity = synchronized(lock) {
        val current = loadSealedRecord() ?: return@synchronized createNewIdentity(newName)
        val updated = current.copy(displayName = newName.trim().ifEmpty { current.displayName })
        saveSealedRecord(updated)
        updated.toPublicIdentity()
    }

    /**
     * Rotates the X25519 key-agreement keypair while preserving the device's root Ed25519 signing
     * identity or rotating epoch cleanly. Increments keyEpoch so peers know to refresh session keys.
     */
    fun rotateAgreementKey(): DevicePublicIdentity = synchronized(lock) {
        val current = loadSealedRecord() ?: return@synchronized createNewIdentity("Mesh Node")
        val newXPriv = X25519.generatePrivateKey()
        val newXPub = X25519.publicFromPrivate(newXPriv)
        val aad = current.deviceId.toByteArray(Charsets.UTF_8)
        val sealedXPriv = keyProtector.seal(newXPriv, aad)
        newXPriv.fill(0)

        val updated = current.copy(
            x25519PublicKeyBase64 = Base64.encodeToString(newXPub, Base64.NO_WRAP),
            x25519PrivateKeySealedBase64 = Base64.encodeToString(sealedXPriv, Base64.NO_WRAP),
            keyEpoch = current.keyEpoch + 1,
            lastRotatedAtMillis = System.currentTimeMillis()
        )
        saveSealedRecord(updated)
        updated.toPublicIdentity()
    }

    fun getPublicIdentityOrNull(): DevicePublicIdentity? = synchronized(lock) {
        loadSealedRecord()?.toPublicIdentity()
    }

    fun isHardwareKeystoreBacked(): Boolean = keyProtector.isHardwareKeystoreActive

    internal fun withX25519PrivateKey(block: (ByteArray) -> Unit) = synchronized(lock) {
        val record = requireNotNull(loadSealedRecord()) { "Device identity not initialized" }
        val aad = record.deviceId.toByteArray(Charsets.UTF_8)
        val priv = keyProtector.unseal(Base64.decode(record.x25519PrivateKeySealedBase64, Base64.NO_WRAP), aad)
        try {
            block(priv)
        } finally {
            priv.fill(0)
        }
    }

    internal fun <T> computeWithX25519PrivateKey(block: (ByteArray) -> T): T = synchronized(lock) {
        val record = requireNotNull(loadSealedRecord()) { "Device identity not initialized" }
        val aad = record.deviceId.toByteArray(Charsets.UTF_8)
        val priv = keyProtector.unseal(Base64.decode(record.x25519PrivateKeySealedBase64, Base64.NO_WRAP), aad)
        try {
            block(priv)
        } finally {
            priv.fill(0)
        }
    }

    internal fun signWithEd25519(data: ByteArray): ByteArray = synchronized(lock) {
        val record = requireNotNull(loadSealedRecord()) { "Device identity not initialized" }
        val aad = record.deviceId.toByteArray(Charsets.UTF_8)
        val priv = keyProtector.unseal(Base64.decode(record.ed25519PrivateKeySealedBase64, Base64.NO_WRAP), aad)
        try {
            Ed25519Sign(priv).sign(data)
        } finally {
            priv.fill(0)
        }
    }

    internal fun getLocalDatabaseKey(): ByteArray = synchronized(lock) {
        val record = loadSealedRecord() ?: run {
            createNewIdentity("Mesh Node")
            requireNotNull(loadSealedRecord())
        }
        val aad = ("db_key:" + record.deviceId).toByteArray(Charsets.UTF_8)
        keyProtector.unseal(Base64.decode(record.localDbKeySealedBase64, Base64.NO_WRAP), aad)
    }

    /**
     * Securely deletes all application-managed keys and Keystore master key.
     */
    fun secureWipeAllKeys() = synchronized(lock) {
        if (identityFile.exists()) {
            val len = identityFile.length().toInt().coerceAtLeast(64)
            runCatching {
                identityFile.writeBytes(ByteArray(len)) // overwrite before unlink
            }
            identityFile.delete()
        }
        keyProtector.deleteMasterKey()
    }

    private fun createNewIdentity(displayName: String): DevicePublicIdentity {
        val deviceId = "mc-" + UUID.randomUUID().toString().replace("-", "").take(16)
        val aad = deviceId.toByteArray(Charsets.UTF_8)

        val xPriv = X25519.generatePrivateKey()
        val xPub = X25519.publicFromPrivate(xPriv)

        val edPair = Ed25519Sign.KeyPair.newKeyPair()
        val edPriv = edPair.privateKey
        val edPub = edPair.publicKey

        val dbKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val sealedXPriv = keyProtector.seal(xPriv, aad)
        val sealedEdPriv = keyProtector.seal(edPriv, aad)
        val sealedDbKey = keyProtector.seal(dbKey, ("db_key:$deviceId").toByteArray(Charsets.UTF_8))

        xPriv.fill(0)
        edPriv.fill(0)
        dbKey.fill(0)

        val now = System.currentTimeMillis()
        val record = SealedIdentityRecord(
            deviceId = deviceId,
            displayName = displayName,
            x25519PublicKeyBase64 = Base64.encodeToString(xPub, Base64.NO_WRAP),
            ed25519PublicKeyBase64 = Base64.encodeToString(edPub, Base64.NO_WRAP),
            x25519PrivateKeySealedBase64 = Base64.encodeToString(sealedXPriv, Base64.NO_WRAP),
            ed25519PrivateKeySealedBase64 = Base64.encodeToString(sealedEdPriv, Base64.NO_WRAP),
            localDbKeySealedBase64 = Base64.encodeToString(sealedDbKey, Base64.NO_WRAP),
            keyEpoch = 1,
            createdAtMillis = now,
            lastRotatedAtMillis = now
        )
        saveSealedRecord(record)
        return record.toPublicIdentity()
    }

    private fun loadSealedRecord(): SealedIdentityRecord? {
        if (!identityFile.exists()) return null
        return runCatching {
            json.decodeFromString<SealedIdentityRecord>(identityFile.readText())
        }.getOrNull()
    }

    private fun saveSealedRecord(record: SealedIdentityRecord) {
        val tmp = File(context.filesDir, "mesh_identity_sealed_v1.tmp")
        tmp.writeText(json.encodeToString(record))
        if (!tmp.renameTo(identityFile)) {
            identityFile.writeText(json.encodeToString(record))
            tmp.delete()
        }
    }

    private fun SealedIdentityRecord.toPublicIdentity(): DevicePublicIdentity {
        val fp = computeFingerprintHex(x25519PublicKeyBase64, ed25519PublicKeyBase64)
        val safety = computeSafetyNumber(fp)
        return DevicePublicIdentity(
            deviceId = deviceId,
            displayName = displayName,
            x25519PublicKeyBase64 = x25519PublicKeyBase64,
            ed25519PublicKeyBase64 = ed25519PublicKeyBase64,
            fingerprintHex = fp,
            safetyNumber = safety,
            keyEpoch = keyEpoch,
            createdAtMillis = createdAtMillis,
            lastRotatedAtMillis = lastRotatedAtMillis
        )
    }

    companion object {
        fun computeFingerprintHex(x25519PubB64: String, ed25519PubB64: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(Base64.decode(x25519PubB64, Base64.NO_WRAP))
            digest.update(Base64.decode(ed25519PubB64, Base64.NO_WRAP))
            return digest.digest().joinToString("") { "%02X".format(it) }
        }

        fun formatFingerprintGrouped(fpHex: String): String =
            fpHex.chunked(4).joinToString(" ")

        fun computeSafetyNumber(fpHex: String): String {
            val bytes = fpHex.chunked(2).map { it.toInt(16) }
            val sb = StringBuilder()
            for (i in 0 until 12) {
                val b0 = bytes[(i * 2) % bytes.size]
                val b1 = bytes[(i * 2 + 1) % bytes.size]
                val val5 = ((b0 shl 8) or b1) % 100000
                if (i > 0) sb.append(if (i % 4 == 0) "\n" else " ")
                sb.append("%05d".format(val5))
            }
            return sb.toString()
        }

        fun computeSharedSafetyNumber(fpHexA: String, fpHexB: String): String {
            val ordered = listOf(fpHexA, fpHexB).sorted()
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(ordered[0].toByteArray(Charsets.UTF_8))
            digest.update(ordered[1].toByteArray(Charsets.UTF_8))
            val combinedHex = digest.digest().joinToString("") { "%02X".format(it) }
            return computeSafetyNumber(combinedHex)
        }
    }
}
