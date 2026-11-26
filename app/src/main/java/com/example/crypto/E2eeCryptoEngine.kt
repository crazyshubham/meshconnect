package com.example.crypto

import android.util.Base64
import com.google.crypto.tink.subtle.AesGcmJce
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import kotlinx.serialization.Serializable
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Serializable
data class EncryptedEnvelope(
    val version: Int = 1,
    val messageId: String,
    val senderId: String,
    val recipientId: String,
    val senderKeyEpoch: Int,
    val recipientKeyEpoch: Int,
    val ephemeralX25519PubB64: String,
    val wrappedDekB64: String,
    val payloadCiphertextB64: String,
    val nonceB64: String,
    val payloadSha256Hex: String,
    val timestampMillis: Long,
    val signatureB64: String
)

data class EncryptedStreamHeader(
    val transferId: String,
    val senderId: String,
    val recipientId: String,
    val ephemeralX25519PubB64: String,
    val wrappedDekB64: String,
    val baseNonceB64: String,
    val totalPlaintextBytes: Long,
    val totalChunks: Int,
    val plaintextSha256Hex: String,
    val signatureB64: String
)

/**
 * End-to-End Hybrid Encryption Engine:
 * - Ephemeral + Static X25519 ECDH for forward-secret shared secret agreement
 * - HKDF-SHA256 for domain-separated key derivation
 * - AES-256-GCM for authenticated encryption of messages, wrapped DEKs, and 64KB file chunks
 * - Ed25519 digital signatures over canonical metadata
 */
class E2eeCryptoEngine(
    private val identityKeyManager: IdentityKeyManager
) {
    private val secureRandom = SecureRandom()

    fun encryptMessage(
        messageId: String,
        recipientId: String,
        recipientX25519PubB64: String,
        recipientKeyEpoch: Int,
        plaintext: ByteArray,
        timestampMillis: Long = System.currentTimeMillis()
    ): EncryptedEnvelope {
        val localId = identityKeyManager.getPublicIdentityOrNull()
            ?: error("Local device identity not registered")

        // 1. Generate fresh random 256-bit Data Encryption Key (DEK) and 128-bit replay nonce
        val dek = ByteArray(32).also { secureRandom.nextBytes(it) }
        val replayNonce = ByteArray(16).also { secureRandom.nextBytes(it) }

        // 2. Generate ephemeral X25519 key pair for forward secrecy
        val ephPriv = X25519.generatePrivateKey()
        val ephPub = X25519.publicFromPrivate(ephPriv)

        return try {
            val recipientPub = Base64.decode(recipientX25519PubB64, Base64.NO_WRAP)

            // 3. Derive hybrid shared secret: X25519(static_priv, peer_pub) || X25519(eph_priv, peer_pub)
            val staticShared = identityKeyManager.computeWithX25519PrivateKey { localPriv ->
                X25519.computeSharedSecret(localPriv, recipientPub)
            }
            val ephShared = X25519.computeSharedSecret(ephPriv, recipientPub)
            val ikm = staticShared + ephShared

            // 4. HKDF-SHA256 to derive Key Encryption Key (KEK)
            val info = "MeshConnect-E2EE-v1|${localId.deviceId}|$recipientId|$messageId".toByteArray(Charsets.UTF_8)
            val kek = Hkdf.computeHkdf("HMACSHA256", ikm, replayNonce, info, 32)
            staticShared.fill(0)
            ephShared.fill(0)
            ikm.fill(0)

            // 5. Encrypt plaintext payload with AES-256-GCM using DEK and AAD binding
            val payloadAad = canonicalAad(messageId, localId.deviceId, recipientId, timestampMillis)
            val payloadCiphertext = AesGcmJce(dek).encrypt(plaintext, payloadAad)

            // 6. Wrap DEK with KEK using AES-256-GCM
            val wrappedDek = AesGcmJce(kek).encrypt(dek, payloadAad)
            kek.fill(0)

            val ctHashHex = sha256Hex(payloadCiphertext)
            val ephPubB64 = Base64.encodeToString(ephPub, Base64.NO_WRAP)
            val nonceB64 = Base64.encodeToString(replayNonce, Base64.NO_WRAP)

            // 7. Sign canonical metadata using Ed25519 private key
            val canonicalToSign = canonicalSignBytes(
                messageId = messageId,
                senderId = localId.deviceId,
                recipientId = recipientId,
                timestampMillis = timestampMillis,
                nonceB64 = nonceB64,
                ephPubB64 = ephPubB64,
                payloadHashHex = ctHashHex
            )
            val signature = identityKeyManager.signWithEd25519(canonicalToSign)

            EncryptedEnvelope(
                version = 1,
                messageId = messageId,
                senderId = localId.deviceId,
                recipientId = recipientId,
                senderKeyEpoch = localId.keyEpoch,
                recipientKeyEpoch = recipientKeyEpoch,
                ephemeralX25519PubB64 = ephPubB64,
                wrappedDekB64 = Base64.encodeToString(wrappedDek, Base64.NO_WRAP),
                payloadCiphertextB64 = Base64.encodeToString(payloadCiphertext, Base64.NO_WRAP),
                nonceB64 = nonceB64,
                payloadSha256Hex = ctHashHex,
                timestampMillis = timestampMillis,
                signatureB64 = Base64.encodeToString(signature, Base64.NO_WRAP)
            )
        } finally {
            dek.fill(0)
            ephPriv.fill(0)
        }
    }

    fun decryptMessage(
        envelope: EncryptedEnvelope,
        senderX25519PubB64: String,
        senderEd25519PubB64: String,
        maxClockSkewAndAgeMillis: Long = 7L * 24 * 60 * 60 * 1000
    ): ByteArray {
        val localId = identityKeyManager.getPublicIdentityOrNull()
            ?: error("Local device identity not registered")

        if (envelope.recipientId != localId.deviceId) {
            throw SecurityException("Envelope recipient mismatch")
        }

        val now = System.currentTimeMillis()
        if (now - envelope.timestampMillis > maxClockSkewAndAgeMillis ||
            envelope.timestampMillis - now > 10 * 60 * 1000L
        ) {
            throw SecurityException("Envelope timestamp outside valid session window")
        }

        val payloadCiphertext = Base64.decode(envelope.payloadCiphertextB64, Base64.NO_WRAP)
        val computedHash = sha256Hex(payloadCiphertext)
        if (!MessageDigest.isEqual(
                computedHash.toByteArray(Charsets.UTF_8),
                envelope.payloadSha256Hex.toByteArray(Charsets.UTF_8)
            )
        ) {
            throw SecurityException("Ciphertext SHA-256 integrity mismatch")
        }

        // 1. Verify Ed25519 signature BEFORE touching key agreement or decryption
        val canonicalSigned = canonicalSignBytes(
            messageId = envelope.messageId,
            senderId = envelope.senderId,
            recipientId = envelope.recipientId,
            timestampMillis = envelope.timestampMillis,
            nonceB64 = envelope.nonceB64,
            ephPubB64 = envelope.ephemeralX25519PubB64,
            payloadHashHex = envelope.payloadSha256Hex
        )
        val signature = Base64.decode(envelope.signatureB64, Base64.NO_WRAP)
        val senderEdPub = Base64.decode(senderEd25519PubB64, Base64.NO_WRAP)
        try {
            Ed25519Verify(senderEdPub).verify(signature, canonicalSigned)
        } catch (e: GeneralSecurityException) {
            throw SecurityException("Ed25519 signature verification failed", e)
        }

        // 2. Recompute hybrid shared secret using local X25519 private key
        val senderStaticPub = Base64.decode(senderX25519PubB64, Base64.NO_WRAP)
        val senderEphPub = Base64.decode(envelope.ephemeralX25519PubB64, Base64.NO_WRAP)
        val replayNonce = Base64.decode(envelope.nonceB64, Base64.NO_WRAP)

        val ikm = identityKeyManager.computeWithX25519PrivateKey { localPriv ->
            val staticShared = X25519.computeSharedSecret(localPriv, senderStaticPub)
            val ephShared = X25519.computeSharedSecret(localPriv, senderEphPub)
            staticShared + ephShared
        }

        val info = "MeshConnect-E2EE-v1|${envelope.senderId}|${envelope.recipientId}|${envelope.messageId}"
            .toByteArray(Charsets.UTF_8)
        val kek = Hkdf.computeHkdf("HMACSHA256", ikm, replayNonce, info, 32)
        ikm.fill(0)

        val payloadAad = canonicalAad(
            envelope.messageId,
            envelope.senderId,
            envelope.recipientId,
            envelope.timestampMillis
        )
        val wrappedDek = Base64.decode(envelope.wrappedDekB64, Base64.NO_WRAP)
        val dek = try {
            AesGcmJce(kek).decrypt(wrappedDek, payloadAad)
        } finally {
            kek.fill(0)
        }

        return try {
            AesGcmJce(dek).decrypt(payloadCiphertext, payloadAad)
        } finally {
            dek.fill(0)
        }
    }

    /**
     * Wraps a symmetric group key (32 bytes) for a specific authorized group member.
     */
    fun wrapSymmetricKeyForRecipient(
        groupId: String,
        epoch: Int,
        symmetricKey: ByteArray,
        recipientId: String,
        recipientX25519PubB64: String
    ): EncryptedEnvelope = encryptMessage(
        messageId = "grpkey:$groupId:$epoch:$recipientId",
        recipientId = recipientId,
        recipientX25519PubB64 = recipientX25519PubB64,
        recipientKeyEpoch = epoch,
        plaintext = symmetricKey
    )

    fun encryptWithSymmetricKey(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray
    ): ByteArray = AesGcmJce(key).encrypt(plaintext, aad)

    fun decryptWithSymmetricKey(
        key: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray
    ): ByteArray = AesGcmJce(key).decrypt(ciphertext, aad)

    /**
     * Generates a fresh 256-bit File Encryption Key (FEK) and base 96-bit nonce for streaming
     * chunk-based AES-256-GCM encryption without loading large videos into memory.
     */
    fun createChunkedFileEncryptionSession(
        transferId: String,
        recipientId: String,
        recipientX25519PubB64: String
    ): Pair<ByteArray, FileWrapArtifact> {
        val localId = identityKeyManager.getPublicIdentityOrNull()
            ?: error("Local device identity not registered")
        val fek = ByteArray(32).also { secureRandom.nextBytes(it) }
        val baseNonce = ByteArray(12).also { secureRandom.nextBytes(it) }
        val ephPriv = X25519.generatePrivateKey()
        val ephPub = X25519.publicFromPrivate(ephPriv)

        return try {
            val recipientPub = Base64.decode(recipientX25519PubB64, Base64.NO_WRAP)
            val ikm = identityKeyManager.computeWithX25519PrivateKey { localPriv ->
                X25519.computeSharedSecret(localPriv, recipientPub) +
                    X25519.computeSharedSecret(ephPriv, recipientPub)
            }
            val info = "MeshConnect-File-v1|${localId.deviceId}|$recipientId|$transferId".toByteArray(Charsets.UTF_8)
            val kek = Hkdf.computeHkdf("HMACSHA256", ikm, baseNonce, info, 32)
            ikm.fill(0)
            val aad = "$transferId|${localId.deviceId}|$recipientId".toByteArray(Charsets.UTF_8)
            val wrappedFek = AesGcmJce(kek).encrypt(fek, aad)
            kek.fill(0)

            fek to FileWrapArtifact(
                senderId = localId.deviceId,
                ephemeralX25519PubB64 = Base64.encodeToString(ephPub, Base64.NO_WRAP),
                wrappedDekB64 = Base64.encodeToString(wrappedFek, Base64.NO_WRAP),
                baseNonceB64 = Base64.encodeToString(baseNonce, Base64.NO_WRAP)
            )
        } finally {
            ephPriv.fill(0)
        }
    }

    fun unwrapFileEncryptionKey(
        transferId: String,
        senderId: String,
        recipientId: String,
        senderX25519PubB64: String,
        ephemeralX25519PubB64: String,
        wrappedDekB64: String,
        baseNonceB64: String
    ): ByteArray {
        val senderStatic = Base64.decode(senderX25519PubB64, Base64.NO_WRAP)
        val senderEph = Base64.decode(ephemeralX25519PubB64, Base64.NO_WRAP)
        val baseNonce = Base64.decode(baseNonceB64, Base64.NO_WRAP)
        val ikm = identityKeyManager.computeWithX25519PrivateKey { localPriv ->
            X25519.computeSharedSecret(localPriv, senderStatic) +
                X25519.computeSharedSecret(localPriv, senderEph)
        }
        val info = "MeshConnect-File-v1|$senderId|$recipientId|$transferId".toByteArray(Charsets.UTF_8)
        val kek = Hkdf.computeHkdf("HMACSHA256", ikm, baseNonce, info, 32)
        ikm.fill(0)
        val aad = "$transferId|$senderId|$recipientId".toByteArray(Charsets.UTF_8)
        return try {
            AesGcmJce(kek).decrypt(Base64.decode(wrappedDekB64, Base64.NO_WRAP), aad)
        } finally {
            kek.fill(0)
        }
    }

    fun encryptFileChunk(
        fek: ByteArray,
        baseNonce: ByteArray,
        transferId: String,
        chunkIndex: Int,
        plainChunk: ByteArray
    ): ByteArray {
        val chunkNonce = deriveChunkNonce(baseNonce, chunkIndex)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(fek, "AES"), GCMParameterSpec(128, chunkNonce))
        cipher.updateAAD("$transferId:$chunkIndex".toByteArray(Charsets.UTF_8))
        return cipher.doFinal(plainChunk)
    }

    fun decryptFileChunk(
        fek: ByteArray,
        baseNonce: ByteArray,
        transferId: String,
        chunkIndex: Int,
        encryptedChunk: ByteArray
    ): ByteArray {
        val chunkNonce = deriveChunkNonce(baseNonce, chunkIndex)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(fek, "AES"), GCMParameterSpec(128, chunkNonce))
        cipher.updateAAD("$transferId:$chunkIndex".toByteArray(Charsets.UTF_8))
        return cipher.doFinal(encryptedChunk)
    }

    fun signFileManifest(
        transferId: String,
        senderId: String,
        recipientId: String,
        fileName: String,
        fileSize: Long,
        sha256Hex: String
    ): String {
        val payload = "FILE|$transferId|$senderId|$recipientId|$fileName|$fileSize|$sha256Hex"
            .toByteArray(Charsets.UTF_8)
        return Base64.encodeToString(identityKeyManager.signWithEd25519(payload), Base64.NO_WRAP)
    }

    fun verifyFileManifestSignature(
        senderEd25519PubB64: String,
        signatureB64: String,
        transferId: String,
        senderId: String,
        recipientId: String,
        fileName: String,
        fileSize: Long,
        sha256Hex: String
    ): Boolean {
        val payload = "FILE|$transferId|$senderId|$recipientId|$fileName|$fileSize|$sha256Hex"
            .toByteArray(Charsets.UTF_8)
        return runCatching {
            Ed25519Verify(Base64.decode(senderEd25519PubB64, Base64.NO_WRAP))
                .verify(Base64.decode(signatureB64, Base64.NO_WRAP), payload)
            true
        }.getOrDefault(false)
    }

    fun signArbitraryBytes(data: ByteArray): String =
        Base64.encodeToString(identityKeyManager.signWithEd25519(data), Base64.NO_WRAP)

    fun verifyArbitrarySignature(ed25519PubB64: String, data: ByteArray, signatureB64: String): Boolean =
        runCatching {
            Ed25519Verify(Base64.decode(ed25519PubB64, Base64.NO_WRAP))
                .verify(Base64.decode(signatureB64, Base64.NO_WRAP), data)
            true
        }.getOrDefault(false)

    fun streamSha256(inputStream: InputStream): Pair<Long, String> {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_CHUNK_SIZE)
        var total = 0L
        while (true) {
            val read = inputStream.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
            total += read
        }
        val hex = digest.digest().joinToString("") { "%02x".format(it) }
        return total to hex
    }

    fun encryptStreamChunked(
        input: InputStream,
        encryptedOutput: OutputStream,
        fek: ByteArray,
        baseNonce: ByteArray,
        transferId: String,
        onChunkProgress: (chunkIndex: Int, bytesRead: Long) -> Unit = { _, _ -> }
    ): Pair<Long, String> {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_CHUNK_SIZE)
        var chunkIdx = 0
        var totalPlain = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            val slice = if (read == buffer.size) buffer else buffer.copyOf(read)
            digest.update(slice)
            val encrypted = encryptFileChunk(fek, baseNonce, transferId, chunkIdx, slice)
            val lenBytes = ByteBuffer.allocate(4).putInt(encrypted.size).array()
            encryptedOutput.write(lenBytes)
            encryptedOutput.write(encrypted)
            totalPlain += read
            onChunkProgress(chunkIdx, totalPlain)
            chunkIdx++
        }
        val hex = digest.digest().joinToString("") { "%02x".format(it) }
        return totalPlain to hex
    }

    private fun deriveChunkNonce(baseNonce: ByteArray, chunkIndex: Int): ByteArray {
        val out = baseNonce.copyOf(12)
        val idxBytes = ByteBuffer.allocate(4).putInt(chunkIndex).array()
        for (i in 0 until 4) {
            out[8 + i] = (out[8 + i].toInt() xor idxBytes[i].toInt()).toByte()
        }
        return out
    }

    private fun canonicalAad(
        messageId: String,
        senderId: String,
        recipientId: String,
        timestampMillis: Long
    ): ByteArray = "$messageId|$senderId|$recipientId|$timestampMillis".toByteArray(Charsets.UTF_8)

    private fun canonicalSignBytes(
        messageId: String,
        senderId: String,
        recipientId: String,
        timestampMillis: Long,
        nonceB64: String,
        ephPubB64: String,
        payloadHashHex: String
    ): ByteArray =
        "MC1|$messageId|$senderId|$recipientId|$timestampMillis|$nonceB64|$ephPubB64|$payloadHashHex"
            .toByteArray(Charsets.UTF_8)

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    data class FileWrapArtifact(
        val senderId: String,
        val ephemeralX25519PubB64: String,
        val wrappedDekB64: String,
        val baseNonceB64: String
    )

    companion object {
        const val DEFAULT_CHUNK_SIZE = 64 * 1024 // 64 KB chunks for memory-safe video transfers
    }
}
