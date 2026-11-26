package com.example

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.example.crypto.E2eeCryptoEngine
import com.example.crypto.EphemeralTestKeyProtector
import com.example.crypto.IdentityKeyManager
import com.example.crypto.QrVerificationCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class CryptoEngineTest {

    private fun isolatedContext(subDir: String): Context {
        val base = ApplicationProvider.getApplicationContext<Context>()
        val dir = File(base.filesDir, subDir).apply {
            deleteRecursively()
            mkdirs()
        }
        return object : android.content.ContextWrapper(base) {
            override fun getFilesDir(): File = dir
        }
    }

    @Test
    fun `hybrid X25519 AES-256-GCM Ed25519 encrypt and decrypt succeeds and rejects tampering`() {
        val aliceMgr = IdentityKeyManager(isolatedContext("alice_ctx"), EphemeralTestKeyProtector())
        val bobMgr = IdentityKeyManager(isolatedContext("bob_ctx"), EphemeralTestKeyProtector())
        val aliceId = aliceMgr.registerIdentity("Alice Phone")
        val bobId = bobMgr.registerIdentity("Bob Phone")

        val aliceCrypto = E2eeCryptoEngine(aliceMgr)
        val bobCrypto = E2eeCryptoEngine(bobMgr)

        val secretMessage = "Meet at Sector 4 off-grid".toByteArray(Charsets.UTF_8)
        val envelope = aliceCrypto.encryptMessage(
            messageId = "msg-1001",
            recipientId = bobId.deviceId,
            recipientX25519PubB64 = bobId.x25519PublicKeyBase64,
            recipientKeyEpoch = bobId.keyEpoch,
            plaintext = secretMessage
        )

        val decrypted = bobCrypto.decryptMessage(
            envelope = envelope,
            senderX25519PubB64 = aliceId.x25519PublicKeyBase64,
            senderEd25519PubB64 = aliceId.ed25519PublicKeyBase64
        )
        assertArrayEquals(secretMessage, decrypted)

        // Tamper signature -> must reject
        val tamperedSig = envelope.copy(
            signatureB64 = Base64.encodeToString(ByteArray(64) { 0x55 }, Base64.NO_WRAP)
        )
        var rejected = false
        try {
            bobCrypto.decryptMessage(tamperedSig, aliceId.x25519PublicKeyBase64, aliceId.ed25519PublicKeyBase64)
        } catch (_: SecurityException) {
            rejected = true
        }
        assertTrue("Tampered Ed25519 signature must be rejected", rejected)

        // Tamper ciphertext -> must reject SHA-256/GCM
        val tamperedCt = envelope.copy(
            payloadCiphertextB64 = Base64.encodeToString(ByteArray(32) { 0x11 }, Base64.NO_WRAP)
        )
        var ctRejected = false
        try {
            bobCrypto.decryptMessage(tamperedCt, aliceId.x25519PublicKeyBase64, aliceId.ed25519PublicKeyBase64)
        } catch (_: SecurityException) {
            ctRejected = true
        }
        assertTrue("Tampered ciphertext must be rejected", ctRejected)
    }

    @Test
    fun `chunked file encryption preserves integrity across 64KB chunks`() {
        val aliceMgr = IdentityKeyManager(isolatedContext("alice_f"), EphemeralTestKeyProtector())
        val bobMgr = IdentityKeyManager(isolatedContext("bob_f"), EphemeralTestKeyProtector())
        val aliceId = aliceMgr.registerIdentity("Alice")
        val bobId = bobMgr.registerIdentity("Bob")

        val aliceCrypto = E2eeCryptoEngine(aliceMgr)
        val bobCrypto = E2eeCryptoEngine(bobMgr)

        val chunk0 = ByteArray(65_536) { (it % 251).toByte() }
        val chunk1 = ByteArray(12_345) { ((it * 7) % 199).toByte() }

        val (fek, wrap) = aliceCrypto.createChunkedFileEncryptionSession(
            transferId = "tx-99",
            recipientId = bobId.deviceId,
            recipientX25519PubB64 = bobId.x25519PublicKeyBase64
        )
        val baseNonce = Base64.decode(wrap.baseNonceB64, Base64.NO_WRAP)
        val enc0 = aliceCrypto.encryptFileChunk(fek, baseNonce, "tx-99", 0, chunk0)
        val enc1 = aliceCrypto.encryptFileChunk(fek, baseNonce, "tx-99", 1, chunk1)

        val bobFek = bobCrypto.unwrapFileEncryptionKey(
            transferId = "tx-99",
            senderId = aliceId.deviceId,
            recipientId = bobId.deviceId,
            senderX25519PubB64 = aliceId.x25519PublicKeyBase64,
            ephemeralX25519PubB64 = wrap.ephemeralX25519PubB64,
            wrappedDekB64 = wrap.wrappedDekB64,
            baseNonceB64 = wrap.baseNonceB64
        )
        assertArrayEquals(chunk0, bobCrypto.decryptFileChunk(bobFek, baseNonce, "tx-99", 0, enc0))
        assertArrayEquals(chunk1, bobCrypto.decryptFileChunk(bobFek, baseNonce, "tx-99", 1, enc1))
    }

    @Test
    fun `signed QR payload verifies and key rotation increments epoch`() {
        val mgr = IdentityKeyManager(isolatedContext("qr_ctx"), EphemeralTestKeyProtector())
        val id = mgr.registerIdentity("Relay Node A")
        val crypto = E2eeCryptoEngine(mgr)
        val qrText = QrVerificationCodec.encodeSignedPayload(id) { crypto.signArbitraryBytes(it) }
        val parsed = QrVerificationCodec.decodeAndVerify(qrText).getOrThrow()
        assertEquals(id.deviceId, parsed.id)
        assertEquals(id.fingerprintHex, parsed.fp)

        val rotated = mgr.rotateAgreementKey()
        assertEquals(id.keyEpoch + 1, rotated.keyEpoch)
        assertNotEquals(id.x25519PublicKeyBase64, rotated.x25519PublicKeyBase64)
    }
}
