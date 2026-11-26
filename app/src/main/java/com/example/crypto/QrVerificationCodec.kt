package com.example.crypto

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Base64
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class QrPeerVerificationPayload(
    val v: Int = 1,
    val id: String,
    val name: String,
    val x25519: String,
    val ed25519: String,
    val fp: String,
    val epoch: Int,
    val ts: Long,
    val sig: String
)

/**
 * Generates and cryptographically verifies offline QR codes for out-of-band device verification.
 */
object QrVerificationCodec {
    private val json = Json { ignoreUnknownKeys = true }

    fun encodeSignedPayload(
        identity: DevicePublicIdentity,
        signFn: (ByteArray) -> String
    ): String {
        val ts = System.currentTimeMillis()
        val body = "${identity.deviceId}|${identity.displayName}|${identity.x25519PublicKeyBase64}|${identity.ed25519PublicKeyBase64}|${identity.fingerprintHex}|${identity.keyEpoch}|$ts"
        val sig = signFn(body.toByteArray(Charsets.UTF_8))
        val payload = QrPeerVerificationPayload(
            v = 1,
            id = identity.deviceId,
            name = identity.displayName,
            x25519 = identity.x25519PublicKeyBase64,
            ed25519 = identity.ed25519PublicKeyBase64,
            fp = identity.fingerprintHex,
            epoch = identity.keyEpoch,
            ts = ts,
            sig = sig
        )
        return "MCQR1:" + json.encodeToString(payload)
    }

    fun decodeAndVerify(rawQrText: String): Result<QrPeerVerificationPayload> = runCatching {
        require(rawQrText.startsWith("MCQR1:")) { "Unsupported QR format" }
        val payload = json.decodeFromString<QrPeerVerificationPayload>(rawQrText.removePrefix("MCQR1:"))
        val expectedFp = IdentityKeyManager.computeFingerprintHex(payload.x25519, payload.ed25519)
        require(expectedFp.equals(payload.fp, ignoreCase = true)) {
            "Fingerprint does not match embedded public keys"
        }
        val body = "${payload.id}|${payload.name}|${payload.x25519}|${payload.ed25519}|${payload.fp}|${payload.epoch}|${payload.ts}"
        val edPub = Base64.decode(payload.ed25519, Base64.NO_WRAP)
        val sigBytes = Base64.decode(payload.sig, Base64.NO_WRAP)
        Ed25519Verify(edPub).verify(sigBytes, body.toByteArray(Charsets.UTF_8))
        payload
    }

    fun renderQrBitmap(content: String, sizePx: Int = 512): Bitmap {
        val bitMatrix: BitMatrix = MultiFormatWriter().encode(
            content,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx
        )
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }
}
