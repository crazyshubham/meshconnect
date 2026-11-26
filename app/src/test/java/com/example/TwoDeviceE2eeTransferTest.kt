package com.example

import android.content.Context
import android.net.Uri
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.crypto.EphemeralTestKeyProtector
import com.example.crypto.IdentityKeyManager
import com.example.data.local.ConnectionState
import com.example.data.local.MeshDatabase
import com.example.data.local.MessageStatus
import com.example.data.local.MessageType
import com.example.data.local.TransferState
import com.example.data.prefs.MeshPreferences
import com.example.data.repository.MeshRepository
import com.example.ml.LightGbmLinkPredictor
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.security.SecureRandom

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class TwoDeviceE2eeTransferTest {

    @Test
    fun `two devices exchange bidirectional HELLO, encrypted messages, and multi-chunk files over local sockets`() = runBlocking {
        val baseContext = ApplicationProvider.getApplicationContext<Context>()
        val dirA = File(baseContext.cacheDir, "nodeA_${System.nanoTime()}").apply { mkdirs() }
        val dirB = File(baseContext.cacheDir, "nodeB_${System.nanoTime()}").apply { mkdirs() }

        val ctxA = object : android.content.ContextWrapper(baseContext) {
            override fun getFilesDir(): File = File(dirA, "files").apply { mkdirs() }
            override fun getCacheDir(): File = File(dirA, "cache").apply { mkdirs() }
        }
        val ctxB = object : android.content.ContextWrapper(baseContext) {
            override fun getFilesDir(): File = File(dirB, "files").apply { mkdirs() }
            override fun getCacheDir(): File = File(dirB, "cache").apply { mkdirs() }
        }

        val dbA = Room.inMemoryDatabaseBuilder(baseContext, MeshDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        val dbB = Room.inMemoryDatabaseBuilder(baseContext, MeshDatabase::class.java)
            .allowMainThreadQueries()
            .build()

        val prefsA = MeshPreferences(ctxA)
        val prefsB = MeshPreferences(ctxB)

        val repoA = MeshRepository(
            context = ctxA,
            db = dbA,
            identityKeyManager = IdentityKeyManager(ctxA, EphemeralTestKeyProtector()),
            preferences = prefsA,
            linkPredictor = LightGbmLinkPredictor(null, null)
        )
        val repoB = MeshRepository(
            context = ctxB,
            db = dbB,
            identityKeyManager = IdentityKeyManager(ctxB, EphemeralTestKeyProtector()),
            preferences = prefsB,
            linkPredictor = LightGbmLinkPredictor(null, null)
        )

        val idA = repoA.registerDevice("SM-T225")
        val idB = repoB.registerDevice("CPH2578")

        // Wait briefly for both ServerSockets to bind
        var portA = 0
        var portB = 0
        repeat(20) {
            if (repoA.lanStatus.value.isListening && repoB.lanStatus.value.isListening) {
                portA = repoA.lanStatus.value.listenPort
                portB = repoB.lanStatus.value.listenPort
                return@repeat
            }
            delay(100)
        }
        assertTrue("Node A socket server should be listening", portA > 0)
        assertTrue("Node B socket server should be listening", portB > 0)

        // Exchange QR verification & connect A -> B
        val qrA = repoA.generateLocalQrPayload()!!
        val qrB = repoB.generateLocalQrPayload()!!
        repoA.verifyScannedQrPayload(qrB).getOrThrow()
        repoB.verifyScannedQrPayload(qrA).getOrThrow()

        val handshakeRes = repoA.connectToManualIpEndpoint("127.0.0.1", portB)
        assertTrue("HELLO handshake should succeed", handshakeRes.isSuccess)

        // Both sides must mark each other CONNECTED after HELLO + HELLO_ACK
        var peerBonA = repoA.allPeersFlow.first().find { it.deviceId == idB.deviceId }
        var peerAonB = repoB.allPeersFlow.first().find { it.deviceId == idA.deviceId }
        repeat(20) {
            if (peerBonA?.connectionState == ConnectionState.CONNECTED &&
                peerAonB?.connectionState == ConnectionState.CONNECTED
            ) return@repeat
            delay(100)
            peerBonA = repoA.allPeersFlow.first().find { it.deviceId == idB.deviceId }
            peerAonB = repoB.allPeersFlow.first().find { it.deviceId == idA.deviceId }
        }
        assertEquals(ConnectionState.CONNECTED, peerBonA?.connectionState)
        assertEquals(ConnectionState.CONNECTED, peerAonB?.connectionState)

        // 1. Send private E2EE text message A -> B
        val convA = repoA.getOrCreatePrivateConversation(idB.deviceId)
        val sendRes = repoA.sendPrivateTextMessage(convA, idB.deviceId, "hi from tablet")
        assertTrue(sendRes.isSuccess)

        val convB = repoB.getOrCreatePrivateConversation(idA.deviceId)
        var msgsOnB = repoB.observeMessages(convB).first()
        repeat(20) {
            if (msgsOnB.any { it.text == "hi from tablet" }) return@repeat
            delay(100)
            msgsOnB = repoB.observeMessages(convB).first()
        }
        assertTrue(msgsOnB.any { it.text == "hi from tablet" && !it.isOutgoing })

        // Verify DELIVERED ACK arrived back at A
        var msgsOnA = repoA.observeMessages(convA).first()
        repeat(20) {
            if (msgsOnA.any { it.text == "hi from tablet" && it.status == MessageStatus.DELIVERED }) return@repeat
            delay(100)
            msgsOnA = repoA.observeMessages(convA).first()
        }
        assertEquals(MessageStatus.DELIVERED, msgsOnA.first { it.text == "hi from tablet" }.status)

        // 2. Send 150 KB encrypted multi-chunk file A -> B
        val sampleBytes = ByteArray(150 * 1024).also { SecureRandom().nextBytes(it) }
        val srcFile = File(dirA, "sample_doc.bin").apply { writeBytes(sampleBytes) }
        val fileRes = repoA.sendFileAttachment(
            conversationId = convA,
            peerDeviceId = idB.deviceId,
            fileUri = Uri.fromFile(srcFile),
            overrideFileName = "sample_doc.bin",
            overrideMimeType = "application/octet-stream"
        )
        assertTrue("File transfer should succeed: ${fileRes.exceptionOrNull()}", fileRes.isSuccess)

        var rxTransfer = repoB.transfersFlow.first().find { it.fileName == "sample_doc.bin" }
        repeat(30) {
            if (rxTransfer?.state == TransferState.COMPLETED) return@repeat
            delay(100)
            rxTransfer = repoB.transfersFlow.first().find { it.fileName == "sample_doc.bin" }
        }
        assertNotNull(rxTransfer)
        assertEquals(TransferState.COMPLETED, rxTransfer?.state)
        val receivedFile = File(rxTransfer!!.localUriOrPath!!)
        assertTrue(receivedFile.exists())
        assertArrayEquals(sampleBytes, receivedFile.readBytes())

        // Verify file appears in B's chat and A gets DELIVERED double-tick
        repeat(20) {
            msgsOnB = repoB.observeMessages(convB).first()
            msgsOnA = repoA.observeMessages(convA).first()
            if (msgsOnB.any { it.attachmentName == "sample_doc.bin" && !it.isOutgoing } &&
                msgsOnA.any { it.attachmentName == "sample_doc.bin" && it.status == MessageStatus.DELIVERED }
            ) return@repeat
            delay(100)
        }
        assertTrue(msgsOnB.any { it.attachmentName == "sample_doc.bin" && !it.isOutgoing && it.messageType == MessageType.DOCUMENT })
        assertEquals(MessageStatus.DELIVERED, msgsOnA.first { it.attachmentName == "sample_doc.bin" }.status)

        // 3. Send Voice Audio & Image A -> B and verify both arrive in B's chat + DELIVERED ticks on A
        val voiceBytes = ByteArray(12 * 1024).also { SecureRandom().nextBytes(it) }
        val voiceFile = File(dirA, "voice_test.m4a").apply { writeBytes(voiceBytes) }
        assertTrue(repoA.sendVoiceMessage(convA, idB.deviceId, voiceFile).isSuccess)

        val imgBytes = ByteArray(24 * 1024).also { SecureRandom().nextBytes(it) }
        val imgFile = File(dirA, "photo_test.jpg").apply { writeBytes(imgBytes) }
        assertTrue(repoA.sendFileAttachment(convA, idB.deviceId, Uri.fromFile(imgFile)).isSuccess)

        repeat(30) {
            msgsOnB = repoB.observeMessages(convB).first()
            msgsOnA = repoA.observeMessages(convA).first()
            val hasVoiceOnB = msgsOnB.any { it.attachmentName == "voice_test.m4a" && !it.isOutgoing }
            val hasImgOnB = msgsOnB.any { it.attachmentName == "photo_test.jpg" && !it.isOutgoing }
            val voiceDeliveredOnA = msgsOnA.any { it.attachmentName == "voice_test.m4a" && it.status == MessageStatus.DELIVERED }
            val imgDeliveredOnA = msgsOnA.any { it.attachmentName == "photo_test.jpg" && it.status == MessageStatus.DELIVERED }
            if (hasVoiceOnB && hasImgOnB && voiceDeliveredOnA && imgDeliveredOnA) return@repeat
            delay(100)
        }
        assertTrue(msgsOnB.any { it.attachmentName == "voice_test.m4a" && it.messageType == MessageType.AUDIO })
        assertTrue(msgsOnB.any { it.attachmentName == "photo_test.jpg" && it.messageType == MessageType.IMAGE })
        assertEquals(MessageStatus.DELIVERED, msgsOnA.first { it.attachmentName == "voice_test.m4a" }.status)
        assertEquals(MessageStatus.DELIVERED, msgsOnA.first { it.attachmentName == "photo_test.jpg" }.status)

        repoA.stopAllDiscovery()
        repoB.stopAllDiscovery()
        repoA.lanTransport.stop()
        repoB.lanTransport.stop()
        dbA.close()
        dbB.close()
    }
}
