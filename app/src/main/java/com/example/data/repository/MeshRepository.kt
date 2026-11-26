package com.example.data.repository

import android.content.Context
import android.net.Uri
import android.os.StatFs
import android.provider.OpenableColumns
import android.util.Base64
import com.example.crypto.DevicePublicIdentity
import com.example.crypto.E2eeCryptoEngine
import com.example.crypto.IdentityKeyManager
import com.example.crypto.LocalStorageCipher
import com.example.crypto.QrPeerVerificationPayload
import com.example.crypto.QrVerificationCodec
import com.example.data.local.ConnectionState
import com.example.data.local.ConversationDao
import com.example.data.local.ConversationEntity
import com.example.data.local.ConversationType
import com.example.data.local.GroupDao
import com.example.data.local.GroupEntity
import com.example.data.local.GroupMemberEntity
import com.example.data.local.MeshDatabase
import com.example.data.local.MessageDao
import com.example.data.local.MessageEntity
import com.example.data.local.MessageRecipientStatusEntity
import com.example.data.local.MessageStatus
import com.example.data.local.MessageType
import com.example.data.local.PeerDeviceDao
import com.example.data.local.PeerDeviceEntity
import com.example.data.local.PendingRelayDao
import com.example.data.local.PendingRelayPacketEntity
import com.example.data.local.SeenNonceDao
import com.example.data.local.SeenNonceEntity
import com.example.data.local.TransferRecordDao
import com.example.data.local.TransferRecordEntity
import com.example.data.local.TransferState
import com.example.data.local.TransportType
import com.example.data.local.TrustStatus
import com.example.data.prefs.MeshPreferences
import com.example.data.prefs.SecurityAndAppSettings
import com.example.data.prefs.ThemeMode
import com.example.ml.LightGbmLinkPredictor
import com.example.ml.LinkPredictionResult
import com.example.ml.WirelessLinkMetrics
import com.example.network.ApkShareStatus
import com.example.network.HardwareCapabilityReport
import com.example.network.LanTransportStatus
import com.example.network.LocalApkShareServer
import com.example.network.LocalWifiLanTransport
import com.example.network.MeshForegroundService
import com.example.network.MeshRouteEntry
import com.example.network.MeshRouter
import com.example.network.RelayDecision
import com.example.network.RouteAdvertisementEntry
import com.example.network.TransportCapabilities
import com.example.network.WifiAwareStatus
import com.example.network.WifiAwareTransport
import com.example.network.WifiDirectStatus
import com.example.network.WifiDirectTransport
import com.example.network.WireFrame
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class DecryptedMessageItem(
    val messageId: String,
    val conversationId: String,
    val senderId: String,
    val senderName: String,
    val replyToMessageId: String?,
    val replyToPreview: String?,
    val forwardedFrom: String?,
    val messageType: String,
    val text: String,
    val attachmentPath: String?,
    val attachmentName: String?,
    val attachmentMimeType: String?,
    val attachmentSize: Long,
    val attachmentSha256: String?,
    val status: String,
    val hopCount: Int,
    val timestampMillis: Long,
    val isOutgoing: Boolean
)

data class ConversationListItem(
    val conversationId: String,
    val type: String,
    val title: String,
    val peerDeviceId: String?,
    val groupId: String?,
    val lastMessagePreview: String,
    val lastMessageTimestamp: Long,
    val unreadCount: Int
)

@Serializable
data class FileCryptoMetadata(
    val ephemeralX25519PubB64: String,
    val wrappedDekB64: String,
    val baseNonceB64: String,
    val senderX25519PubB64: String,
    val senderEd25519PubB64: String,
    val manifestSigB64: String
)

class MeshRepository(
    private val context: Context,
    private val db: MeshDatabase,
    val identityKeyManager: IdentityKeyManager,
    val preferences: MeshPreferences,
    val linkPredictor: LightGbmLinkPredictor
) {
    private val scopeExceptionHandler = CoroutineExceptionHandler { _, _ ->
        // Background transport failures stay silent to avoid intrusive UI popups
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + scopeExceptionHandler)
    private val json = Json { ignoreUnknownKeys = true }
    private val storageCipher = LocalStorageCipher(identityKeyManager)
    val cryptoEngine = E2eeCryptoEngine(identityKeyManager)

    private val peerDao: PeerDeviceDao = db.peerDeviceDao()
    private val conversationDao: ConversationDao = db.conversationDao()
    private val messageDao: MessageDao = db.messageDao()
    private val groupDao: GroupDao = db.groupDao()
    private val transferDao: TransferRecordDao = db.transferRecordDao()
    private val pendingRelayDao: PendingRelayDao = db.pendingRelayDao()
    private val seenNonceDao: SeenNonceDao = db.seenNonceDao()

    val meshRouter = MeshRouter(pendingRelayDao, linkPredictor)

    private val pausedTransfers = ConcurrentHashMap<String, Boolean>()
    private val incomingFileChunks = ConcurrentHashMap<String, MutableMap<Int, ByteArray>>()
    private val completedFileTransfers = ConcurrentHashMap<String, Boolean>()
    private val fileAssemblyLocks = ConcurrentHashMap<String, Mutex>()
    private val chatIngressMutex = Mutex()
    private val lastEndpointHelloMillis = ConcurrentHashMap<String, Long>()
    private val lastWifiDirectAutoConnectMillis = ConcurrentHashMap<String, Long>()
    private val directFailCounts = ConcurrentHashMap<String, Int>()
    private val transferHopCounts = ConcurrentHashMap<String, Int>()

    private val _localIdentity = MutableStateFlow(identityKeyManager.getPublicIdentityOrNull())
    val localIdentity: StateFlow<DevicePublicIdentity?> = _localIdentity.asStateFlow()

    private val _hardwareCapabilities = MutableStateFlow(TransportCapabilities.inspect(context))
    val hardwareCapabilities: StateFlow<HardwareCapabilityReport> = _hardwareCapabilities.asStateFlow()

    private val _securityEvents = MutableSharedFlow<String>(extraBufferCapacity = 32)
    val securityEvents: SharedFlow<String> = _securityEvents.asSharedFlow()

    private val _relayedPacketCount = MutableStateFlow(0)
    val relayedPacketCount: StateFlow<Int> = _relayedPacketCount.asStateFlow()

    private var listenersStarted = false
    private var meshHeartbeatJob: Job? = null
    private val pendingAutoPairP2pAddresses: MutableSet<String> = ConcurrentHashMap.newKeySet()

    val wifiDirectTransport: WifiDirectTransport = WifiDirectTransport(
        context = context,
        onGroupConnected = { goIp, isGo ->
            scope.launch {
                val id = _localIdentity.value ?: return@launch
                lanTransport.startServerAndNsd(id.deviceId, id.displayName)
                lanTransport.startDiscovery()
                lanTransport.broadcastUdpBeacon(id.deviceId, id.displayName)
                if (!isGo) {
                    sendHelloToEndpointWithRetry(goIp, LocalWifiLanTransport.DEFAULT_PORT, TransportType.WIFI_DIRECT)
                } else {
                    flushOfflineQueueAndCleanup()
                }
            }
        },
        onGroupDisconnected = {
            // Silent state transition on Wi-Fi Direct group teardown
        },
        onServiceDiscovered = { svc ->
            scope.launch {
                val meshId = svc.meshDeviceId?.takeIf { it.isNotBlank() } ?: return@launch
                if (meshId == _localIdentity.value?.deviceId) return@launch
                val displayName = svc.meshDisplayName?.takeIf { it.isNotBlank() } ?: svc.deviceName
                val existing = peerDao.getPeerById(meshId)
                if (existing == null) {
                    val metrics = WirelessLinkMetrics(-60, 0.94f, 32, 0.02f, 8000)
                    val pred = linkPredictor.predict(metrics)
                    peerDao.upsertPeer(
                        PeerDeviceEntity(
                            deviceId = meshId,
                            displayName = displayName,
                            trustStatus = TrustStatus.DISCOVERED,
                            connectionState = ConnectionState.OFFLINE,
                            transportType = TransportType.WIFI_DIRECT,
                            wifiP2pAddress = svc.deviceAddress,
                            rssiDbm = metrics.rssiDbm,
                            packetDeliveryRatio = metrics.packetDeliveryRatio,
                            latencyMs = metrics.latencyMs,
                            packetLossRate = metrics.packetLossRate,
                            throughputKbps = metrics.throughputKbps,
                            predictedLinkScore = pred.score,
                            lastSeenMillis = svc.lastSeenMillis
                        )
                    )
                } else {
                    if (existing.trustStatus == TrustStatus.BLOCKED) return@launch
                    peerDao.upsertPeer(
                        existing.copy(
                            displayName = displayName,
                            transportType = TransportType.WIFI_DIRECT,
                            wifiP2pAddress = svc.deviceAddress,
                            lastSeenMillis = svc.lastSeenMillis
                        )
                    )
                    // Auto-reconnect previously paired peer when back in Wi-Fi Direct range
                    val isPaired = existing.trustStatus == TrustStatus.PAIRED_UNVERIFIED ||
                        existing.trustStatus == TrustStatus.VERIFIED_QR
                    if (isPaired &&
                        existing.connectionState != ConnectionState.CONNECTED &&
                        !wifiDirectStatus.value.isGroupFormed
                    ) {
                        val now = System.currentTimeMillis()
                        val lastAttempt = lastWifiDirectAutoConnectMillis[svc.deviceAddress] ?: 0L
                        if (now - lastAttempt > 20_000L) {
                            lastWifiDirectAutoConnectMillis[svc.deviceAddress] = now
                            connectWifiDirectPeer(svc.deviceAddress)
                        }
                    }
                }
            }
        }
    )

    val lanTransport = LocalWifiLanTransport(
        context = context,
        scope = scope,
        onEndpointDiscovered = { _, host, port ->
            val key = "$host:$port"
            val now = System.currentTimeMillis()
            val last = lastEndpointHelloMillis[key] ?: 0L
            if (now - last >= 4_000L) {
                lastEndpointHelloMillis[key] = now
                scope.launch {
                    sendHelloToEndpoint(host, port, TransportType.LOCAL_LAN)
                }
            }
        },
        onFrameReceived = { rawJson, remoteIp ->
            handleIncomingRawFrame(rawJson, remoteIp, TransportType.LOCAL_LAN)
        }
    )

    val apkShareServer = LocalApkShareServer(context, scope)

    val wifiAwareTransport = WifiAwareTransport(
        context = context,
        onAwarePeerFound = { tag, infoText ->
            scope.launch {
                val parts = infoText.split("|")
                val id = parts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: "nan-$tag"
                val name = parts.getOrNull(1)?.takeIf { it.isNotBlank() } ?: "Wi-Fi Aware Peer"
                val existing = peerDao.getPeerById(id)
                if (existing == null) {
                    val metrics = WirelessLinkMetrics(-64, 0.94f, 38, 0.03f, 6500)
                    val pred = linkPredictor.predict(metrics)
                    peerDao.upsertPeer(
                        PeerDeviceEntity(
                            deviceId = id,
                            displayName = name,
                            trustStatus = TrustStatus.DISCOVERED,
                            connectionState = ConnectionState.OFFLINE,
                            transportType = TransportType.WIFI_AWARE,
                            rssiDbm = metrics.rssiDbm,
                            packetDeliveryRatio = metrics.packetDeliveryRatio,
                            latencyMs = metrics.latencyMs,
                            packetLossRate = metrics.packetLossRate,
                            throughputKbps = metrics.throughputKbps,
                            predictedLinkScore = pred.score
                        )
                    )
                }
            }
        }
    )

    val wifiDirectStatus: StateFlow<WifiDirectStatus> = wifiDirectTransport.status
    val wifiAwareStatus: StateFlow<WifiAwareStatus> = wifiAwareTransport.status
    val lanStatus: StateFlow<LanTransportStatus> = lanTransport.status
    val apkShareStatus: StateFlow<ApkShareStatus> = apkShareServer.status
    val meshRoutes: StateFlow<Map<String, MeshRouteEntry>> = meshRouter.routes
    val settingsFlow: Flow<SecurityAndAppSettings> = preferences.settingsFlow

    val allPeersFlow: Flow<List<PeerDeviceEntity>> = peerDao.observeAllPeers()
    val trustedPeersFlow: Flow<List<PeerDeviceEntity>> = peerDao.observeTrustedPeers()
    val transfersFlow: Flow<List<TransferRecordEntity>> = transferDao.observeAllTransfers()
    val groupsFlow: Flow<List<GroupEntity>> = groupDao.observeGroups()
    val pendingRelayFlow: Flow<List<PendingRelayPacketEntity>> = pendingRelayDao.observePendingPackets()

    val conversationsFlow: Flow<List<ConversationListItem>> =
        conversationDao.observeConversations().map { list ->
            list.map { c ->
                ConversationListItem(
                    conversationId = c.conversationId,
                    type = c.type,
                    title = c.title,
                    peerDeviceId = c.peerDeviceId,
                    groupId = c.groupId,
                    lastMessagePreview = storageCipher.decryptField(c.lastMessagePreviewEnc, "conv:${c.conversationId}"),
                    lastMessageTimestamp = c.lastMessageTimestamp,
                    unreadCount = c.unreadCount
                )
            }
        }

    init {
        scope.launch {
            settingsFlow.collect { s ->
                linkPredictor.mlModuleEnabled = s.mlPredictorEnabled
            }
        }
        scope.launch {
            allPeersFlow.collect { peers ->
                val localId = _localIdentity.value?.deviceId ?: return@collect
                meshRouter.updateDirectRoutes(localId, peers)
            }
        }
    }

    fun refreshHardwareCapabilities() {
        _hardwareCapabilities.value = TransportCapabilities.inspect(context)
    }

    suspend fun registerDevice(displayName: String): DevicePublicIdentity {
        val identity = withContext(Dispatchers.IO) {
            identityKeyManager.registerIdentity(displayName)
        }
        _localIdentity.value = identity
        preferences.setOnboardingCompleted(true)
        ensureListenersStarted()
        MeshForegroundService.start(context)
        return identity
    }

    suspend fun updateDisplayName(newName: String) {
        val updated = withContext(Dispatchers.IO) {
            identityKeyManager.updateDisplayName(newName)
        }
        _localIdentity.value = updated
    }

    suspend fun rotateDeviceKeys(): DevicePublicIdentity {
        val updated = withContext(Dispatchers.IO) {
            identityKeyManager.rotateAgreementKey()
        }
        _localIdentity.value = updated
        _securityEvents.tryEmit("X25519 key agreement pair rotated (Epoch ${updated.keyEpoch})")
        return updated
    }

    fun ensureListenersStarted() {
        val id = _localIdentity.value ?: return
        if (!listenersStarted) {
            listenersStarted = true
            wifiDirectTransport.initialize()
            wifiDirectTransport.registerLocalService(id.deviceId, id.displayName)
        }
        // Always ensure Wi-Fi socket servers restart cleanly if Wi-Fi was enabled later
        lanTransport.startServerAndNsd(id.deviceId, id.displayName)
        if (meshHeartbeatJob?.isActive != true) {
            meshHeartbeatJob = scope.launch {
                var tick = 0
                while (isActive) {
                    delay(4_500L)
                    tick++
                    runCatching {
                        val currentId = _localIdentity.value ?: return@runCatching
                        // Periodic silent UDP beacon so previously paired peers auto-reconnect fast in range
                        lanTransport.broadcastUdpBeacon(currentId.deviceId, currentId.displayName)
                        autoReconnectKnownPeers(currentId.deviceId)
                        meshRouter.updateDirectRoutes(currentId.deviceId, peerDao.getConnectedPeers())
                        if (tick % 2 == 0) {
                            sendRouteAdvertisementsToAll()
                            flushOfflineQueueAndCleanup()
                        }
                    }
                }
            }
        }
    }

    private suspend fun autoReconnectKnownPeers(localId: String) {
        val now = System.currentTimeMillis()
        val peers = peerDao.observeAllPeers().first()
        for (peer in peers) {
            if (peer.deviceId == localId || peer.trustStatus == TrustStatus.BLOCKED) continue
            val host = peer.endpointHost?.takeIf { it.isNotBlank() } ?: continue
            // Skip probing localhost/loopback endpoints (used in multi-device Robolectric tests)
            if (host == "127.0.0.1" || host == "::1") continue
            val staleOrOffline = peer.connectionState != ConnectionState.CONNECTED ||
                (now - peer.lastSeenMillis > 18_000L)
            if (staleOrOffline && peer.transportType != TransportType.MESH_RELAY) {
                val port = peer.endpointPort.takeIf { it in 1..65535 } ?: LocalWifiLanTransport.DEFAULT_PORT
                val key = "$host:$port"
                val lastAttempt = lastEndpointHelloMillis[key] ?: 0L
                if (now - lastAttempt >= 5_000L) {
                    lastEndpointHelloMillis[key] = now
                    sendHelloToEndpoint(host, port, peer.transportType.ifBlank { TransportType.LOCAL_LAN }, isAck = false)
                }
            }
        }
    }

    fun startAllDiscovery() {
        val id = _localIdentity.value ?: return
        ensureListenersStarted()
        refreshHardwareCapabilities()
        wifiDirectTransport.startDiscovery(id.deviceId, id.displayName)
        lanTransport.startDiscovery()
        wifiAwareTransport.start(id.deviceId, id.displayName)
    }

    fun stopAllDiscovery() {
        wifiDirectTransport.stopDiscovery()
        lanTransport.stopDiscoveryOnly()
        wifiAwareTransport.stop()
    }

    fun startApkShareServer() = apkShareServer.start()
    fun stopApkShareServer() = apkShareServer.stop()
    fun refreshApkShareIps() = apkShareServer.refreshIps()
    fun selectApkShareIp(ip: String) = apkShareServer.selectIp(ip)
    fun exportApkForShare(): File? = apkShareServer.exportShareableApkCopy()

    fun connectWifiDirectPeer(macAddress: String) {
        wifiDirectTransport.connectToPeer(macAddress)
    }

    fun connectAndPairWifiDirectPeer(macAddress: String) {
        pendingAutoPairP2pAddresses.add(macAddress)
        wifiDirectTransport.connectToPeer(macAddress)
    }

    fun generateLocalQrPayload(): String? {
        val id = _localIdentity.value ?: return null
        return QrVerificationCodec.encodeSignedPayload(id) { bytes ->
            cryptoEngine.signArbitraryBytes(bytes)
        }
    }

    suspend fun verifyScannedQrPayload(rawQr: String): Result<PeerDeviceEntity> = withContext(Dispatchers.IO) {
        val parsed: QrPeerVerificationPayload = QrVerificationCodec.decodeAndVerify(rawQr)
            .getOrElse { return@withContext Result.failure(it) }

        val localId = _localIdentity.value?.deviceId
        if (parsed.id == localId) {
            return@withContext Result.failure(IllegalArgumentException("Cannot verify your own device QR"))
        }

        val existing = peerDao.getPeerById(parsed.id)
        val updated = (existing ?: PeerDeviceEntity(deviceId = parsed.id, displayName = parsed.name)).copy(
            displayName = parsed.name,
            x25519PublicKeyB64 = parsed.x25519,
            ed25519PublicKeyB64 = parsed.ed25519,
            fingerprintHex = parsed.fp,
            keyEpoch = parsed.epoch,
            trustStatus = TrustStatus.VERIFIED_QR,
            lastSeenMillis = System.currentTimeMillis()
        )
        peerDao.upsertPeer(updated)
        ensurePrivateConversation(updated)
        _securityEvents.tryEmit("QR cryptographic verification succeeded for ${parsed.name}")
        if (!updated.endpointHost.isNullOrBlank() || meshRouter.selectBestNextHop(updated.deviceId) != null) {
            requestPairing(updated.deviceId)
        }
        flushOfflineQueueAndCleanup()
        Result.success(updated)
    }

    suspend fun requestPairing(peerDeviceId: String) {
        val peer = peerDao.getPeerById(peerDeviceId) ?: return
        val local = _localIdentity.value ?: return
        if (peer.endpointHost.isNullOrBlank() &&
            !peer.wifiP2pAddress.isNullOrBlank() &&
            meshRouter.selectBestNextHop(peerDeviceId) == null
        ) {
            connectAndPairWifiDirectPeer(peer.wifiP2pAddress)
        }
        peerDao.updateTrustStatus(peerDeviceId, TrustStatus.PENDING_OUTGOING)
        val payloadToSign = "PAIR_REQ|${local.deviceId}|${local.x25519PublicKeyBase64}|${local.ed25519PublicKeyBase64}".toByteArray()
        val frame = WireFrame(
            type = WireFrame.Types.PAIR_REQUEST,
            senderId = local.deviceId,
            senderName = local.displayName,
            x25519PubB64 = local.x25519PublicKeyBase64,
            ed25519PubB64 = local.ed25519PublicKeyBase64,
            fingerprintHex = local.fingerprintHex,
            keyEpoch = local.keyEpoch,
            listenPort = lanStatus.value.listenPort,
            signatureB64 = cryptoEngine.signArbitraryBytes(payloadToSign)
        )
        dispatchFrameToPeerOrRelay(peer, frame, "pair-req-${local.deviceId}-${peer.deviceId}-${System.currentTimeMillis()}")
    }

    suspend fun respondToPairing(peerDeviceId: String, accept: Boolean) {
        val peer = peerDao.getPeerById(peerDeviceId) ?: return
        val local = _localIdentity.value ?: return
        val newTrust = if (accept) TrustStatus.PAIRED_UNVERIFIED else TrustStatus.DISCOVERED
        peerDao.updateTrustStatus(peerDeviceId, newTrust)
        if (accept) ensurePrivateConversation(peer.copy(trustStatus = newTrust))

        val sigData = "PAIR_RESP|${local.deviceId}|$accept".toByteArray()
        val frame = WireFrame(
            type = WireFrame.Types.PAIR_RESPONSE,
            senderId = local.deviceId,
            senderName = local.displayName,
            x25519PubB64 = local.x25519PublicKeyBase64,
            ed25519PubB64 = local.ed25519PublicKeyBase64,
            fingerprintHex = local.fingerprintHex,
            keyEpoch = local.keyEpoch,
            accepted = accept,
            signatureB64 = cryptoEngine.signArbitraryBytes(sigData)
        )
        dispatchFrameToPeerOrRelay(peer, frame, "pair-resp-${local.deviceId}-${peer.deviceId}-${System.currentTimeMillis()}")
    }

    suspend fun markPeerManuallyVerified(peerDeviceId: String) {
        peerDao.updateTrustStatus(peerDeviceId, TrustStatus.VERIFIED_QR)
        peerDao.getPeerById(peerDeviceId)?.let { ensurePrivateConversation(it) }
    }

    suspend fun blockPeer(peerDeviceId: String) {
        peerDao.updateTrustStatus(peerDeviceId, TrustStatus.BLOCKED)
        peerDao.updateConnectionState(peerDeviceId, ConnectionState.OFFLINE)
        _securityEvents.tryEmit("Blocked device $peerDeviceId; all packets will be rejected")
    }

    suspend fun unblockPeer(peerDeviceId: String) {
        peerDao.updateTrustStatus(peerDeviceId, TrustStatus.PAIRED_UNVERIFIED)
    }

    suspend fun deletePeerConnection(peerDeviceId: String) = withContext(Dispatchers.IO) {
        meshRouter.removeRoute(peerDeviceId)
        val convId = "dm:$peerDeviceId"
        messageDao.deleteMessagesForConversation(convId)
        conversationDao.deleteConversation(convId)
        pendingRelayDao.deletePacketsForTarget(peerDeviceId)
        peerDao.deletePeer(peerDeviceId)
        directFailCounts.remove(peerDeviceId)
    }

    suspend fun deleteConversation(conversationId: String) = withContext(Dispatchers.IO) {
        messageDao.deleteMessagesForConversation(conversationId)
        conversationDao.deleteConversation(conversationId)
    }

    fun disconnectWifiDirect() {
        wifiDirectTransport.disconnect()
    }

    suspend fun connectToManualIpEndpoint(host: String, port: Int = LocalWifiLanTransport.DEFAULT_PORT): Result<Unit> {
        val ok = sendHelloToEndpoint(host.trim(), port, TransportType.LOCAL_LAN, isAck = false)
        return if (ok) Result.success(Unit)
        else Result.failure(IllegalStateException("Could not reach $host:$port"))
    }

    private suspend fun sendHelloToEndpointWithRetry(host: String, port: Int, transportType: String) {
        repeat(5) { attempt ->
            if (sendHelloToEndpoint(host, port, transportType, isAck = false)) return
            kotlinx.coroutines.delay(600L * (attempt + 1))
        }
    }

    private suspend fun buildHelloFrame(isAck: Boolean): WireFrame? {
        val local = _localIdentity.value ?: return null
        val body = "HELLO|${local.deviceId}|${local.x25519PublicKeyBase64}|${local.ed25519PublicKeyBase64}|${local.keyEpoch}".toByteArray()
        return WireFrame(
            type = WireFrame.Types.HELLO,
            senderId = local.deviceId,
            senderName = local.displayName,
            x25519PubB64 = local.x25519PublicKeyBase64,
            ed25519PubB64 = local.ed25519PublicKeyBase64,
            fingerprintHex = local.fingerprintHex,
            keyEpoch = local.keyEpoch,
            listenPort = lanStatus.value.listenPort,
            accepted = isAck,
            signatureB64 = cryptoEngine.signArbitraryBytes(body)
        )
    }

    private suspend fun sendHelloToEndpoint(
        host: String,
        port: Int,
        transportType: String,
        isAck: Boolean = false
    ): Boolean {
        val hello = buildHelloFrame(isAck) ?: return false
        val rttResult = lanTransport.sendFrame(host, port, json.encodeToString(hello))
        return rttResult.isSuccess
    }

    fun observeMessages(conversationId: String): Flow<List<DecryptedMessageItem>> =
        messageDao.observeMessages(conversationId).map { list ->
            list.map { m ->
                DecryptedMessageItem(
                    messageId = m.messageId,
                    conversationId = m.conversationId,
                    senderId = m.senderId,
                    senderName = m.senderName,
                    replyToMessageId = m.replyToMessageId,
                    replyToPreview = m.replyToPreviewEnc?.let {
                        storageCipher.decryptField(it, "reply:${m.messageId}")
                    },
                    forwardedFrom = m.forwardedFrom,
                    messageType = m.messageType,
                    text = storageCipher.decryptField(m.contentEnc, "msg:${m.messageId}"),
                    attachmentPath = m.attachmentPath,
                    attachmentName = m.attachmentName,
                    attachmentMimeType = m.attachmentMimeType,
                    attachmentSize = m.attachmentSize,
                    attachmentSha256 = m.attachmentSha256,
                    status = m.status,
                    hopCount = m.hopCount,
                    timestampMillis = m.timestampMillis,
                    isOutgoing = m.isOutgoing
                )
            }
        }

    fun observeGroupMembers(groupId: String): Flow<List<GroupMemberEntity>> =
        groupDao.observeGroupMembers(groupId)

    fun observeRecipientStatusesForConversation(conversationId: String): Flow<List<MessageRecipientStatusEntity>> =
        groupDao.observeRecipientStatusesForConversation(conversationId)

    suspend fun getOrCreatePrivateConversation(peerDeviceId: String): String {
        val peer = peerDao.getPeerById(peerDeviceId)
            ?: error("Unknown peer $peerDeviceId")
        return ensurePrivateConversation(peer)
    }

    private suspend fun ensurePrivateConversation(peer: PeerDeviceEntity): String {
        val convId = "dm:${peer.deviceId}"
        val existing = conversationDao.getConversation(convId)
        if (existing == null) {
            conversationDao.upsertConversation(
                ConversationEntity(
                    conversationId = convId,
                    type = ConversationType.PRIVATE,
                    title = peer.displayName,
                    peerDeviceId = peer.deviceId,
                    lastMessagePreviewEnc = storageCipher.encryptField("End-to-end encrypted session ready", "conv:$convId")
                )
            )
        }
        return convId
    }

    suspend fun markConversationRead(conversationId: String) {
        conversationDao.markConversationRead(conversationId)
    }

    suspend fun sendPrivateTextMessage(
        conversationId: String,
        peerDeviceId: String,
        text: String,
        replyToId: String? = null,
        replyToPreview: String? = null,
        forwardedFrom: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val local = _localIdentity.value ?: return@withContext Result.failure(IllegalStateException("Not registered"))
        val peer = peerDao.getPeerById(peerDeviceId)
            ?: return@withContext Result.failure(IllegalArgumentException("Peer not found"))
        if (peer.trustStatus == TrustStatus.BLOCKED) {
            return@withContext Result.failure(SecurityException("Cannot message a blocked device"))
        }
        if (peer.x25519PublicKeyB64.isBlank()) {
            return@withContext Result.failure(IllegalStateException("Peer public key not yet exchanged. Pair or scan QR first."))
        }

        val messageId = "msg-${UUID.randomUUID()}"
        val now = System.currentTimeMillis()
        val msgEntity = MessageEntity(
            messageId = messageId,
            conversationId = conversationId,
            senderId = local.deviceId,
            senderName = local.displayName,
            replyToMessageId = replyToId,
            replyToPreviewEnc = replyToPreview?.let { storageCipher.encryptField(it, "reply:$messageId") },
            forwardedFrom = forwardedFrom,
            messageType = MessageType.TEXT,
            contentEnc = storageCipher.encryptField(text, "msg:$messageId"),
            status = MessageStatus.QUEUED,
            timestampMillis = now,
            isOutgoing = true
        )
        messageDao.upsertMessage(msgEntity)
        conversationDao.upsertConversation(
            ConversationEntity(
                conversationId = conversationId,
                type = ConversationType.PRIVATE,
                title = peer.displayName,
                peerDeviceId = peer.deviceId,
                lastMessagePreviewEnc = storageCipher.encryptField(text, "conv:$conversationId"),
                lastMessageTimestamp = now,
                unreadCount = 0
            )
        )

        val envelope = cryptoEngine.encryptMessage(
            messageId = messageId,
            recipientId = peer.deviceId,
            recipientX25519PubB64 = peer.x25519PublicKeyB64,
            recipientKeyEpoch = peer.keyEpoch,
            plaintext = text.toByteArray(Charsets.UTF_8),
            timestampMillis = now
        )
        val frame = WireFrame(
            type = WireFrame.Types.CHAT_ENVELOPE,
            senderId = local.deviceId,
            senderName = local.displayName,
            envelope = envelope,
            messageType = MessageType.TEXT,
            replyToId = replyToId,
            forwardedFrom = forwardedFrom
        )
        val deliveredDirect = dispatchFrameToPeerOrRelay(peer, frame, messageId)
        messageDao.updateMessageStatus(
            messageId,
            if (deliveredDirect) MessageStatus.SENT else MessageStatus.QUEUED
        )
        Result.success(Unit)
    }

    suspend fun sendVoiceMessage(
        conversationId: String,
        peerDeviceId: String,
        voiceFile: File
    ): Result<Unit> = sendFileAttachment(
        conversationId = conversationId,
        peerDeviceId = peerDeviceId,
        fileUri = Uri.fromFile(voiceFile),
        overrideMessageType = MessageType.VOICE,
        overrideFileName = voiceFile.name,
        overrideMimeType = "audio/mp4"
    )

    suspend fun createGroupOrBroadcast(
        name: String,
        description: String,
        memberDeviceIds: List<String>,
        isBroadcastChannel: Boolean,
        allowMemberBroadcast: Boolean
    ): String = withContext(Dispatchers.IO) {
        val local = _localIdentity.value ?: error("Identity not initialized")
        val groupId = (if (isBroadcastChannel) "bcast-" else "grp-") + UUID.randomUUID().toString().take(12)
        val groupKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val groupKeyB64 = Base64.encodeToString(groupKey, Base64.NO_WRAP)
        groupKey.fill(0)

        val group = GroupEntity(
            groupId = groupId,
            name = name.trim(),
            description = description.trim(),
            adminDeviceId = local.deviceId,
            isBroadcastChannel = isBroadcastChannel,
            allowMemberBroadcast = allowMemberBroadcast,
            requireOptIn = true,
            isOptedIn = true,
            keyEpoch = 1,
            wrappedGroupKeyEnc = storageCipher.encryptField(groupKeyB64, "grp:$groupId")
        )
        groupDao.upsertGroup(group)
        groupDao.upsertGroupMember(
            GroupMemberEntity(
                groupId = groupId,
                deviceId = local.deviceId,
                displayName = local.displayName,
                role = "ADMIN",
                canBroadcast = true
            )
        )

        for (peerId in memberDeviceIds.distinct()) {
            val peer = peerDao.getPeerById(peerId) ?: continue
            if (peer.trustStatus == TrustStatus.BLOCKED) continue
            groupDao.upsertGroupMember(
                GroupMemberEntity(
                    groupId = groupId,
                    deviceId = peer.deviceId,
                    displayName = peer.displayName,
                    role = if (isBroadcastChannel) "LISTENER" else "MEMBER",
                    canBroadcast = !isBroadcastChannel || allowMemberBroadcast
                )
            )
        }

        val convId = "conv:$groupId"
        conversationDao.upsertConversation(
            ConversationEntity(
                conversationId = convId,
                type = if (isBroadcastChannel) ConversationType.BROADCAST else ConversationType.GROUP,
                title = name.trim(),
                groupId = groupId,
                lastMessagePreviewEnc = storageCipher.encryptField(
                    if (isBroadcastChannel) "Broadcast channel created" else "Encrypted group created",
                    "conv:$convId"
                )
            )
        )
        syncGroupMembershipToPeers(groupId)
        convId
    }

    suspend fun addMemberToGroup(groupId: String, peerDeviceId: String) {
        val peer = peerDao.getPeerById(peerDeviceId) ?: return
        if (peer.trustStatus == TrustStatus.BLOCKED) return
        val group = groupDao.getGroupById(groupId) ?: return
        groupDao.upsertGroupMember(
            GroupMemberEntity(
                groupId = groupId,
                deviceId = peer.deviceId,
                displayName = peer.displayName,
                role = if (group.isBroadcastChannel) "LISTENER" else "MEMBER",
                canBroadcast = !group.isBroadcastChannel || group.allowMemberBroadcast
            )
        )
        syncGroupMembershipToPeers(groupId)
    }

    private suspend fun syncGroupMembershipToPeers(groupId: String) {
        val local = _localIdentity.value ?: return
        val group = groupDao.getGroupById(groupId) ?: return
        val members = groupDao.getGroupMembers(groupId)
        val memberIds = members.map { it.deviceId }
        val memberNames = members.map { it.displayName }
        val sig = cryptoEngine.signArbitraryBytes("GRPSYNC|$groupId|${group.adminDeviceId}|${group.keyEpoch}".toByteArray())
        val syncFrame = WireFrame(
            type = WireFrame.Types.GROUP_KEY_SYNC,
            senderId = local.deviceId,
            senderName = local.displayName,
            groupId = groupId,
            groupName = group.name,
            groupDesc = group.description,
            groupAdminId = group.adminDeviceId,
            isBroadcast = group.isBroadcastChannel,
            allowMemberBroadcast = group.allowMemberBroadcast,
            keyEpoch = group.keyEpoch,
            groupMemberIds = memberIds,
            groupMemberNames = memberNames,
            signatureB64 = sig
        )
        for (member in members) {
            if (member.deviceId == local.deviceId) continue
            val peer = peerDao.getPeerById(member.deviceId) ?: continue
            if (peer.trustStatus == TrustStatus.BLOCKED) continue
            dispatchFrameToPeerOrRelay(peer, syncFrame, "grpsync-$groupId-${group.keyEpoch}-${peer.deviceId}")
        }
    }

    suspend fun removeMemberFromGroupAndRotateKey(groupId: String, deviceId: String) {
        val group = groupDao.getGroupById(groupId) ?: return
        groupDao.removeGroupMember(groupId, deviceId)
        val newGroupKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val newKeyB64 = Base64.encodeToString(newGroupKey, Base64.NO_WRAP)
        newGroupKey.fill(0)
        groupDao.upsertGroup(
            group.copy(
                keyEpoch = group.keyEpoch + 1,
                wrappedGroupKeyEnc = storageCipher.encryptField(newKeyB64, "grp:$groupId")
            )
        )
        _securityEvents.tryEmit("Removed member & rotated group key to Epoch ${group.keyEpoch + 1}")
    }

    suspend fun setBroadcastOptIn(groupId: String, optIn: Boolean) {
        groupDao.updateGroupOptIn(groupId, optIn)
    }

    suspend fun sendGroupOrBroadcastMessage(
        groupId: String,
        text: String,
        attachmentUri: Uri? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val local = _localIdentity.value ?: return@withContext Result.failure(IllegalStateException("Not registered"))
        val group = groupDao.getGroupById(groupId)
            ?: return@withContext Result.failure(IllegalArgumentException("Group not found"))

        if (group.isBroadcastChannel && group.adminDeviceId != local.deviceId && !group.allowMemberBroadcast) {
            return@withContext Result.failure(SecurityException("Unauthorized broadcast: Only channel admin may broadcast."))
        }
        if (group.isBroadcastChannel && !group.isOptedIn) {
            return@withContext Result.failure(SecurityException("You have opted out of this broadcast channel."))
        }

        val convId = "conv:$groupId"
        val messageId = "gmsg-${UUID.randomUUID()}"
        val now = System.currentTimeMillis()

        var attachName: String? = null
        var attachMime: String? = null
        var attachSize = 0L
        var attachSha: String? = null
        var msgType = MessageType.TEXT
        var localCopyPath: String? = null

        if (attachmentUri != null) {
            val meta = queryUriMeta(attachmentUri)
            attachName = meta.first
            attachMime = meta.second
            attachSize = meta.third
            msgType = classifyMime(attachMime)
            val savedFile = copyUriToReceivedDir(attachmentUri, attachName)
            localCopyPath = savedFile.absolutePath
            attachSha = FileInputStream(savedFile).use { cryptoEngine.streamSha256(it).second }
        }

        messageDao.upsertMessage(
            MessageEntity(
                messageId = messageId,
                conversationId = convId,
                senderId = local.deviceId,
                senderName = local.displayName,
                messageType = msgType,
                contentEnc = storageCipher.encryptField(text, "msg:$messageId"),
                attachmentPath = localCopyPath,
                attachmentName = attachName,
                attachmentMimeType = attachMime,
                attachmentSize = attachSize,
                attachmentSha256 = attachSha,
                status = MessageStatus.SENT,
                timestampMillis = now,
                isOutgoing = true
            )
        )
        conversationDao.upsertConversation(
            ConversationEntity(
                conversationId = convId,
                type = if (group.isBroadcastChannel) ConversationType.BROADCAST else ConversationType.GROUP,
                title = group.name,
                groupId = groupId,
                lastMessagePreviewEnc = storageCipher.encryptField(
                    text.ifBlank { attachName ?: "Attachment" },
                    "conv:$convId"
                ),
                lastMessageTimestamp = now
            )
        )

        val members = groupDao.getGroupMembers(groupId).filter { it.deviceId != local.deviceId }
        for (member in members) {
            val peer = peerDao.getPeerById(member.deviceId)
            if (peer == null || peer.trustStatus == TrustStatus.BLOCKED || peer.x25519PublicKeyB64.isBlank()) {
                groupDao.upsertRecipientStatus(
                    MessageRecipientStatusEntity(
                        messageId = messageId,
                        recipientDeviceId = member.deviceId,
                        recipientName = member.displayName,
                        status = if (peer?.trustStatus == TrustStatus.BLOCKED) MessageStatus.FAILED else MessageStatus.QUEUED
                    )
                )
                continue
            }

            val perRecipientPayload = text.ifBlank { attachName ?: "Media" }
            val envelope = cryptoEngine.encryptMessage(
                messageId = "$messageId:${peer.deviceId}",
                recipientId = peer.deviceId,
                recipientX25519PubB64 = peer.x25519PublicKeyB64,
                recipientKeyEpoch = peer.keyEpoch,
                plaintext = perRecipientPayload.toByteArray(Charsets.UTF_8),
                timestampMillis = now
            )
            val frame = WireFrame(
                type = WireFrame.Types.CHAT_ENVELOPE,
                senderId = local.deviceId,
                senderName = local.displayName,
                envelope = envelope,
                messageType = msgType,
                groupId = groupId,
                groupName = group.name,
                isBroadcast = group.isBroadcastChannel
            )
            val sent = dispatchFrameToPeerOrRelay(peer, frame, "$messageId:${peer.deviceId}")
            groupDao.upsertRecipientStatus(
                MessageRecipientStatusEntity(
                    messageId = messageId,
                    recipientDeviceId = peer.deviceId,
                    recipientName = peer.displayName,
                    status = if (sent) MessageStatus.SENT else MessageStatus.QUEUED
                )
            )
            if (attachmentUri != null && localCopyPath != null) {
                sendFileAttachment(convId, peer.deviceId, Uri.fromFile(File(localCopyPath)), msgType, attachName, attachMime)
            }
        }
        Result.success(Unit)
    }

    suspend fun deleteMessage(messageId: String) {
        messageDao.deleteMessage(messageId)
    }

    /**
     * Streams a file in 64 KB chunks with AES-256-GCM encryption + SHA-256 integrity verification,
     * never loading large videos into memory. Supports pause/resume & duplicate detection.
     */
    suspend fun sendFileAttachment(
        conversationId: String,
        peerDeviceId: String,
        fileUri: Uri,
        overrideMessageType: String? = null,
        overrideFileName: String? = null,
        overrideMimeType: String? = null
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val local = _localIdentity.value ?: return@withContext Result.failure(IllegalStateException("Not registered"))
        val peer = peerDao.getPeerById(peerDeviceId)
            ?: return@withContext Result.failure(IllegalArgumentException("Recipient peer not found"))
        if (peer.trustStatus == TrustStatus.BLOCKED) {
            return@withContext Result.failure(SecurityException("Recipient is blocked"))
        }
        if (peer.x25519PublicKeyB64.isBlank()) {
            return@withContext Result.failure(IllegalStateException("Recipient cryptographic keys unavailable. Pair first."))
        }

        val meta = queryUriMeta(fileUri)
        val fileName = overrideFileName ?: meta.first
        val mimeType = overrideMimeType ?: meta.second
        val estimatedSize = meta.third
        if (estimatedSize > MAX_FILE_SIZE_BYTES) {
            return@withContext Result.failure(IllegalArgumentException("File exceeds 2 GB safety cap"))
        }

        val transferId = "tx-${UUID.randomUUID()}"
        val cacheTmp = File(context.cacheDir, "tx_$transferId.tmp")
        val shaHex: String
        val actualSize: Long
        try {
            val input = context.contentResolver.openInputStream(fileUri)
                ?: FileInputStream(File(fileUri.path ?: ""))
            input.use { ins ->
                FileOutputStream(cacheTmp).use { outs ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buf = ByteArray(E2eeCryptoEngine.DEFAULT_CHUNK_SIZE)
                    var total = 0L
                    while (true) {
                        val r = ins.read(buf)
                        if (r <= 0) break
                        digest.update(buf, 0, r)
                        outs.write(buf, 0, r)
                        total += r
                    }
                    actualSize = total
                    shaHex = digest.digest().joinToString("") { "%02x".format(it) }
                }
            }
        } catch (e: Exception) {
            cacheTmp.delete()
            return@withContext Result.failure(e)
        }

        val duplicate = transferDao.findCompletedBySha256(shaHex)
        if (duplicate != null) {
            _securityEvents.tryEmit("Duplicate file detected (${duplicate.fileName}); continuing encrypted send.")
        }

        val totalChunks = if (actualSize == 0L) {
            0
        } else {
            ((actualSize + E2eeCryptoEngine.DEFAULT_CHUNK_SIZE - 1) / E2eeCryptoEngine.DEFAULT_CHUNK_SIZE)
                .toInt()
        }

        val (fek, wrap) = cryptoEngine.createChunkedFileEncryptionSession(
            transferId = transferId,
            recipientId = peer.deviceId,
            recipientX25519PubB64 = peer.x25519PublicKeyB64
        )
        val manifestSig = cryptoEngine.signFileManifest(
            transferId = transferId,
            senderId = local.deviceId,
            recipientId = peer.deviceId,
            fileName = fileName,
            fileSize = actualSize,
            sha256Hex = shaHex
        )

        val record = TransferRecordEntity(
            transferId = transferId,
            peerDeviceId = peer.deviceId,
            peerName = peer.displayName,
            conversationId = conversationId,
            fileName = fileName,
            mimeType = mimeType,
            fileSize = actualSize,
            sha256Hex = shaHex,
            direction = "OUTGOING",
            state = TransferState.IN_PROGRESS,
            bytesTransferred = 0L,
            chunkIndex = 0,
            totalChunks = totalChunks,
            localUriOrPath = cacheTmp.absolutePath,
            tempFilePath = cacheTmp.absolutePath,
            cryptoHeaderJson = json.encodeToString(
                FileCryptoMetadata(
                    ephemeralX25519PubB64 = wrap.ephemeralX25519PubB64,
                    wrappedDekB64 = wrap.wrappedDekB64,
                    baseNonceB64 = wrap.baseNonceB64,
                    senderX25519PubB64 = local.x25519PublicKeyBase64,
                    senderEd25519PubB64 = local.ed25519PublicKeyBase64,
                    manifestSigB64 = manifestSig
                )
            )
        )
        transferDao.upsertTransfer(record)

        val isGroupAttachment = conversationId.startsWith("conv:")
        val msgId = if (isGroupAttachment) null else "fmsg-$transferId"
        val msgType = overrideMessageType ?: classifyMime(mimeType)
        val convId = if (isGroupAttachment) conversationId else ensurePrivateConversation(peer)
        if (msgId != null) {
            messageDao.upsertMessage(
                MessageEntity(
                    messageId = msgId,
                    conversationId = convId,
                    senderId = local.deviceId,
                    senderName = local.displayName,
                    messageType = msgType,
                    contentEnc = storageCipher.encryptField("Encrypted file: $fileName", "msg:$msgId"),
                    attachmentPath = cacheTmp.absolutePath,
                    attachmentName = fileName,
                    attachmentMimeType = mimeType,
                    attachmentSize = actualSize,
                    attachmentSha256 = shaHex,
                    status = MessageStatus.SENDING,
                    isOutgoing = true
                )
            )
            conversationDao.upsertConversation(
                ConversationEntity(
                    conversationId = convId,
                    type = ConversationType.PRIVATE,
                    title = peer.displayName,
                    peerDeviceId = peer.deviceId,
                    lastMessagePreviewEnc = storageCipher.encryptField("File: $fileName", "conv:$convId"),
                    lastMessageTimestamp = System.currentTimeMillis(),
                    unreadCount = 0
                )
            )
        }

        // Send FILE_OFFER (directly if reachable, otherwise over multi-hop blind MESH_RELAY)
        val offerFrame = WireFrame(
            type = WireFrame.Types.FILE_OFFER,
            senderId = local.deviceId,
            senderName = local.displayName,
            transferId = transferId,
            conversationId = convId,
            fileName = fileName,
            mimeType = mimeType,
            fileSize = actualSize,
            sha256Hex = shaHex,
            totalChunks = totalChunks,
            ephemeralX25519PubB64 = wrap.ephemeralX25519PubB64,
            wrappedDekB64 = wrap.wrappedDekB64,
            baseNonceB64 = wrap.baseNonceB64,
            manifestSigB64 = manifestSig
        )
        val directSession = openPeerSession(peer)
        var useRelay = directSession == null
        var transportPeer: PeerDeviceEntity = peer
        var activeSession: LocalWifiLanTransport.PeerFrameSession? = directSession

        if (activeSession == null) {
            val relayPeer = resolveRelayHopPeer(peer.deviceId)
            if (relayPeer != null) {
                transportPeer = relayPeer
                activeSession = openPeerSession(relayPeer)
                useRelay = true
            }
        }

        val offerWireFrame = if (useRelay) {
            wrapForMultiHopRelay(local.deviceId, peer.deviceId, offerFrame, "relay-$transferId-offer")
        } else {
            offerFrame
        }
        val offerSent = dispatchFrameOnSessionOrDirect(transportPeer, activeSession, offerWireFrame)
        if (!offerSent) {
            runCatching { activeSession?.close() }
            fek.fill(0)
            transferDao.updateProgress(transferId, TransferState.PAUSED, 0L, 0)
            msgId?.let { messageDao.updateMessageStatus(it, MessageStatus.FAILED) }
            return@withContext Result.failure(
                IllegalStateException("Peer unreachable over Wi-Fi or multi-hop relay")
            )
        }

        // Stream chunks in 64KB increments without holding file in memory
        val baseNonce = Base64.decode(wrap.baseNonceB64, Base64.NO_WRAP)
        val result = streamEncryptedChunksFromOffset(
            peer = peer,
            transferId = transferId,
            sourceFile = cacheTmp,
            fek = fek,
            baseNonce = baseNonce,
            startChunkIndex = 0,
            totalSize = actualSize,
            shaHex = shaHex,
            msgId = msgId,
            initialSession = activeSession,
            transportPeer = transportPeer,
            useRelay = useRelay
        )
        fek.fill(0)
        result
    }

    private suspend fun resolveRelayHopPeer(targetDeviceId: String): PeerDeviceEntity? {
        val route = meshRouter.selectBestNextHop(targetDeviceId)
        if (route != null && route.nextHopDeviceId != targetDeviceId) {
            val nextPeer = peerDao.getPeerById(route.nextHopDeviceId)
            if (nextPeer != null && !nextPeer.endpointHost.isNullOrBlank()) return nextPeer
        }
        return peerDao.getConnectedPeers().firstOrNull {
            it.deviceId != targetDeviceId && !it.endpointHost.isNullOrBlank()
        }
    }

    private fun wrapForMultiHopRelay(
        localId: String,
        targetDeviceId: String,
        innerFrame: WireFrame,
        packetId: String
    ): WireFrame = WireFrame(
        type = WireFrame.Types.MESH_RELAY,
        senderId = localId,
        packetId = packetId,
        originDeviceId = localId,
        targetDeviceId = targetDeviceId,
        hopCount = 0,
        maxHops = MeshRouter.MAX_MESH_HOPS,
        ttlExpiresAt = System.currentTimeMillis() + 24 * 60 * 60 * 1000L,
        visitedPath = listOf(localId),
        innerPayloadJson = json.encodeToString(innerFrame)
    )

    private suspend fun openPeerSession(peer: PeerDeviceEntity): LocalWifiLanTransport.PeerFrameSession? {
        val host = peer.endpointHost?.takeIf { it.isNotBlank() } ?: return null
        val port = peer.endpointPort.takeIf { it in 1..65535 } ?: LocalWifiLanTransport.DEFAULT_PORT
        return lanTransport.openPeerSession(host, port).getOrNull()
    }

    private suspend fun dispatchFrameOnSessionOrDirect(
        peer: PeerDeviceEntity,
        session: LocalWifiLanTransport.PeerFrameSession?,
        frame: WireFrame
    ): Boolean {
        val raw = json.encodeToString(frame)
        if (session != null && session.sendFrame(raw).isSuccess) {
            return true
        }
        return dispatchFrameToPeer(peer, frame)
    }

    private suspend fun streamEncryptedChunksFromOffset(
        peer: PeerDeviceEntity,
        transferId: String,
        sourceFile: File,
        fek: ByteArray,
        baseNonce: ByteArray,
        startChunkIndex: Int,
        totalSize: Long,
        shaHex: String,
        msgId: String? = null,
        initialSession: LocalWifiLanTransport.PeerFrameSession? = null,
        transportPeer: PeerDeviceEntity = peer,
        useRelay: Boolean = false
    ): Result<Unit> {
        val local = _localIdentity.value ?: return Result.failure(IllegalStateException("No identity"))
        var session = initialSession ?: openPeerSession(transportPeer)
        return try {
            runCatching {
                val chunkSize = E2eeCryptoEngine.DEFAULT_CHUNK_SIZE
                FileInputStream(sourceFile).use { fis ->
                    val skipBytes = startChunkIndex.toLong() * chunkSize
                    if (skipBytes > 0) fis.skip(skipBytes)
                    var chunkIdx = startChunkIndex
                    var transferred = skipBytes
                    val buf = ByteArray(chunkSize)

                    while (true) {
                        if (pausedTransfers[transferId] == true) {
                            transferDao.updateProgress(transferId, TransferState.PAUSED, transferred, chunkIdx)
                            return Result.success(Unit)
                        }
                        val read = fis.read(buf)
                        if (read <= 0) break
                        val plainSlice = if (read == buf.size) buf else buf.copyOf(read)
                        val encChunk = cryptoEngine.encryptFileChunk(fek, baseNonce, transferId, chunkIdx, plainSlice)
                        val chunkFrame = WireFrame(
                            type = WireFrame.Types.FILE_CHUNK,
                            senderId = local.deviceId,
                            transferId = transferId,
                            chunkIndex = chunkIdx,
                            encryptedChunkB64 = Base64.encodeToString(encChunk, Base64.NO_WRAP)
                        )
                        val wireChunk = if (useRelay) {
                            wrapForMultiHopRelay(local.deviceId, peer.deviceId, chunkFrame, "relay-$transferId-c$chunkIdx")
                        } else {
                            chunkFrame
                        }
                        val rawChunk = json.encodeToString(wireChunk)
                        var sent = session?.sendFrame(rawChunk)?.isSuccess == true
                        if (!sent) {
                            runCatching { session?.close() }
                            session = openPeerSession(transportPeer)
                            sent = session?.sendFrame(rawChunk)?.isSuccess == true || dispatchFrameToPeer(transportPeer, wireChunk)
                        }
                        if (!sent) {
                            transferDao.updateProgress(transferId, TransferState.PAUSED, transferred, chunkIdx)
                            return Result.failure(IllegalStateException("Peer disconnected mid-transfer; ready to resume at chunk $chunkIdx"))
                        }
                        transferred += read
                        chunkIdx++
                        transferDao.updateProgress(transferId, TransferState.IN_PROGRESS, transferred, chunkIdx)
                    }

                    val completeFrame = WireFrame(
                        type = WireFrame.Types.FILE_COMPLETE,
                        senderId = local.deviceId,
                        transferId = transferId,
                        sha256Hex = shaHex
                    )
                    val wireComplete = if (useRelay) {
                        wrapForMultiHopRelay(local.deviceId, peer.deviceId, completeFrame, "relay-$transferId-done")
                    } else {
                        completeFrame
                    }
                    val rawComplete = json.encodeToString(wireComplete)
                    var completeSent = session?.sendFrame(rawComplete)?.isSuccess == true
                    if (!completeSent) {
                        runCatching { session?.close() }
                        session = openPeerSession(transportPeer)
                        completeSent = session?.sendFrame(rawComplete)?.isSuccess == true || dispatchFrameToPeer(transportPeer, wireComplete)
                    }
                    if (!completeSent) {
                        transferDao.updateProgress(transferId, TransferState.PAUSED, transferred, chunkIdx)
                        return Result.failure(IllegalStateException("Failed to finalize file transfer with peer"))
                    }
                    transferDao.updateProgress(transferId, TransferState.COMPLETED, totalSize, chunkIdx)
                    msgId?.let { messageDao.updateStatusIfNotDelivered(it, MessageStatus.SENT) }
                }
                Unit
            }.onFailure {
                transferDao.updateProgress(transferId, TransferState.FAILED, 0L, startChunkIndex)
                msgId?.let { id -> messageDao.updateMessageStatus(id, MessageStatus.FAILED) }
            }
        } finally {
            runCatching { session?.close() }
        }
    }

    suspend fun pauseTransfer(transferId: String) {
        pausedTransfers[transferId] = true
        val existing = transferDao.getTransfer(transferId) ?: return
        transferDao.updateProgress(transferId, TransferState.PAUSED, existing.bytesTransferred, existing.chunkIndex)
    }

    suspend fun resumeTransfer(transferId: String): Result<Unit> = withContext(Dispatchers.IO) {
        pausedTransfers[transferId] = false
        val rec = transferDao.getTransfer(transferId)
            ?: return@withContext Result.failure(IllegalArgumentException("Transfer not found"))
        val peer = peerDao.getPeerById(rec.peerDeviceId)
            ?: return@withContext Result.failure(IllegalStateException("Peer offline"))

        if (rec.direction == "OUTGOING") {
            val file = rec.tempFilePath?.let { File(it) }
                ?: return@withContext Result.failure(IllegalStateException("Temp file missing"))
            val meta = json.decodeFromString<FileCryptoMetadata>(rec.cryptoHeaderJson)
            val local = _localIdentity.value ?: return@withContext Result.failure(IllegalStateException("No identity"))
            val (fek, wrap) = cryptoEngine.createChunkedFileEncryptionSession(
                transferId = transferId,
                recipientId = peer.deviceId,
                recipientX25519PubB64 = peer.x25519PublicKeyB64
            )
            // Re-send offer with current session key if restarting from chunk 0, or resume chunk
            val baseNonce = Base64.decode(meta.baseNonceB64, Base64.NO_WRAP)
            transferDao.updateProgress(transferId, TransferState.IN_PROGRESS, rec.bytesTransferred, rec.chunkIndex)
            val res = streamEncryptedChunksFromOffset(
                peer = peer,
                transferId = transferId,
                sourceFile = file,
                fek = fek,
                baseNonce = baseNonce,
                startChunkIndex = rec.chunkIndex,
                totalSize = rec.fileSize,
                shaHex = rec.sha256Hex
            )
            fek.fill(0)
            res
        } else {
            val local = _localIdentity.value ?: return@withContext Result.failure(IllegalStateException("No identity"))
            transferDao.updateProgress(transferId, TransferState.IN_PROGRESS, rec.bytesTransferred, rec.chunkIndex)
            dispatchFrameToPeer(
                peer,
                WireFrame(
                    type = WireFrame.Types.FILE_RESPONSE,
                    senderId = local.deviceId,
                    transferId = transferId,
                    accepted = true,
                    chunkIndex = rec.chunkIndex
                )
            )
            Result.success(Unit)
        }
    }

    suspend fun acceptOrRejectIncomingTransfer(transferId: String, accept: Boolean) = withContext(Dispatchers.IO) {
        val rec = transferDao.getTransfer(transferId) ?: return@withContext
        val peer = peerDao.getPeerById(rec.peerDeviceId) ?: return@withContext
        val local = _localIdentity.value ?: return@withContext

        if (!accept) {
            transferDao.updateProgress(transferId, TransferState.REJECTED, 0L, 0)
            incomingFileChunks.remove(transferId)
            rec.tempFilePath?.let { File(it).delete() }
            dispatchFrameToPeer(
                peer,
                WireFrame(
                    type = WireFrame.Types.FILE_RESPONSE,
                    senderId = local.deviceId,
                    transferId = transferId,
                    accepted = false
                )
            )
            return@withContext
        }

        if (!hasEnoughStorage(rec.fileSize + 1_048_576L)) {
            transferDao.updateProgress(transferId, TransferState.FAILED, 0L, 0)
            _securityEvents.tryEmit("Insufficient storage for ${rec.fileName}")
            return@withContext
        }

        transferDao.updateProgress(transferId, TransferState.IN_PROGRESS, rec.bytesTransferred, rec.chunkIndex)
        dispatchFrameToPeer(
            peer,
            WireFrame(
                type = WireFrame.Types.FILE_RESPONSE,
                senderId = local.deviceId,
                transferId = transferId,
                accepted = true,
                chunkIndex = rec.chunkIndex
            )
        )
        // If chunks were already buffered before user tapped Accept, assemble now
        tryAssembleBufferedChunks(transferId)
    }

    private suspend fun handleIncomingRawFrame(rawJson: String, remoteAddr: String, transport: String) {
        val frame = runCatching { json.decodeFromString<WireFrame>(rawJson) }.getOrNull() ?: return
        val local = _localIdentity.value ?: return

        val senderPeer = peerDao.getPeerById(frame.senderId)
        if (senderPeer?.trustStatus == TrustStatus.BLOCKED) {
            _securityEvents.tryEmit("Rejected packet from blocked device ${frame.senderId}")
            return
        }

        when (frame.type) {
            WireFrame.Types.HELLO -> handleHello(frame, remoteAddr, transport, local)
            WireFrame.Types.PAIR_REQUEST -> handlePairRequest(frame, remoteAddr, transport)
            WireFrame.Types.PAIR_RESPONSE -> handlePairResponse(frame)
            WireFrame.Types.CHAT_ENVELOPE -> handleChatEnvelope(frame, local)
            WireFrame.Types.GROUP_KEY_SYNC -> handleGroupSync(frame, local)
            WireFrame.Types.ACK_PACKET -> handleAck(frame)
            WireFrame.Types.MESH_RELAY -> handleMeshRelay(frame, local)
            WireFrame.Types.ROUTE_ADV -> handleRouteAdvertisement(frame, local)
            WireFrame.Types.FILE_OFFER -> handleIncomingFileOffer(frame, local)
            WireFrame.Types.FILE_CHUNK -> handleIncomingFileChunk(frame)
            WireFrame.Types.FILE_COMPLETE -> handleIncomingFileComplete(frame, local)
            WireFrame.Types.FILE_RESPONSE -> handleFileResponse(frame)
        }
    }

    private suspend fun handleHello(
        frame: WireFrame,
        remoteAddr: String,
        transport: String,
        local: DevicePublicIdentity
    ) {
        if (frame.senderId.isBlank() || frame.senderId == local.deviceId) return
        val expectedFp = IdentityKeyManager.computeFingerprintHex(frame.x25519PubB64, frame.ed25519PubB64)
        if (!expectedFp.equals(frame.fingerprintHex, ignoreCase = true)) {
            _securityEvents.tryEmit("Rejected HELLO with mismatched public key fingerprint from ${frame.senderName}")
            return
        }
        val body = "HELLO|${frame.senderId}|${frame.x25519PubB64}|${frame.ed25519PubB64}|${frame.keyEpoch}".toByteArray()
        if (!cryptoEngine.verifyArbitrarySignature(frame.ed25519PubB64, body, frame.signatureB64)) {
            _securityEvents.tryEmit("Rejected HELLO with invalid Ed25519 signature from ${frame.senderName}")
            return
        }

        val resolvedTransport = if (transport == TransportType.LOCAL_LAN && remoteAddr.startsWith("192.168.49.")) {
            TransportType.WIFI_DIRECT
        } else {
            transport
        }

        val existing = peerDao.getPeerById(frame.senderId)
        val metrics = WirelessLinkMetrics(-58, 0.96f, 28, 0.02f, 8200)
        val pred = linkPredictor.predict(metrics)
        val updatedEndpointHost = remoteAddr.ifBlank { existing?.endpointHost }
        val updatedEndpointPort = frame.listenPort.takeIf { it > 0 }
            ?: existing?.endpointPort
            ?: LocalWifiLanTransport.DEFAULT_PORT

        // Preserve verified/paired root identity and accept rotated X25519 keys if Ed25519 root key matches
        val trustedKeyUpdate = existing == null ||
            existing.ed25519PublicKeyB64.isBlank() ||
            existing.ed25519PublicKeyB64 == frame.ed25519PubB64

        val updated = (existing ?: PeerDeviceEntity(deviceId = frame.senderId, displayName = frame.senderName)).copy(
            displayName = frame.senderName,
            x25519PublicKeyB64 = if (trustedKeyUpdate) frame.x25519PubB64 else existing!!.x25519PublicKeyB64,
            ed25519PublicKeyB64 = if (trustedKeyUpdate) frame.ed25519PubB64 else existing!!.ed25519PublicKeyB64,
            fingerprintHex = if (trustedKeyUpdate) frame.fingerprintHex else existing!!.fingerprintHex,
            keyEpoch = if (trustedKeyUpdate) frame.keyEpoch else existing!!.keyEpoch,
            connectionState = ConnectionState.CONNECTED,
            transportType = resolvedTransport,
            endpointHost = updatedEndpointHost,
            endpointPort = updatedEndpointPort,
            rssiDbm = metrics.rssiDbm,
            packetDeliveryRatio = metrics.packetDeliveryRatio,
            latencyMs = metrics.latencyMs,
            packetLossRate = metrics.packetLossRate,
            throughputKbps = metrics.throughputKbps,
            predictedLinkScore = pred.score,
            lastSeenMillis = System.currentTimeMillis()
        )
        peerDao.upsertPeer(updated)

        // Reply with HELLO_ACK so both Group Owner and Client become CONNECTED
        if (!frame.accepted && !updatedEndpointHost.isNullOrBlank()) {
            sendHelloToEndpoint(updatedEndpointHost, updatedEndpointPort, resolvedTransport, isAck = true)
        }
        meshRouter.updateDirectRoutes(local.deviceId, peerDao.getConnectedPeers())
        sendRouteAdvertisementToPeer(updated)
        sendRouteAdvertisementsToAll(excludePeerId = updated.deviceId)
        flushOfflineQueueAndCleanup()

        // If user tapped a Wi-Fi Direct peer to connect & pair, auto-send PAIR_REQUEST once HELLO succeeds
        val autoPairMatched = (!updated.wifiP2pAddress.isNullOrBlank() &&
            pendingAutoPairP2pAddresses.remove(updated.wifiP2pAddress)) ||
            (resolvedTransport == TransportType.WIFI_DIRECT && pendingAutoPairP2pAddresses.isNotEmpty())
        if (autoPairMatched && updated.trustStatus == TrustStatus.DISCOVERED) {
            if (resolvedTransport == TransportType.WIFI_DIRECT && updated.wifiP2pAddress == null) {
                pendingAutoPairP2pAddresses.clear()
            }
            requestPairing(updated.deviceId)
        }
    }

    private suspend fun sendRouteAdvertisementToPeer(neighbor: PeerDeviceEntity) {
        val local = _localIdentity.value ?: return
        if (neighbor.deviceId == local.deviceId || neighbor.trustStatus == TrustStatus.BLOCKED) return
        val allPeersById = peerDao.observeAllPeers().first().associateBy { it.deviceId }
        val entries = meshRouter.buildRouteAdvertisementsForNeighbor(neighbor.deviceId, local, allPeersById)
        if (entries.isEmpty()) return
        dispatchFrameToPeer(
            neighbor,
            WireFrame(
                type = WireFrame.Types.ROUTE_ADV,
                senderId = local.deviceId,
                senderName = local.displayName,
                routes = entries
            )
        )
    }

    private suspend fun sendRouteAdvertisementsToAll(excludePeerId: String? = null) {
        val connected = peerDao.getConnectedPeers()
        for (neighbor in connected) {
            if (neighbor.deviceId == excludePeerId) continue
            sendRouteAdvertisementToPeer(neighbor)
        }
    }

    private suspend fun handleRouteAdvertisement(frame: WireFrame, local: DevicePublicIdentity) {
        val senderPeer = peerDao.getPeerById(frame.senderId)
        if (senderPeer?.trustStatus == TrustStatus.BLOCKED) return
        val peerScore = senderPeer?.predictedLinkScore ?: 0.7f

        for (entry in frame.routes) {
            if (entry.targetDeviceId.isBlank() || entry.targetDeviceId == local.deviceId) continue
            if (entry.hopCount + 1 > MeshRouter.MAX_MESH_HOPS) continue
            val hasKeys = entry.x25519PubB64.isNotBlank() && entry.ed25519PubB64.isNotBlank()
            if (hasKeys && entry.fingerprintHex.isNotBlank()) {
                val expectedFp = IdentityKeyManager.computeFingerprintHex(entry.x25519PubB64, entry.ed25519PubB64)
                if (!expectedFp.equals(entry.fingerprintHex, ignoreCase = true)) continue
            }
            val existing = peerDao.getPeerById(entry.targetDeviceId)
            if (existing == null) {
                peerDao.upsertPeer(
                    PeerDeviceEntity(
                        deviceId = entry.targetDeviceId,
                        displayName = entry.displayName.ifBlank { "Mesh Node" },
                        x25519PublicKeyB64 = entry.x25519PubB64,
                        ed25519PublicKeyB64 = entry.ed25519PubB64,
                        fingerprintHex = entry.fingerprintHex,
                        keyEpoch = entry.keyEpoch,
                        trustStatus = TrustStatus.DISCOVERED,
                        connectionState = ConnectionState.OFFLINE,
                        transportType = TransportType.MESH_RELAY,
                        predictedLinkScore = entry.linkScore,
                        lastSeenMillis = System.currentTimeMillis()
                    )
                )
            } else if (existing.connectionState != ConnectionState.CONNECTED && hasKeys &&
                (existing.ed25519PublicKeyB64.isBlank() || existing.ed25519PublicKeyB64 == entry.ed25519PubB64)
            ) {
                peerDao.upsertPeer(
                    existing.copy(
                        displayName = entry.displayName.ifBlank { existing.displayName },
                        x25519PublicKeyB64 = entry.x25519PubB64,
                        ed25519PublicKeyB64 = entry.ed25519PubB64,
                        fingerprintHex = entry.fingerprintHex.ifBlank { existing.fingerprintHex },
                        keyEpoch = entry.keyEpoch,
                        transportType = if (existing.endpointHost.isNullOrBlank()) TransportType.MESH_RELAY else existing.transportType,
                        lastSeenMillis = System.currentTimeMillis()
                    )
                )
            }
        }

        val topologyChanged = meshRouter.ingestRouteAdvertisement(frame.senderId, peerScore, frame.routes, local.deviceId)
        if (topologyChanged) {
            sendRouteAdvertisementsToAll(excludePeerId = frame.senderId)
            flushOfflineQueueAndCleanup()
        }
    }

    private suspend fun handlePairRequest(frame: WireFrame, remoteAddr: String, transport: String) {
        val body = "PAIR_REQ|${frame.senderId}|${frame.x25519PubB64}|${frame.ed25519PubB64}".toByteArray()
        if (!cryptoEngine.verifyArbitrarySignature(frame.ed25519PubB64, body, frame.signatureB64)) {
            _securityEvents.tryEmit("Rejected forged pairing request from ${frame.senderName}")
            return
        }
        val existing = peerDao.getPeerById(frame.senderId)
        val isRelayed = transport == TransportType.MESH_RELAY || remoteAddr.isBlank()
        val updated = (existing ?: PeerDeviceEntity(deviceId = frame.senderId, displayName = frame.senderName)).copy(
            displayName = frame.senderName.ifBlank { existing?.displayName ?: "Mesh Peer" },
            x25519PublicKeyB64 = frame.x25519PubB64,
            ed25519PublicKeyB64 = frame.ed25519PubB64,
            fingerprintHex = frame.fingerprintHex,
            keyEpoch = frame.keyEpoch,
            trustStatus = when (existing?.trustStatus) {
                TrustStatus.VERIFIED_QR -> TrustStatus.VERIFIED_QR
                TrustStatus.PAIRED_UNVERIFIED -> TrustStatus.PAIRED_UNVERIFIED
                else -> TrustStatus.PENDING_INCOMING
            },
            connectionState = if (isRelayed) (existing?.connectionState ?: ConnectionState.OFFLINE) else ConnectionState.CONNECTED,
            transportType = when {
                isRelayed -> existing?.transportType?.takeIf { !existing.endpointHost.isNullOrBlank() } ?: TransportType.MESH_RELAY
                transport == TransportType.LOCAL_LAN && remoteAddr.startsWith("192.168.49.") -> TransportType.WIFI_DIRECT
                else -> transport
            },
            endpointHost = remoteAddr.ifBlank { existing?.endpointHost },
            endpointPort = if (isRelayed) (existing?.endpointPort ?: LocalWifiLanTransport.DEFAULT_PORT) else (frame.listenPort.takeIf { it > 0 } ?: existing?.endpointPort ?: LocalWifiLanTransport.DEFAULT_PORT),
            lastSeenMillis = System.currentTimeMillis()
        )
        peerDao.upsertPeer(updated)
    }

    private suspend fun handlePairResponse(frame: WireFrame) {
        val peer = peerDao.getPeerById(frame.senderId) ?: return
        val body = "PAIR_RESP|${frame.senderId}|${frame.accepted}".toByteArray()
        if (!cryptoEngine.verifyArbitrarySignature(peer.ed25519PublicKeyB64, body, frame.signatureB64)) {
            _securityEvents.tryEmit("Invalid signature on pairing response")
            return
        }
        val nextTrust = if (frame.accepted) TrustStatus.PAIRED_UNVERIFIED else TrustStatus.DISCOVERED
        peerDao.updateTrustStatus(peer.deviceId, nextTrust)
        if (frame.accepted) ensurePrivateConversation(peer)
    }

    private suspend fun handleChatEnvelope(frame: WireFrame, local: DevicePublicIdentity) {
        val env = frame.envelope ?: return
        val peer = peerDao.getPeerById(env.senderId)
        if (peer == null || peer.trustStatus == TrustStatus.BLOCKED ||
            (peer.trustStatus != TrustStatus.PAIRED_UNVERIFIED && peer.trustStatus != TrustStatus.VERIFIED_QR)
        ) {
            _securityEvents.tryEmit("Rejected encrypted message from unauthorized device ${env.senderId}")
            return
        }

        val nonceKey = "${env.senderId}:${env.nonceB64}"
        val plaintextBytes: ByteArray = chatIngressMutex.withLock {
            // Atomic replay + duplicate message guard across concurrent multi-hop paths
            if (seenNonceDao.exists(nonceKey) || messageDao.getMessageById(env.messageId) != null) {
                return
            }
            val decrypted = runCatching {
                cryptoEngine.decryptMessage(env, peer.x25519PublicKeyB64, peer.ed25519PublicKeyB64)
            }.getOrElse { err ->
                _securityEvents.tryEmit("Decryption/Signature failed for ${peer.displayName}: ${err.message}")
                return
            }
            seenNonceDao.insert(SeenNonceEntity(nonceKey))
            decrypted
        }

        val text = String(plaintextBytes, Charsets.UTF_8)
        val groupId = frame.groupId
        val convId = if (groupId != null) {
            val group = groupDao.getGroupById(groupId)
            if (group == null && frame.isBroadcast) {
                // Reject unjoined broadcast announcements
                _securityEvents.tryEmit("Ignored broadcast from unjoined channel $groupId")
                return
            }
            if (group == null && !frame.isBroadcast) {
                groupDao.upsertGroup(
                    GroupEntity(
                        groupId = groupId,
                        name = frame.groupName ?: "Mesh Group",
                        description = "",
                        adminDeviceId = peer.deviceId,
                        isBroadcastChannel = false,
                        allowMemberBroadcast = true,
                        requireOptIn = false,
                        isOptedIn = true,
                        keyEpoch = 1,
                        wrappedGroupKeyEnc = ""
                    )
                )
                groupDao.upsertGroupMember(GroupMemberEntity(groupId, local.deviceId, local.displayName, "MEMBER", true))
                groupDao.upsertGroupMember(GroupMemberEntity(groupId, peer.deviceId, peer.displayName, "ADMIN", true))
            }
            if (group != null && group.isBroadcastChannel && !group.isOptedIn) {
                return
            }
            "conv:$groupId"
        } else {
            ensurePrivateConversation(peer)
        }

        val msgEntity = MessageEntity(
            messageId = env.messageId,
            conversationId = convId,
            senderId = peer.deviceId,
            senderName = peer.displayName,
            replyToMessageId = frame.replyToId,
            forwardedFrom = frame.forwardedFrom,
            messageType = frame.messageType,
            contentEnc = storageCipher.encryptField(text, "msg:${env.messageId}"),
            status = MessageStatus.DELIVERED,
            hopCount = frame.hopCount.coerceAtLeast(1),
            timestampMillis = env.timestampMillis,
            isOutgoing = false
        )
        messageDao.upsertMessage(msgEntity)
        val existingConv = conversationDao.getConversation(convId)
        conversationDao.upsertConversation(
            ConversationEntity(
                conversationId = convId,
                type = if (frame.isBroadcast) ConversationType.BROADCAST else if (groupId != null) ConversationType.GROUP else ConversationType.PRIVATE,
                title = frame.groupName ?: existingConv?.title ?: peer.displayName,
                peerDeviceId = if (groupId == null) peer.deviceId else null,
                groupId = groupId,
                lastMessagePreviewEnc = storageCipher.encryptField(text, "conv:$convId"),
                lastMessageTimestamp = env.timestampMillis,
                unreadCount = (existingConv?.unreadCount ?: 0) + 1
            )
        )

        // Send DELIVERED ACK (works across direct Wi-Fi or multi-hop relay D -> C -> B -> A)
        val ackSig = cryptoEngine.signArbitraryBytes("ACK|${env.messageId}|DELIVERED".toByteArray())
        dispatchFrameToPeerOrRelay(
            peer,
            WireFrame(
                type = WireFrame.Types.ACK_PACKET,
                senderId = local.deviceId,
                ackMessageId = env.messageId,
                ackStatus = MessageStatus.DELIVERED,
                signatureB64 = ackSig
            ),
            "ack-${env.messageId}"
        )
    }

    private suspend fun handleGroupSync(frame: WireFrame, local: DevicePublicIdentity) {
        val groupId = frame.groupId ?: return
        val peer = peerDao.getPeerById(frame.senderId) ?: return
        if (peer.trustStatus == TrustStatus.BLOCKED ||
            (peer.trustStatus != TrustStatus.PAIRED_UNVERIFIED && peer.trustStatus != TrustStatus.VERIFIED_QR)
        ) return
        val sigPayload = "GRPSYNC|$groupId|${frame.groupAdminId}|${frame.keyEpoch}".toByteArray()
        if (!cryptoEngine.verifyArbitrarySignature(peer.ed25519PublicKeyB64, sigPayload, frame.signatureB64)) return

        val groupName = frame.groupName ?: "Mesh Group"
        groupDao.upsertGroup(
            GroupEntity(
                groupId = groupId,
                name = groupName,
                description = frame.groupDesc,
                adminDeviceId = frame.groupAdminId.ifBlank { peer.deviceId },
                isBroadcastChannel = frame.isBroadcast,
                allowMemberBroadcast = frame.allowMemberBroadcast,
                requireOptIn = frame.isBroadcast,
                isOptedIn = true,
                keyEpoch = frame.keyEpoch,
                wrappedGroupKeyEnc = ""
            )
        )
        frame.groupMemberIds.forEachIndexed { index, memberId ->
            val memberName = frame.groupMemberNames.getOrNull(index)
                ?: peerDao.getPeerById(memberId)?.displayName
                ?: if (memberId == local.deviceId) local.displayName else "Mesh Member"
            val role = if (memberId == frame.groupAdminId) "ADMIN" else if (frame.isBroadcast) "LISTENER" else "MEMBER"
            groupDao.upsertGroupMember(
                GroupMemberEntity(
                    groupId = groupId,
                    deviceId = memberId,
                    displayName = memberName,
                    role = role,
                    canBroadcast = !frame.isBroadcast || frame.allowMemberBroadcast || memberId == frame.groupAdminId
                )
            )
        }
        val convId = "conv:$groupId"
        if (conversationDao.getConversation(convId) == null) {
            conversationDao.upsertConversation(
                ConversationEntity(
                    conversationId = convId,
                    type = if (frame.isBroadcast) ConversationType.BROADCAST else ConversationType.GROUP,
                    title = groupName,
                    groupId = groupId,
                    lastMessagePreviewEnc = storageCipher.encryptField(
                        if (frame.isBroadcast) "Invited to broadcast channel" else "Added to encrypted group",
                        "conv:$convId"
                    )
                )
            )
        }
    }

    private suspend fun handleAck(frame: WireFrame) {
        val msgId = frame.ackMessageId ?: return
        val status = frame.ackStatus ?: return
        val baseMsgId = msgId.substringBefore(":")
        messageDao.updateMessageStatus(baseMsgId, status)
        groupDao.updateRecipientStatus(baseMsgId, frame.senderId, status)
    }

    private suspend fun handleMeshRelay(frame: WireFrame, local: DevicePublicIdentity) {
        val settings = preferences.settingsFlow.first()
        when (meshRouter.decideIncomingRelay(local.deviceId, frame, settings.allowMeshRelay)) {
            RelayDecision.DELIVER_LOCALLY -> {
                val inner = frame.innerPayloadJson ?: return
                val innerFrame = runCatching { json.decodeFromString<WireFrame>(inner) }.getOrNull() ?: return
                // Preserve observed hop count for UI diagnostics
                val updatedInner = if (innerFrame.hopCount < frame.hopCount + 1) {
                    innerFrame.copy(hopCount = frame.hopCount + 1)
                } else {
                    innerFrame
                }
                handleIncomingRawFrame(json.encodeToString(updatedInner), "", TransportType.MESH_RELAY)
            }
            RelayDecision.FORWARD_TO_NEXT_HOP -> {
                val forwarded = frame.copy(
                    hopCount = frame.hopCount + 1,
                    visitedPath = frame.visitedPath + local.deviceId
                )
                val route = meshRouter.selectBestNextHop(frame.targetDeviceId)
                val primaryNext = route?.let { peerDao.getPeerById(it.nextHopDeviceId) }
                var relayed = primaryNext != null && dispatchFrameToPeer(primaryNext, forwarded)
                if (!relayed) {
                    val candidates = peerDao.getConnectedPeers().filter {
                        it.deviceId !in forwarded.visitedPath &&
                            it.deviceId != forwarded.originDeviceId &&
                            it.deviceId != route?.nextHopDeviceId
                    }
                    for (candidate in candidates) {
                        if (dispatchFrameToPeer(candidate, forwarded)) {
                            relayed = true
                        }
                    }
                }
                if (relayed) {
                    _relayedPacketCount.value = _relayedPacketCount.value + 1
                } else {
                    meshRouter.enqueueStoreAndForward(
                        packetId = forwarded.packetId,
                        targetDeviceId = forwarded.targetDeviceId,
                        originDeviceId = forwarded.originDeviceId,
                        packetType = WireFrame.Types.MESH_RELAY,
                        payloadJson = json.encodeToString(forwarded),
                        hopCount = forwarded.hopCount,
                        maxHops = forwarded.maxHops,
                        ttlExpiresAt = forwarded.ttlExpiresAt
                    )
                }
            }
            RelayDecision.QUEUE_STORE_AND_FORWARD -> {
                val forwarded = frame.copy(
                    hopCount = frame.hopCount + 1,
                    visitedPath = frame.visitedPath + local.deviceId
                )
                // Controlled blind flood to connected neighbors not yet visited so range extends even before route convergence
                val candidates = peerDao.getConnectedPeers().filter {
                    it.deviceId !in forwarded.visitedPath &&
                        it.deviceId != forwarded.originDeviceId &&
                        !it.endpointHost.isNullOrBlank()
                }
                var relayed = false
                for (candidate in candidates) {
                    if (dispatchFrameToPeer(candidate, forwarded)) {
                        relayed = true
                    }
                }
                if (relayed) {
                    _relayedPacketCount.value = _relayedPacketCount.value + 1
                } else {
                    meshRouter.enqueueStoreAndForward(
                        packetId = forwarded.packetId,
                        targetDeviceId = forwarded.targetDeviceId,
                        originDeviceId = forwarded.originDeviceId,
                        packetType = WireFrame.Types.MESH_RELAY,
                        payloadJson = json.encodeToString(forwarded),
                        hopCount = forwarded.hopCount,
                        maxHops = forwarded.maxHops,
                        ttlExpiresAt = forwarded.ttlExpiresAt
                    )
                }
            }
            else -> Unit
        }
    }

    private suspend fun handleIncomingFileOffer(frame: WireFrame, local: DevicePublicIdentity) {
        val peer = peerDao.getPeerById(frame.senderId) ?: return
        if (peer.trustStatus == TrustStatus.BLOCKED) return

        val sigValid = cryptoEngine.verifyFileManifestSignature(
            senderEd25519PubB64 = peer.ed25519PublicKeyB64,
            signatureB64 = frame.manifestSigB64,
            transferId = frame.transferId,
            senderId = frame.senderId,
            recipientId = local.deviceId,
            fileName = frame.fileName,
            fileSize = frame.fileSize,
            sha256Hex = frame.sha256Hex
        )
        if (!sigValid) {
            _securityEvents.tryEmit("Rejected file offer with invalid Ed25519 signature from ${peer.displayName}")
            return
        }

        transferHopCounts[frame.transferId] = frame.hopCount.coerceAtLeast(1)
        val settings = preferences.settingsFlow.first()
        val initialState = if (settings.requireFileAcceptancePrompt) {
            TransferState.PENDING_ACCEPT
        } else {
            TransferState.IN_PROGRESS
        }

        val tempDir = File(context.cacheDir, "rx_tmp").apply { mkdirs() }
        val tmpFile = File(tempDir, "${frame.transferId}.part")
        val cryptoMeta = FileCryptoMetadata(
            ephemeralX25519PubB64 = frame.ephemeralX25519PubB64,
            wrappedDekB64 = frame.wrappedDekB64,
            baseNonceB64 = frame.baseNonceB64,
            senderX25519PubB64 = peer.x25519PublicKeyB64,
            senderEd25519PubB64 = peer.ed25519PublicKeyB64,
            manifestSigB64 = frame.manifestSigB64
        )
        val convId = if (frame.conversationId.startsWith("conv:") &&
            groupDao.getGroupById(frame.conversationId.removePrefix("conv:")) != null
        ) {
            frame.conversationId
        } else {
            ensurePrivateConversation(peer)
        }
        transferDao.upsertTransfer(
            TransferRecordEntity(
                transferId = frame.transferId,
                peerDeviceId = peer.deviceId,
                peerName = peer.displayName,
                conversationId = convId,
                fileName = frame.fileName,
                mimeType = frame.mimeType,
                fileSize = frame.fileSize,
                sha256Hex = frame.sha256Hex,
                direction = "INCOMING",
                state = initialState,
                totalChunks = frame.totalChunks,
                tempFilePath = tmpFile.absolutePath,
                cryptoHeaderJson = json.encodeToString(cryptoMeta)
            )
        )
        incomingFileChunks.getOrPut(frame.transferId) { ConcurrentHashMap() }
        if (initialState == TransferState.PENDING_ACCEPT) {
            _securityEvents.tryEmit("Incoming file from ${peer.displayName}: ${frame.fileName} (open Files to accept)")
        } else if (completedFileTransfers[frame.transferId] == true) {
            tryAssembleBufferedChunks(frame.transferId)
        }
    }

    private suspend fun handleIncomingFileChunk(frame: WireFrame) {
        val bytes = Base64.decode(frame.encryptedChunkB64, Base64.NO_WRAP)
        val bucket = incomingFileChunks.getOrPut(frame.transferId) { ConcurrentHashMap() }
        bucket[frame.chunkIndex] = bytes
        val rec = transferDao.getTransfer(frame.transferId) ?: return
        if (rec.state == TransferState.REJECTED || rec.state == TransferState.PAUSED) return
        val approxBytes = (bucket.size.toLong() * E2eeCryptoEngine.DEFAULT_CHUNK_SIZE).coerceAtMost(rec.fileSize)
        if (rec.state == TransferState.IN_PROGRESS) {
            transferDao.updateProgress(rec.transferId, TransferState.IN_PROGRESS, approxBytes, bucket.size)
            if (completedFileTransfers[frame.transferId] == true && bucket.size >= rec.totalChunks) {
                tryAssembleBufferedChunks(frame.transferId)
            }
        }
    }

    private suspend fun handleIncomingFileComplete(frame: WireFrame, local: DevicePublicIdentity) {
        completedFileTransfers[frame.transferId] = true
        tryAssembleBufferedChunks(frame.transferId)
    }

    private suspend fun handleFileResponse(frame: WireFrame) {
        val rec = transferDao.getTransfer(frame.transferId) ?: return
        if (!frame.accepted) {
            pausedTransfers[frame.transferId] = true
            transferDao.updateProgress(frame.transferId, TransferState.REJECTED, rec.bytesTransferred, rec.chunkIndex)
            _securityEvents.tryEmit("${rec.peerName} rejected file ${rec.fileName}")
        } else if (rec.state == TransferState.PAUSED) {
            resumeTransfer(frame.transferId)
        }
    }

    private suspend fun tryAssembleBufferedChunks(transferId: String) {
        val lock = fileAssemblyLocks.getOrPut(transferId) { Mutex() }
        lock.withLock {
            val rec = transferDao.getTransfer(transferId) ?: return
            if (rec.state != TransferState.IN_PROGRESS) return
            val local = _localIdentity.value ?: return
            val bucket = incomingFileChunks[transferId] ?: return
            if (rec.totalChunks > 0 && (0 until rec.totalChunks).any { !bucket.containsKey(it) }) return

            val meta = runCatching { json.decodeFromString<FileCryptoMetadata>(rec.cryptoHeaderJson) }.getOrNull() ?: return
            val fek = runCatching {
                cryptoEngine.unwrapFileEncryptionKey(
                    transferId = transferId,
                    senderId = rec.peerDeviceId,
                    recipientId = local.deviceId,
                    senderX25519PubB64 = meta.senderX25519PubB64,
                    ephemeralX25519PubB64 = meta.ephemeralX25519PubB64,
                    wrappedDekB64 = meta.wrappedDekB64,
                    baseNonceB64 = meta.baseNonceB64
                )
            }.getOrElse {
                transferDao.updateProgress(transferId, TransferState.FAILED, 0L, 0)
                incomingFileChunks.remove(transferId)
                completedFileTransfers.remove(transferId)
                fileAssemblyLocks.remove(transferId)
                _securityEvents.tryEmit("Failed to unwrap file key for ${rec.fileName}")
                return
            }

            val baseNonce = Base64.decode(meta.baseNonceB64, Base64.NO_WRAP)
            val receivedDir = File(context.filesDir, "received").apply { mkdirs() }
            val safeName = rec.fileName.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val destFile = File(receivedDir, "${transferId.take(8)}_$safeName")
            val digest = MessageDigest.getInstance("SHA-256")

            val decryptOk = runCatching {
                FileOutputStream(destFile).use { fos ->
                    for (i in 0 until rec.totalChunks) {
                        val enc = bucket[i] ?: error("Missing chunk $i")
                        val plain = cryptoEngine.decryptFileChunk(fek, baseNonce, transferId, i, enc)
                        digest.update(plain)
                        fos.write(plain)
                    }
                }
                true
            }.getOrDefault(false)
            fek.fill(0)
            incomingFileChunks.remove(transferId)
            completedFileTransfers.remove(transferId)

            val actualSha = digest.digest().joinToString("") { "%02x".format(it) }
            if (!decryptOk || !actualSha.equals(rec.sha256Hex, ignoreCase = true)) {
                destFile.delete()
                transferDao.updateProgress(transferId, TransferState.FAILED, 0L, 0)
                fileAssemblyLocks.remove(transferId)
                _securityEvents.tryEmit("SHA-256 integrity or GCM authentication failed for ${rec.fileName}")
                return
            }

            rec.tempFilePath?.let { File(it).delete() }
            transferDao.upsertTransfer(
                rec.copy(
                    state = TransferState.COMPLETED,
                    bytesTransferred = rec.fileSize,
                    chunkIndex = rec.totalChunks,
                    localUriOrPath = destFile.absolutePath,
                    updatedAtMillis = System.currentTimeMillis()
                )
            )

            val msgId = "rxfile-$transferId"
            val rxHopCount = transferHopCounts.remove(transferId) ?: 1
            messageDao.upsertMessage(
                MessageEntity(
                    messageId = msgId,
                    conversationId = rec.conversationId,
                    senderId = rec.peerDeviceId,
                    senderName = rec.peerName,
                    messageType = classifyMime(rec.mimeType),
                    contentEnc = storageCipher.encryptField("Received verified file: ${rec.fileName}", "msg:$msgId"),
                    attachmentPath = destFile.absolutePath,
                    attachmentName = rec.fileName,
                    attachmentMimeType = rec.mimeType,
                    attachmentSize = rec.fileSize,
                    attachmentSha256 = rec.sha256Hex,
                    status = MessageStatus.DELIVERED,
                    hopCount = rxHopCount,
                    isOutgoing = false
                )
            )
            val existingConv = conversationDao.getConversation(rec.conversationId)
            val isGroupConv = rec.conversationId.startsWith("conv:")
            val groupId = if (isGroupConv) rec.conversationId.removePrefix("conv:") else null
            conversationDao.upsertConversation(
                ConversationEntity(
                    conversationId = rec.conversationId,
                    type = if (isGroupConv) ConversationType.GROUP else ConversationType.PRIVATE,
                    title = existingConv?.title ?: rec.peerName,
                    peerDeviceId = if (isGroupConv) null else rec.peerDeviceId,
                    groupId = groupId,
                    lastMessagePreviewEnc = storageCipher.encryptField("File: ${rec.fileName}", "conv:${rec.conversationId}"),
                    lastMessageTimestamp = System.currentTimeMillis(),
                    unreadCount = (existingConv?.unreadCount ?: 0) + 1
                )
            )
            fileAssemblyLocks.remove(transferId)

            // Send DELIVERED ACK back to sender so sender sees double-tick for audio/image/video/file
            runCatching {
                val senderPeer = peerDao.getPeerById(rec.peerDeviceId)
                if (senderPeer != null) {
                    val ackMsgId = "fmsg-$transferId"
                    val ackSig = cryptoEngine.signArbitraryBytes("ACK|$ackMsgId|DELIVERED".toByteArray())
                    dispatchFrameToPeerOrRelay(
                        senderPeer,
                        WireFrame(
                            type = WireFrame.Types.ACK_PACKET,
                            senderId = local.deviceId,
                            ackMessageId = ackMsgId,
                            ackStatus = MessageStatus.DELIVERED,
                            signatureB64 = ackSig
                        ),
                        "ack-$ackMsgId"
                    )
                }
            }
        }
    }

    private suspend fun dispatchFrameToPeer(peer: PeerDeviceEntity, frame: WireFrame): Boolean {
        val raw = json.encodeToString(frame)
        val host = peer.endpointHost
        if (!host.isNullOrBlank()) {
            val port = peer.endpointPort.takeIf { it in 1..65535 } ?: LocalWifiLanTransport.DEFAULT_PORT
            val res = lanTransport.sendFrame(host, port, raw)
            if (res.isSuccess) {
                directFailCounts.remove(peer.deviceId)
                return true
            }
            val fails = (directFailCounts[peer.deviceId] ?: 0) + 1
            directFailCounts[peer.deviceId] = fails
            if (fails >= 2 && peer.connectionState == ConnectionState.CONNECTED) {
                peerDao.updateConnectionState(peer.deviceId, ConnectionState.OFFLINE)
                meshRouter.markDirectPeerOffline(peer.deviceId)
            }
        }
        return false
    }

    private suspend fun dispatchFrameToPeerOrRelay(
        peer: PeerDeviceEntity,
        frame: WireFrame,
        packetId: String
    ): Boolean {
        if (dispatchFrameToPeer(peer, frame)) return true

        val local = _localIdentity.value ?: return false
        val relayFrame = WireFrame(
            type = WireFrame.Types.MESH_RELAY,
            senderId = local.deviceId,
            packetId = packetId,
            originDeviceId = local.deviceId,
            targetDeviceId = peer.deviceId,
            hopCount = 0,
            maxHops = MeshRouter.MAX_MESH_HOPS,
            ttlExpiresAt = System.currentTimeMillis() + 24 * 60 * 60 * 1000L,
            visitedPath = listOf(local.deviceId),
            innerPayloadJson = json.encodeToString(frame)
        )

        val route = meshRouter.selectBestNextHop(peer.deviceId)
        if (route != null && route.nextHopDeviceId != peer.deviceId) {
            val nextPeer = peerDao.getPeerById(route.nextHopDeviceId)
            if (nextPeer != null && dispatchFrameToPeer(nextPeer, relayFrame)) {
                return true
            }
        }

        // Controlled neighbor fallback if best route isn't converged yet
        val connectedNeighbors = peerDao.getConnectedPeers().filter {
            it.deviceId != peer.deviceId && it.deviceId != local.deviceId && !it.endpointHost.isNullOrBlank()
        }
        var forwardedAny = false
        for (neighbor in connectedNeighbors) {
            if (dispatchFrameToPeer(neighbor, relayFrame)) {
                forwardedAny = true
            }
        }
        if (forwardedAny) return true

        meshRouter.enqueueStoreAndForward(
            packetId = packetId,
            targetDeviceId = peer.deviceId,
            originDeviceId = local.deviceId,
            packetType = WireFrame.Types.MESH_RELAY,
            payloadJson = json.encodeToString(relayFrame),
            hopCount = 0,
            maxHops = MeshRouter.MAX_MESH_HOPS,
            ttlExpiresAt = relayFrame.ttlExpiresAt
        )
        return false
    }

    suspend fun flushOfflineQueueAndCleanup() = withContext(Dispatchers.IO) {
        meshRouter.purgeExpiredPackets()
        seenNonceDao.pruneOlderThan(System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000L)
        val activePackets = pendingRelayDao.getActivePendingPackets()
        for (pkt in activePackets) {
            val frame = runCatching { json.decodeFromString<WireFrame>(pkt.payloadJson) }.getOrNull() ?: continue
            val targetPeer = peerDao.getPeerById(pkt.targetDeviceId)
            val route = meshRouter.selectBestNextHop(pkt.targetDeviceId)
            val hasDirectEndpoint = targetPeer != null &&
                targetPeer.trustStatus != TrustStatus.BLOCKED &&
                !targetPeer.endpointHost.isNullOrBlank()
            val nextPeer = when {
                hasDirectEndpoint -> targetPeer
                route != null -> peerDao.getPeerById(route.nextHopDeviceId)
                else -> null
            }

            if (nextPeer != null && dispatchFrameToPeer(nextPeer, frame)) {
                pendingRelayDao.deletePacket(pkt.packetId)
                messageDao.updateMessageStatus(pkt.packetId.substringBefore(":"), MessageStatus.SENT)
                continue
            }

            // Fallback: relay to newly connected neighbor not yet on visitedPath
            val neighbors = peerDao.getConnectedPeers().filter {
                it.deviceId !in frame.visitedPath &&
                    it.deviceId != frame.originDeviceId &&
                    !it.endpointHost.isNullOrBlank()
            }
            var sentToAny = false
            for (neighbor in neighbors) {
                if (dispatchFrameToPeer(neighbor, frame)) {
                    sentToAny = true
                }
            }
            if (sentToAny) {
                pendingRelayDao.deletePacket(pkt.packetId)
                messageDao.updateMessageStatus(pkt.packetId.substringBefore(":"), MessageStatus.SENT)
            } else {
                pendingRelayDao.incrementRetry(pkt.packetId)
            }
        }
    }

    suspend fun secureWipeEverything() = withContext(Dispatchers.IO) {
        meshHeartbeatJob?.cancel()
        meshHeartbeatJob = null
        stopAllDiscovery()
        apkShareServer.stop()
        lanTransport.stop()
        listenersStarted = false
        storageCipher.clearCachedKey()
        identityKeyManager.secureWipeAllKeys()
        peerDao.clearAll()
        conversationDao.clearAll()
        messageDao.clearAll()
        groupDao.clearGroups()
        groupDao.clearMembers()
        transferDao.clearAll()
        pendingRelayDao.clearAll()
        seenNonceDao.clearAll()
        preferences.clearAll()
        File(context.filesDir, "received").deleteRecursively()
        File(context.filesDir, "voice").deleteRecursively()
        File(context.cacheDir, "rx_tmp").deleteRecursively()
        _localIdentity.value = null
        _securityEvents.tryEmit("All cryptographic keys and local records securely wiped")
    }

    suspend fun setThemeMode(mode: ThemeMode) = preferences.setThemeMode(mode)
    suspend fun setAllowMeshRelay(enabled: Boolean) = preferences.setAllowMeshRelay(enabled)
    suspend fun setRequireFileAcceptancePrompt(required: Boolean) = preferences.setRequireFileAcceptancePrompt(required)
    suspend fun setSessionExpiryHours(hours: Int) = preferences.setSessionExpiryHours(hours)
    suspend fun setMlPredictorEnabled(enabled: Boolean) = preferences.setMlPredictorEnabled(enabled)

    fun evaluateMetrics(metrics: WirelessLinkMetrics): LinkPredictionResult =
        linkPredictor.predict(metrics)

    private fun hasEnoughStorage(requiredBytes: Long): Boolean {
        val stat = StatFs(context.filesDir.absolutePath)
        return stat.availableBytes > requiredBytes
    }

    private fun queryUriMeta(uri: Uri): Triple<String, String, Long> {
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "shared_file"
        var size = 0L
        if (uri.scheme == "content") {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst()) {
                    if (nameIdx >= 0) name = cursor.getString(nameIdx) ?: name
                    if (sizeIdx >= 0) size = cursor.getLong(sizeIdx)
                }
            }
        } else if (uri.scheme == "file" && uri.path != null) {
            val f = File(uri.path!!)
            name = f.name
            size = f.length()
        }
        val mime = context.contentResolver.getType(uri) ?: guessMimeFromName(name)
        return Triple(name, mime, size)
    }

    private fun copyUriToReceivedDir(uri: Uri, name: String): File {
        val dir = File(context.filesDir, "received").apply { mkdirs() }
        val safe = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val out = File(dir, "${UUID.randomUUID().toString().take(8)}_$safe")
        val ins = context.contentResolver.openInputStream(uri) ?: FileInputStream(File(uri.path!!))
        ins.use { i -> FileOutputStream(out).use { o -> i.copyTo(o) } }
        return out
    }

    private fun guessMimeFromName(name: String): String = when (name.substringAfterLast('.', "").lowercase()) {
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "webp" -> "image/webp"
        "mp4", "mkv" -> "video/mp4"
        "m4a", "mp3", "wav", "ogg" -> "audio/mp4"
        "pdf" -> "application/pdf"
        "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        "xlsx" -> "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        "zip" -> "application/zip"
        else -> "application/octet-stream"
    }

    private fun classifyMime(mime: String): String = when {
        mime.startsWith("image/") -> MessageType.IMAGE
        mime.startsWith("video/") -> MessageType.VIDEO
        mime.startsWith("audio/") -> MessageType.AUDIO
        else -> MessageType.DOCUMENT
    }

    companion object {
        private const val MAX_FILE_SIZE_BYTES = 2L * 1024L * 1024L * 1024L
    }
}
