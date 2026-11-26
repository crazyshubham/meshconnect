package com.example.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

object TrustStatus {
    const val DISCOVERED = "DISCOVERED"
    const val PENDING_INCOMING = "PENDING_INCOMING"
    const val PENDING_OUTGOING = "PENDING_OUTGOING"
    const val PAIRED_UNVERIFIED = "PAIRED_UNVERIFIED"
    const val VERIFIED_QR = "VERIFIED_QR"
    const val BLOCKED = "BLOCKED"
}

object ConnectionState {
    const val OFFLINE = "OFFLINE"
    const val CONNECTING = "CONNECTING"
    const val CONNECTED = "CONNECTED"
}

object TransportType {
    const val NONE = "NONE"
    const val WIFI_DIRECT = "WIFI_DIRECT"
    const val BLE = "BLE"
    const val WIFI_AWARE = "WIFI_AWARE"
    const val LOCAL_LAN = "LOCAL_LAN"
    const val MESH_RELAY = "MESH_RELAY"
}

object ConversationType {
    const val PRIVATE = "PRIVATE"
    const val GROUP = "GROUP"
    const val BROADCAST = "BROADCAST"
}

object MessageType {
    const val TEXT = "TEXT"
    const val VOICE = "VOICE"
    const val IMAGE = "IMAGE"
    const val VIDEO = "VIDEO"
    const val DOCUMENT = "DOCUMENT"
    const val AUDIO = "AUDIO"
}

object MessageStatus {
    const val QUEUED = "QUEUED"
    const val SENDING = "SENDING"
    const val SENT = "SENT"
    const val DELIVERED = "DELIVERED"
    const val READ = "READ"
    const val FAILED = "FAILED"
}

object TransferState {
    const val PENDING_ACCEPT = "PENDING_ACCEPT"
    const val IN_PROGRESS = "IN_PROGRESS"
    const val PAUSED = "PAUSED"
    const val COMPLETED = "COMPLETED"
    const val FAILED = "FAILED"
    const val REJECTED = "REJECTED"
}

@Entity(tableName = "peer_devices")
data class PeerDeviceEntity(
    @PrimaryKey val deviceId: String,
    val displayName: String,
    val x25519PublicKeyB64: String = "",
    val ed25519PublicKeyB64: String = "",
    val fingerprintHex: String = "",
    val keyEpoch: Int = 1,
    val trustStatus: String = TrustStatus.DISCOVERED,
    val connectionState: String = ConnectionState.OFFLINE,
    val transportType: String = TransportType.NONE,
    val hopCount: Int = 1,
    val viaDeviceId: String? = null,
    val rssiDbm: Int = -72,
    val packetDeliveryRatio: Float = 0.92f,
    val latencyMs: Int = 45,
    val packetLossRate: Float = 0.04f,
    val throughputKbps: Int = 4200,
    val predictedLinkScore: Float = 0.0f,
    val endpointHost: String? = null,
    val endpointPort: Int = 45455,
    val wifiP2pAddress: String? = null,
    val bleAddress: String? = null,
    val lastSeenMillis: Long = System.currentTimeMillis()
)

@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey val conversationId: String,
    val type: String,
    val title: String,
    val peerDeviceId: String? = null,
    val groupId: String? = null,
    val lastMessagePreviewEnc: String = "",
    val lastMessageTimestamp: Long = System.currentTimeMillis(),
    val unreadCount: Int = 0
)

@Entity(tableName = "messages")
data class MessageEntity(
    @PrimaryKey val messageId: String,
    val conversationId: String,
    val senderId: String,
    val senderName: String,
    val replyToMessageId: String? = null,
    val replyToPreviewEnc: String? = null,
    val forwardedFrom: String? = null,
    val messageType: String = MessageType.TEXT,
    val contentEnc: String = "",
    val attachmentPath: String? = null,
    val attachmentName: String? = null,
    val attachmentMimeType: String? = null,
    val attachmentSize: Long = 0L,
    val attachmentSha256: String? = null,
    val status: String = MessageStatus.QUEUED,
    val hopCount: Int = 1,
    val ttlExpiresAt: Long = System.currentTimeMillis() + 86_400_000L,
    val timestampMillis: Long = System.currentTimeMillis(),
    val isOutgoing: Boolean = true
)

@Entity(tableName = "groups")
data class GroupEntity(
    @PrimaryKey val groupId: String,
    val name: String,
    val description: String = "",
    val adminDeviceId: String,
    val isBroadcastChannel: Boolean = false,
    val allowMemberBroadcast: Boolean = false,
    val requireOptIn: Boolean = true,
    val isOptedIn: Boolean = true,
    val keyEpoch: Int = 1,
    val wrappedGroupKeyEnc: String = "",
    val createdAtMillis: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "group_members",
    primaryKeys = ["groupId", "deviceId"]
)
data class GroupMemberEntity(
    val groupId: String,
    val deviceId: String,
    val displayName: String,
    val role: String = "MEMBER",
    val canBroadcast: Boolean = true,
    val joinedAtMillis: Long = System.currentTimeMillis()
)

@Entity(
    tableName = "message_recipient_status",
    primaryKeys = ["messageId", "recipientDeviceId"]
)
data class MessageRecipientStatusEntity(
    val messageId: String,
    val recipientDeviceId: String,
    val recipientName: String,
    val status: String = MessageStatus.QUEUED,
    val updatedAtMillis: Long = System.currentTimeMillis()
)

@Entity(tableName = "transfer_records")
data class TransferRecordEntity(
    @PrimaryKey val transferId: String,
    val peerDeviceId: String,
    val peerName: String,
    val conversationId: String,
    val fileName: String,
    val mimeType: String,
    val fileSize: Long,
    val sha256Hex: String,
    val direction: String, // OUTGOING or INCOMING
    val state: String,
    val bytesTransferred: Long = 0L,
    val chunkIndex: Int = 0,
    val totalChunks: Int = 1,
    val localUriOrPath: String? = null,
    val tempFilePath: String? = null,
    val cryptoHeaderJson: String = "",
    val createdAtMillis: Long = System.currentTimeMillis(),
    val updatedAtMillis: Long = System.currentTimeMillis()
)

@Entity(tableName = "pending_relay_packets")
data class PendingRelayPacketEntity(
    @PrimaryKey val packetId: String,
    val targetDeviceId: String,
    val originDeviceId: String,
    val packetType: String,
    val payloadJson: String,
    val hopCount: Int = 0,
    val maxHops: Int = 4,
    val ttlExpiresAt: Long,
    val retryCount: Int = 0,
    val createdAtMillis: Long = System.currentTimeMillis()
)

@Entity(tableName = "seen_nonces")
data class SeenNonceEntity(
    @PrimaryKey val nonceKey: String,
    val receivedAtMillis: Long = System.currentTimeMillis()
)
