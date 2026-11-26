package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface PeerDeviceDao {
    @Query("SELECT * FROM peer_devices ORDER BY CASE WHEN connectionState = 'CONNECTED' THEN 0 ELSE 1 END, lastSeenMillis DESC")
    fun observeAllPeers(): Flow<List<PeerDeviceEntity>>

    @Query("SELECT * FROM peer_devices WHERE trustStatus IN ('PAIRED_UNVERIFIED', 'VERIFIED_QR') ORDER BY displayName ASC")
    fun observeTrustedPeers(): Flow<List<PeerDeviceEntity>>

    @Query("SELECT * FROM peer_devices WHERE deviceId = :deviceId LIMIT 1")
    suspend fun getPeerById(deviceId: String): PeerDeviceEntity?

    @Query("SELECT * FROM peer_devices WHERE connectionState = 'CONNECTED' AND trustStatus != 'BLOCKED'")
    suspend fun getConnectedPeers(): List<PeerDeviceEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPeer(peer: PeerDeviceEntity)

    @Query("UPDATE peer_devices SET connectionState = :state, lastSeenMillis = :ts WHERE deviceId = :deviceId")
    suspend fun updateConnectionState(deviceId: String, state: String, ts: Long = System.currentTimeMillis())

    @Query("UPDATE peer_devices SET trustStatus = :trustStatus WHERE deviceId = :deviceId")
    suspend fun updateTrustStatus(deviceId: String, trustStatus: String)

    @Query("DELETE FROM peer_devices WHERE deviceId = :deviceId")
    suspend fun deletePeer(deviceId: String)

    @Query("DELETE FROM peer_devices")
    suspend fun clearAll()
}

@Dao
interface ConversationDao {
    @Query("SELECT * FROM conversations ORDER BY lastMessageTimestamp DESC")
    fun observeConversations(): Flow<List<ConversationEntity>>

    @Query("SELECT * FROM conversations WHERE conversationId = :id LIMIT 1")
    suspend fun getConversation(id: String): ConversationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertConversation(conversation: ConversationEntity)

    @Query("UPDATE conversations SET unreadCount = 0 WHERE conversationId = :id")
    suspend fun markConversationRead(id: String)

    @Query("DELETE FROM conversations WHERE conversationId = :id")
    suspend fun deleteConversation(id: String)

    @Query("DELETE FROM conversations")
    suspend fun clearAll()
}

@Dao
interface MessageDao {
    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestampMillis ASC")
    fun observeMessages(conversationId: String): Flow<List<MessageEntity>>

    @Query("SELECT * FROM messages WHERE messageId = :messageId LIMIT 1")
    suspend fun getMessageById(messageId: String): MessageEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMessage(message: MessageEntity)

    @Query("UPDATE messages SET status = :status WHERE messageId = :messageId")
    suspend fun updateMessageStatus(messageId: String, status: String)

    @Query("UPDATE messages SET status = :status WHERE messageId = :messageId AND status NOT IN ('DELIVERED', 'READ')")
    suspend fun updateStatusIfNotDelivered(messageId: String, status: String)

    @Query("DELETE FROM messages WHERE messageId = :messageId")
    suspend fun deleteMessage(messageId: String)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId")
    suspend fun deleteMessagesForConversation(conversationId: String)

    @Query("DELETE FROM messages")
    suspend fun clearAll()
}

@Dao
interface GroupDao {
    @Query("SELECT * FROM groups ORDER BY createdAtMillis DESC")
    fun observeGroups(): Flow<List<GroupEntity>>

    @Query("SELECT * FROM groups WHERE groupId = :groupId LIMIT 1")
    suspend fun getGroupById(groupId: String): GroupEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertGroup(group: GroupEntity)

    @Query("SELECT * FROM group_members WHERE groupId = :groupId ORDER BY joinedAtMillis ASC")
    fun observeGroupMembers(groupId: String): Flow<List<GroupMemberEntity>>

    @Query("SELECT * FROM group_members WHERE groupId = :groupId")
    suspend fun getGroupMembers(groupId: String): List<GroupMemberEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertGroupMember(member: GroupMemberEntity)

    @Query("DELETE FROM group_members WHERE groupId = :groupId AND deviceId = :deviceId")
    suspend fun removeGroupMember(groupId: String, deviceId: String)

    @Query("UPDATE groups SET isOptedIn = :optedIn WHERE groupId = :groupId")
    suspend fun updateGroupOptIn(groupId: String, optedIn: Boolean)

    @Query("SELECT * FROM message_recipient_status WHERE messageId = :messageId")
    fun observeRecipientStatuses(messageId: String): Flow<List<MessageRecipientStatusEntity>>

    @Query("SELECT * FROM message_recipient_status WHERE messageId IN (SELECT messageId FROM messages WHERE conversationId = :conversationId)")
    fun observeRecipientStatusesForConversation(conversationId: String): Flow<List<MessageRecipientStatusEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRecipientStatus(status: MessageRecipientStatusEntity)

    @Query("UPDATE message_recipient_status SET status = :status, updatedAtMillis = :ts WHERE messageId = :messageId AND recipientDeviceId = :recipientId")
    suspend fun updateRecipientStatus(messageId: String, recipientId: String, status: String, ts: Long = System.currentTimeMillis())

    @Query("DELETE FROM groups")
    suspend fun clearGroups()

    @Query("DELETE FROM group_members")
    suspend fun clearMembers()
}

@Dao
interface TransferRecordDao {
    @Query("SELECT * FROM transfer_records ORDER BY updatedAtMillis DESC")
    fun observeAllTransfers(): Flow<List<TransferRecordEntity>>

    @Query("SELECT * FROM transfer_records WHERE transferId = :transferId LIMIT 1")
    suspend fun getTransfer(transferId: String): TransferRecordEntity?

    @Query("SELECT * FROM transfer_records WHERE sha256Hex = :sha256 AND state = 'COMPLETED' LIMIT 1")
    suspend fun findCompletedBySha256(sha256: String): TransferRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTransfer(record: TransferRecordEntity)

    @Query("UPDATE transfer_records SET state = :state, bytesTransferred = :bytes, chunkIndex = :chunkIdx, updatedAtMillis = :ts WHERE transferId = :transferId")
    suspend fun updateProgress(
        transferId: String,
        state: String,
        bytes: Long,
        chunkIdx: Int,
        ts: Long = System.currentTimeMillis()
    )

    @Query("DELETE FROM transfer_records")
    suspend fun clearAll()
}

@Dao
interface PendingRelayDao {
    @Query("SELECT * FROM pending_relay_packets ORDER BY createdAtMillis ASC")
    fun observePendingPackets(): Flow<List<PendingRelayPacketEntity>>

    @Query("SELECT * FROM pending_relay_packets WHERE ttlExpiresAt > :now ORDER BY createdAtMillis ASC")
    suspend fun getActivePendingPackets(now: Long = System.currentTimeMillis()): List<PendingRelayPacketEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertPacket(packet: PendingRelayPacketEntity): Long

    @Query("UPDATE pending_relay_packets SET retryCount = retryCount + 1 WHERE packetId = :packetId")
    suspend fun incrementRetry(packetId: String)

    @Query("DELETE FROM pending_relay_packets WHERE packetId = :packetId")
    suspend fun deletePacket(packetId: String)

    @Query("DELETE FROM pending_relay_packets WHERE ttlExpiresAt <= :now")
    suspend fun purgeExpired(now: Long = System.currentTimeMillis())

    @Query("DELETE FROM pending_relay_packets WHERE targetDeviceId = :deviceId OR originDeviceId = :deviceId")
    suspend fun deletePacketsForTarget(deviceId: String)

    @Query("DELETE FROM pending_relay_packets")
    suspend fun clearAll()
}

@Dao
interface SeenNonceDao {
    @Query("SELECT EXISTS(SELECT 1 FROM seen_nonces WHERE nonceKey = :nonceKey)")
    suspend fun exists(nonceKey: String): Boolean

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: SeenNonceEntity): Long

    @Query("DELETE FROM seen_nonces WHERE receivedAtMillis < :cutoff")
    suspend fun pruneOlderThan(cutoff: Long)

    @Query("DELETE FROM seen_nonces")
    suspend fun clearAll()
}
