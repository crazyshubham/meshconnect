package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        PeerDeviceEntity::class,
        ConversationEntity::class,
        MessageEntity::class,
        GroupEntity::class,
        GroupMemberEntity::class,
        MessageRecipientStatusEntity::class,
        TransferRecordEntity::class,
        PendingRelayPacketEntity::class,
        SeenNonceEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class MeshDatabase : RoomDatabase() {
    abstract fun peerDeviceDao(): PeerDeviceDao
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun groupDao(): GroupDao
    abstract fun transferRecordDao(): TransferRecordDao
    abstract fun pendingRelayDao(): PendingRelayDao
    abstract fun seenNonceDao(): SeenNonceDao

    companion object {
        @Volatile
        private var INSTANCE: MeshDatabase? = null

        fun getInstance(context: Context): MeshDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    MeshDatabase::class.java,
                    "meshconnect_local.db"
                ).build().also { INSTANCE = it }
            }
    }
}
