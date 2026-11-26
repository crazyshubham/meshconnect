package com.example

import android.app.Application
import androidx.work.Configuration
import androidx.work.WorkManager
import com.example.crypto.AndroidKeystoreProtector
import com.example.crypto.IdentityKeyManager
import com.example.data.local.MeshDatabase
import com.example.data.prefs.MeshPreferences
import com.example.data.repository.MeshRepository
import com.example.media.VoiceRecorderHelper
import com.example.ml.LightGbmLinkPredictor
import com.example.network.MeshSyncWorker

class MeshConnectApp : Application(), Configuration.Provider {
    val database: MeshDatabase by lazy { MeshDatabase.getInstance(this) }
    val identityKeyManager: IdentityKeyManager by lazy {
        IdentityKeyManager(this, AndroidKeystoreProtector())
    }
    val preferences: MeshPreferences by lazy { MeshPreferences(this) }
    val linkPredictor: LightGbmLinkPredictor by lazy { LightGbmLinkPredictor(this) }
    val voiceRecorder: VoiceRecorderHelper by lazy { VoiceRecorderHelper(this) }

    val meshRepository: MeshRepository by lazy {
        MeshRepository(
            context = this,
            db = database,
            identityKeyManager = identityKeyManager,
            preferences = preferences,
            linkPredictor = linkPredictor
        )
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()

    override fun onCreate() {
        super.onCreate()
        runCatching {
            if (!WorkManager.isInitialized()) {
                WorkManager.initialize(this, workManagerConfiguration)
            }
            MeshSyncWorker.schedule(this)
        }
    }

    companion object {
        @Volatile
        private var fallbackRepo: MeshRepository? = null

        @Volatile
        private var fallbackVoiceRecorder: VoiceRecorderHelper? = null

        fun getRepository(application: Application): MeshRepository {
            (application as? MeshConnectApp)?.let { return it.meshRepository }
            (application.applicationContext as? MeshConnectApp)?.let { return it.meshRepository }
            return fallbackRepo ?: synchronized(this) {
                fallbackRepo ?: run {
                    val ctx = application.applicationContext ?: application
                    MeshRepository(
                        context = ctx,
                        db = MeshDatabase.getInstance(ctx),
                        identityKeyManager = IdentityKeyManager(ctx, AndroidKeystoreProtector()),
                        preferences = MeshPreferences(ctx),
                        linkPredictor = LightGbmLinkPredictor(ctx)
                    ).also { fallbackRepo = it }
                }
            }
        }

        fun getVoiceRecorder(application: Application): VoiceRecorderHelper {
            (application as? MeshConnectApp)?.let { return it.voiceRecorder }
            (application.applicationContext as? MeshConnectApp)?.let { return it.voiceRecorder }
            return fallbackVoiceRecorder ?: synchronized(this) {
                fallbackVoiceRecorder ?: VoiceRecorderHelper(
                    application.applicationContext ?: application
                ).also { fallbackVoiceRecorder = it }
            }
        }
    }
}
