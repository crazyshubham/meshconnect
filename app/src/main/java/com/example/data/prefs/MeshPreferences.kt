package com.example.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.meshDataStore: DataStore<Preferences> by preferencesDataStore(name = "meshconnect_prefs")

enum class ThemeMode {
    SYSTEM, LIGHT, DARK
}

data class SecurityAndAppSettings(
    val themeMode: ThemeMode = ThemeMode.DARK,
    val allowMeshRelay: Boolean = true,
    val requireFileAcceptancePrompt: Boolean = false,
    val sessionExpiryHours: Int = 24,
    val mlPredictorEnabled: Boolean = true,
    val autoAcceptVerifiedPeers: Boolean = false,
    val onboardingCompleted: Boolean = false
)

class MeshPreferences(private val context: Context) {

    private object Keys {
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val ALLOW_MESH_RELAY = booleanPreferencesKey("allow_mesh_relay")
        val REQUIRE_FILE_ACCEPT = booleanPreferencesKey("require_file_accept")
        val SESSION_EXPIRY_HOURS = intPreferencesKey("session_expiry_hours")
        val ML_PREDICTOR_ENABLED = booleanPreferencesKey("ml_predictor_enabled")
        val AUTO_ACCEPT_VERIFIED = booleanPreferencesKey("auto_accept_verified")
        val ONBOARDING_COMPLETED = booleanPreferencesKey("onboarding_completed")
    }

    val settingsFlow: Flow<SecurityAndAppSettings> = context.meshDataStore.data.map { prefs ->
        SecurityAndAppSettings(
            themeMode = runCatching {
                ThemeMode.valueOf(prefs[Keys.THEME_MODE] ?: ThemeMode.DARK.name)
            }.getOrDefault(ThemeMode.DARK),
            allowMeshRelay = prefs[Keys.ALLOW_MESH_RELAY] ?: true,
            requireFileAcceptancePrompt = prefs[Keys.REQUIRE_FILE_ACCEPT] ?: false,
            sessionExpiryHours = prefs[Keys.SESSION_EXPIRY_HOURS] ?: 24,
            mlPredictorEnabled = prefs[Keys.ML_PREDICTOR_ENABLED] ?: true,
            autoAcceptVerifiedPeers = prefs[Keys.AUTO_ACCEPT_VERIFIED] ?: false,
            onboardingCompleted = prefs[Keys.ONBOARDING_COMPLETED] ?: false
        )
    }

    suspend fun setThemeMode(mode: ThemeMode) {
        context.meshDataStore.edit { it[Keys.THEME_MODE] = mode.name }
    }

    suspend fun setAllowMeshRelay(enabled: Boolean) {
        context.meshDataStore.edit { it[Keys.ALLOW_MESH_RELAY] = enabled }
    }

    suspend fun setRequireFileAcceptancePrompt(required: Boolean) {
        context.meshDataStore.edit { it[Keys.REQUIRE_FILE_ACCEPT] = required }
    }

    suspend fun setSessionExpiryHours(hours: Int) {
        context.meshDataStore.edit { it[Keys.SESSION_EXPIRY_HOURS] = hours }
    }

    suspend fun setMlPredictorEnabled(enabled: Boolean) {
        context.meshDataStore.edit { it[Keys.ML_PREDICTOR_ENABLED] = enabled }
    }

    suspend fun setAutoAcceptVerifiedPeers(enabled: Boolean) {
        context.meshDataStore.edit { it[Keys.AUTO_ACCEPT_VERIFIED] = enabled }
    }

    suspend fun setOnboardingCompleted(done: Boolean) {
        context.meshDataStore.edit { it[Keys.ONBOARDING_COMPLETED] = done }
    }

    suspend fun clearAll() {
        context.meshDataStore.edit { it.clear() }
    }
}
