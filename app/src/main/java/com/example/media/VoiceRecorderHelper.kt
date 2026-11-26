package com.example.media

import android.content.Context
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.os.Build
import java.io.File
import java.util.UUID

class VoiceRecorderHelper(private val context: Context) {
    private var recorder: MediaRecorder? = null
    private var currentFile: File? = null
    private var player: MediaPlayer? = null

    fun startRecording(): Result<File> = runCatching {
        val voiceDir = File(context.filesDir, "voice").apply { mkdirs() }
        val outFile = File(voiceDir, "voice_${UUID.randomUUID().toString().take(8)}.m4a")
        val mr = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(context)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }
        mr.apply {
            setAudioSource(MediaRecorder.AudioSource.MIC)
            setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            setAudioSamplingRate(16_000)
            setAudioEncodingBitRate(32_000)
            setOutputFile(outFile.absolutePath)
            prepare()
            start()
        }
        recorder = mr
        currentFile = outFile
        outFile
    }

    fun stopRecording(): File? {
        return runCatching {
            recorder?.stop()
            recorder?.release()
            recorder = null
            val recorded = currentFile
            currentFile = null
            if (recorded != null && recorded.exists() && recorded.length() > 0L) {
                recorded
            } else {
                recorded?.delete()
                null
            }
        }.getOrElse {
            runCatching { recorder?.release() }
            recorder = null
            currentFile?.delete()
            currentFile = null
            null
        }
    }

    fun cancelRecording() {
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        currentFile?.delete()
        currentFile = null
    }

    fun playAudio(filePath: String, onCompleted: () -> Unit) {
        stopPlayback()
        runCatching {
            player = MediaPlayer().apply {
                setDataSource(filePath)
                setOnCompletionListener {
                    onCompleted()
                    stopPlayback()
                }
                prepare()
                start()
            }
        }.onFailure { onCompleted() }
    }

    fun stopPlayback() {
        runCatching {
            player?.stop()
            player?.release()
        }
        player = null
    }
}
