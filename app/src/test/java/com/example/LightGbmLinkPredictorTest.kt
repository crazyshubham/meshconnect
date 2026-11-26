package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.ml.LightGbmLinkPredictor
import com.example.ml.LinkQualityTier
import com.example.ml.WirelessLinkMetrics
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class LightGbmLinkPredictorTest {

    @Test
    fun `predicts strong vs weak wireless link and supports fallback mode`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val predictor = LightGbmLinkPredictor(context)
        assertTrue("LightGBM asset model should load", predictor.isModelLoaded)

        val strong = predictor.predict(
            WirelessLinkMetrics(
                rssiDbm = -52,
                packetDeliveryRatio = 0.98f,
                latencyMs = 18,
                packetLossRate = 0.01f,
                throughputKbps = 9500
            )
        )
        val weak = predictor.predict(
            WirelessLinkMetrics(
                rssiDbm = -91,
                packetDeliveryRatio = 0.42f,
                latencyMs = 360,
                packetLossRate = 0.45f,
                throughputKbps = 180
            )
        )

        assertFalse("Untrained baseline must never claim field training", strong.isFieldTrained)
        assertTrue("Strong link must score higher than weak link", strong.score > weak.score)
        assertTrue(strong.tier == LinkQualityTier.EXCELLENT || strong.tier == LinkQualityTier.GOOD)
        assertTrue(weak.tier == LinkQualityTier.POOR || weak.tier == LinkQualityTier.FAIR)

        // Fallback mode when ML module disabled
        predictor.mlModuleEnabled = false
        val fallback = predictor.predict(
            WirelessLinkMetrics(-60, 0.90f, 40, 0.05f, 4000)
        )
        assertTrue(fallback.engineMode.contains("Fallback"))
    }
}
