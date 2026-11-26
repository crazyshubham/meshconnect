package com.example.ml

import android.content.Context
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.math.exp

data class WirelessLinkMetrics(
    val rssiDbm: Int,
    val packetDeliveryRatio: Float,
    val latencyMs: Int,
    val packetLossRate: Float,
    val throughputKbps: Int
)

enum class LinkQualityTier {
    EXCELLENT,
    GOOD,
    FAIR,
    POOR
}

data class LinkPredictionResult(
    val score: Float, // 0.0..1.0
    val tier: LinkQualityTier,
    val engineMode: String,
    val isFieldTrained: Boolean,
    val provenanceNote: String,
    val routeRecommendation: String
)

@Serializable
private data class LgbmModelFile(
    @SerialName("model_name") val modelName: String,
    @SerialName("trained_on_field_data") val trainedOnFieldData: Boolean = false,
    val provenance: String = "",
    @SerialName("base_score") val baseScore: Double = 0.0,
    val trees: List<LgbmTree> = emptyList()
)

@Serializable
private data class LgbmTree(
    @SerialName("tree_index") val treeIndex: Int,
    val shrinkage: Double = 1.0,
    val nodes: Map<String, LgbmNode> = emptyMap()
)

@Serializable
private data class LgbmNode(
    @SerialName("split_feature") val splitFeature: Int? = null,
    val threshold: Double? = null,
    @SerialName("decision_type") val decisionType: String? = null,
    @SerialName("left_child") val leftChild: Int? = null,
    @SerialName("right_child") val rightChild: Int? = null,
    @SerialName("leaf_value") val leafValue: Double? = null
)

/**
 * LightGBM-compatible Boosted Decision Tree Link Quality Predictor.
 * Evaluates RSSI, Packet Delivery Ratio (PDR), Latency, Packet Loss Rate, and Throughput.
 *
 * Transparency rule: The bundled ensemble uses research-calibrated baseline tree thresholds
 * and explicitly reports `isFieldTrained = false` unless replaced with a field-trained model.
 * If the ML model is disabled or unavailable, cleanly falls back to deterministic scoring.
 */
class LightGbmLinkPredictor(
    private val context: Context? = null,
    rawModelJsonOverride: String? = null
) {
    private val json = Json { ignoreUnknownKeys = true }
    private var loadedModel: LgbmModelFile? = null

    @Volatile
    var mlModuleEnabled: Boolean = true

    init {
        loadedModel = runCatching {
            val raw = rawModelJsonOverride ?: context?.assets
                ?.open("link_quality_lgbm_model.json")
                ?.bufferedReader()
                ?.use { it.readText() }
            raw?.let { json.decodeFromString<LgbmModelFile>(it) }
        }.getOrNull()
    }

    val isModelLoaded: Boolean
        get() = loadedModel != null && loadedModel!!.trees.isNotEmpty()

    fun predict(metrics: WirelessLinkMetrics): LinkPredictionResult {
        val model = loadedModel
        if (!mlModuleEnabled || model == null || model.trees.isEmpty()) {
            return fallbackRuleBasedPredict(metrics)
        }

        val features = doubleArrayOf(
            metrics.rssiDbm.toDouble(),
            metrics.packetDeliveryRatio.toDouble().coerceIn(0.0, 1.0),
            metrics.latencyMs.toDouble().coerceAtLeast(0.0),
            metrics.packetLossRate.toDouble().coerceIn(0.0, 1.0),
            metrics.throughputKbps.toDouble().coerceAtLeast(0.0)
        )

        var margin = model.baseScore
        for (tree in model.trees) {
            margin += tree.shrinkage * evaluateTree(tree.nodes, features)
        }
        val probability = (1.0 / (1.0 + exp(-margin))).toFloat().coerceIn(0f, 1f)
        val tier = tierForScore(probability)

        return LinkPredictionResult(
            score = probability,
            tier = tier,
            engineMode = "LightGBM GBDT (${model.trees.size} trees)",
            isFieldTrained = model.trainedOnFieldData,
            provenanceNote = model.provenance.ifBlank {
                "Baseline LightGBM decision tree weights (not trained on live user field data)"
            },
            routeRecommendation = recommendationFor(tier, metrics)
        )
    }

    private fun evaluateTree(nodes: Map<String, LgbmNode>, features: DoubleArray): Double {
        var currentId = 0
        var guard = 0
        while (guard < 64) {
            val node = nodes[currentId.toString()] ?: return 0.0
            val leaf = node.leafValue
            if (leaf != null) return leaf
            val featIdx = node.splitFeature ?: return 0.0
            val threshold = node.threshold ?: return 0.0
            val featVal = features.getOrElse(featIdx) { 0.0 }
            val goLeft = featVal <= threshold
            currentId = (if (goLeft) node.leftChild else node.rightChild) ?: return 0.0
            guard++
        }
        return 0.0
    }

    private fun fallbackRuleBasedPredict(metrics: WirelessLinkMetrics): LinkPredictionResult {
        val rssiNorm = ((metrics.rssiDbm + 95f) / 55f).coerceIn(0f, 1f)
        val pdrNorm = metrics.packetDeliveryRatio.coerceIn(0f, 1f)
        val lossPenalty = 1f - metrics.packetLossRate.coerceIn(0f, 1f)
        val latencyNorm = (1f - (metrics.latencyMs / 500f)).coerceIn(0f, 1f)
        val tpNorm = (metrics.throughputKbps / 10000f).coerceIn(0f, 1f)

        val score = (0.25f * rssiNorm + 0.30f * pdrNorm + 0.20f * lossPenalty + 0.15f * latencyNorm + 0.10f * tpNorm)
            .coerceIn(0f, 1f)
        val tier = tierForScore(score)
        return LinkPredictionResult(
            score = score,
            tier = tier,
            engineMode = "Fallback Heuristic (ML Disabled/Unavailable)",
            isFieldTrained = false,
            provenanceNote = "Deterministic fallback scorer active; core messaging & routing remain operational.",
            routeRecommendation = recommendationFor(tier, metrics)
        )
    }

    private fun tierForScore(score: Float): LinkQualityTier = when {
        score >= 0.78f -> LinkQualityTier.EXCELLENT
        score >= 0.56f -> LinkQualityTier.GOOD
        score >= 0.34f -> LinkQualityTier.FAIR
        else -> LinkQualityTier.POOR
    }

    private fun recommendationFor(tier: LinkQualityTier, m: WirelessLinkMetrics): String = when (tier) {
        LinkQualityTier.EXCELLENT -> "Direct high-throughput link (${m.throughputKbps} kbps); safe for large encrypted video & direct routing."
        LinkQualityTier.GOOD -> "Reliable direct link (${m.latencyMs} ms RTT); suitable for E2EE messages and chunked files."
        LinkQualityTier.FAIR -> "Marginal direct signal (${m.rssiDbm} dBm); consider multi-hop relay or smaller chunk retries."
        LinkQualityTier.POOR -> "Unstable link (${(m.packetLossRate * 100).toInt()}% loss); queue store-and-forward or switch transport."
    }
}
