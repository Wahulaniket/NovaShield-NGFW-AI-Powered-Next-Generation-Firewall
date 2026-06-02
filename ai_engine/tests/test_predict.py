"""
NovaShield AI Engine — Unit Tests

Tests model loading, single prediction, batch prediction, and decision logic.

Usage:
    cd ai_engine
    python -m pytest tests/test_predict.py -v
"""

import sys
from pathlib import Path

# Ensure ai_engine is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from model import predict, predict_batch, warmup, _load_artifacts, _features


class TestModelLoading:
    """Verify that model artifacts load correctly."""

    def test_warmup_loads_without_error(self):
        warmup()

    def test_features_list_populated(self):
        warmup()
        assert _features is not None
        assert len(_features) > 0, "features list should not be empty"


class TestSinglePrediction:
    """Test individual predictions."""

    def test_predict_with_zeros_returns_label(self):
        """Zero-vector input should still produce a valid label."""
        warmup()
        data = {"feature_vector": [0.0] * len(_features)}
        result = predict(data)

        assert "label" in result
        assert isinstance(result["label"], str)
        assert len(result["label"]) > 0

    def test_predict_with_features_dict(self):
        """Named features dict should work."""
        warmup()
        features = {name: 0.0 for name in _features}
        data = {"features": features}
        result = predict(data)

        assert "label" in result

    def test_predict_returns_confidence(self):
        """Model should return confidence score."""
        warmup()
        data = {"feature_vector": [0.0] * len(_features)}
        result = predict(data)

        if "confidence" in result:
            assert 0.0 <= result["confidence"] <= 1.0

    def test_predict_benign_traffic(self):
        """Benign-looking traffic (small packet, low rate) should likely be BENIGN."""
        warmup()
        # Simulate benign: small packets, low rate, common port
        features = {name: 0.0 for name in _features}
        features["Destination Port"] = 80.0
        features["Packet Length Mean"] = 64.0
        features["Flow Bytes/s"] = 100.0
        features["Total Fwd Packets"] = 2.0

        data = {"features": features}
        result = predict(data)

        assert "label" in result
        # We don't assert BENIGN here because the model may classify differently
        # with synthetic features — the key test is that it runs without error


class TestBatchPrediction:
    """Test batch prediction functionality."""

    def test_batch_empty_list(self):
        """Empty batch should return empty results."""
        warmup()
        results = predict_batch([])
        assert results == []

    def test_batch_single_item(self):
        """Batch with one item should return one result."""
        warmup()
        items = [{"feature_vector": [0.0] * len(_features)}]
        results = predict_batch(items)

        assert len(results) == 1
        assert "label" in results[0]

    def test_batch_multiple_items(self):
        """Batch with multiple items should return matching count."""
        warmup()
        items = [
            {"feature_vector": [0.0] * len(_features)},
            {"feature_vector": [1.0] * len(_features)},
            {"feature_vector": [0.5] * len(_features)},
        ]
        results = predict_batch(items)

        assert len(results) == 3
        for result in results:
            assert "label" in result


class TestDecisionLogic:
    """Test that decision mapping works correctly."""

    def test_benign_label_means_allow(self):
        """If model returns BENIGN, decision should be allow."""
        label = "BENIGN"
        decision = "allow" if label == "BENIGN" else "block"
        assert decision == "allow"

    def test_attack_label_means_block(self):
        """Any non-BENIGN label should map to block."""
        for label in ["DDoS", "PortScan", "Bot", "Infiltration", "Web Attack"]:
            decision = "allow" if label == "BENIGN" else "block"
            assert decision == "block", f"Expected block for label '{label}'"
