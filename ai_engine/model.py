"""
NovaShield AI Model — CICIDS2017-based threat classification.

Provides single and batch prediction functions that load trained model
artifacts (Random Forest, scaler, feature list, label encoder) from disk.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


MODELS_DIR = Path(__file__).resolve().parent / "model" / "models"
MODEL_PATH = MODELS_DIR / "model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
FEATURES_PATH = MODELS_DIR / "features.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"

_model = None
_scaler = None
_features = None
_label_encoder = None


def _load_artifacts():
    global _model, _scaler, _features, _label_encoder

    if _model is not None:
        return

    missing = [
        str(path)
        for path in [MODEL_PATH, SCALER_PATH, FEATURES_PATH, LABEL_ENCODER_PATH]
        if not path.exists()
    ]
    if missing:
        raise FileNotFoundError(
            "Missing model artifacts. Expected files:\n" + "\n".join(missing)
        )

    _model = joblib.load(MODEL_PATH)
    _scaler = joblib.load(SCALER_PATH)
    _features = joblib.load(FEATURES_PATH)
    _label_encoder = joblib.load(LABEL_ENCODER_PATH)

    # Sandbox/runtime compatibility: avoid spawning worker pools.
    if hasattr(_model, "n_jobs"):
        _model.n_jobs = 1


def warmup():
    """Force-load model artifacts so the first real prediction is fast."""
    _load_artifacts()


def _is_gateway_metadata_only(data):
    """Detect if the input is HTTP metadata from the gateway (no ML features)."""
    if data.get("feature_vector") is not None:
        return False
    if data.get("features") and isinstance(data["features"], dict):
        return False
    # If none of the CICIDS feature names appear with non-zero values,
    # this is gateway metadata, not a feature payload.
    if _features:
        for name in _features:
            if name in data and float(data.get(name, 0.0)) != 0.0:
                return False
    return True


def _predict_from_metadata(data):
    """Heuristic threat classification from HTTP request metadata.

    The CICIDS-trained model cannot meaningfully classify gateway metadata
    (ip, path, method, user_agent). This function provides lightweight
    heuristic analysis so the AI layer is not completely blind to HTTP-level
    attack patterns.
    """
    path = str(data.get("path", "")).lower()
    user_agent = str(data.get("user_agent", "")).lower()
    combined = f"{path} {user_agent}"

    # Known attack tool user-agents
    scanner_tokens = [
        "sqlmap", "nikto", "nmap", "masscan", "hydra", "dirbuster",
        "gobuster", "wfuzz", "burpsuite", "zap", "acunetix", "nessus",
    ]

    # Common injection / traversal patterns
    attack_patterns = [
        "<script", "javascript:", "onerror=", "onload=",
        "union select", "drop table", "sleep(", "' or ", "' and ",
        "1=1", "../../", "/etc/passwd", "boot.ini",
        "; cat ", "; curl ", "; wget ", "| cat ", "&& curl", "&& wget",
        "%00", "\\x00",
    ]

    for token in scanner_tokens:
        if token in combined:
            return {
                "label": "ATTACK",
                "confidence": 0.90,
                "predicted_class": "Scanner-Detected",
            }

    for pattern in attack_patterns:
        if pattern in combined:
            return {
                "label": "ATTACK",
                "confidence": 0.85,
                "predicted_class": "Heuristic-Attack",
            }

    return {
        "label": "BENIGN",
        "confidence": 0.50,
        "predicted_class": "Heuristic-Benign",
    }


def _resolve_feature_vector(data):
    # Preferred direct vector input
    if "feature_vector" in data and data["feature_vector"] is not None:
        vector = np.array(data["feature_vector"], dtype=float).reshape(1, -1)
        if vector.shape[1] != len(_features):
            raise ValueError(
                f"feature_vector length {vector.shape[1]} does not match expected {len(_features)}"
            )
        return pd.DataFrame(vector, columns=_features)

    # Build from named features dict
    if "features" in data and isinstance(data["features"], dict):
        feature_map = data["features"]
        ordered = [float(feature_map.get(name, 0.0)) for name in _features]
        return pd.DataFrame([ordered], columns=_features)

    # Backward-compatible payload support:
    # If feature names are directly provided at top-level, use them.
    ordered = [float(data.get(name, 0.0)) for name in _features]
    return pd.DataFrame([ordered], columns=_features)


def predict(data):
    """
    Predict traffic class from extracted network-flow features.

    Supported input formats:
    - {"feature_vector": [...]}
    - {"features": {...feature_name: value...}}
    - {<feature_name>: value, ...} (flat dict)

    Returns dict with keys: label, confidence, predicted_class (optional).
    """
    _load_artifacts()

    # Gateway metadata (ip, path, method, user_agent) cannot be classified
    # by the CICIDS network flow model — use heuristic analysis instead.
    if _is_gateway_metadata_only(data):
        return _predict_from_metadata(data)

    x = _resolve_feature_vector(data)
    x_scaled = _scaler.transform(x)

    prediction = _model.predict(x_scaled)[0]

    if isinstance(prediction, (int, np.integer)):
        label = _label_encoder.inverse_transform([prediction])[0]
    else:
        label = prediction

    result = {"label": str(label)}

    if hasattr(_model, "predict_proba"):

        probabilities = _model.predict_proba(x_scaled)[0]
        best_idx = int(np.argmax(probabilities))
        result["confidence"] = float(probabilities[best_idx])

        if hasattr(_model, "classes_"):
            cls_val = _model.classes_[best_idx]
            if isinstance(cls_val, (int, np.integer)):
                result["predicted_class"] = str(
                    _label_encoder.inverse_transform([cls_val])[0]
                )
            else:
                result["predicted_class"] = str(cls_val)

    return result


def predict_batch(items: list) -> list:
    """
    Batch prediction — process multiple inputs in a single model call for
    higher throughput.

    Each item in ``items`` follows the same format as ``predict()``.
    """
    _load_artifacts()

    frames = [_resolve_feature_vector(item) for item in items]
    x = pd.concat(frames, ignore_index=True)
    x_scaled = _scaler.transform(x)

    predictions = _model.predict(x_scaled)
    probabilities = None
    if hasattr(_model, "predict_proba"):
        probabilities = _model.predict_proba(x_scaled)

    results = []
    for i, pred in enumerate(predictions):
        if isinstance(pred, (int, np.integer)):
            label = _label_encoder.inverse_transform([pred])[0]
        else:
            label = pred

        entry = {"label": str(label)}

        if probabilities is not None:
            probs = probabilities[i]
            best_idx = int(np.argmax(probs))
            entry["confidence"] = float(probs[best_idx])

            if hasattr(_model, "classes_"):
                cls_val = _model.classes_[best_idx]
                if isinstance(cls_val, (int, np.integer)):
                    entry["predicted_class"] = str(
                        _label_encoder.inverse_transform([cls_val])[0]
                    )
                else:
                    entry["predicted_class"] = str(cls_val)

        results.append(entry)

    return results
