from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
DATASET_DIR = BASE_DIR / "dataset"

MODEL_PATH = MODELS_DIR / "model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
FEATURES_PATH = MODELS_DIR / "features.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"


def load_dataset():
    candidates = [
        DATASET_DIR / "cleaned.csv",
        DATASET_DIR / "combined.csv",
    ]

    for path in candidates:
        if path.exists():
            print(f"Using dataset: {path}")
            return pd.read_csv(path, low_memory=False)

    raise FileNotFoundError(
        "No dataset found for testing. Expected one of:\n"
        f"- {candidates[0]}\n"
        f"- {candidates[1]}"
    )


def ensure_artifacts_exist():
    required = [MODEL_PATH, SCALER_PATH, FEATURES_PATH, LABEL_ENCODER_PATH]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing model artifacts:\n" + "\n".join(missing)
        )


def normalize_columns(df):
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], 0)
    return df.dropna()


def main():
    ensure_artifacts_exist()

    model = joblib.load(MODEL_PATH)
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    scaler = joblib.load(SCALER_PATH)
    features = joblib.load(FEATURES_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)

    df = normalize_columns(load_dataset())

    if "Label" not in df.columns:
        raise ValueError("Dataset must contain a 'Label' column.")

    # Align features with model training feature order
    X = df.reindex(columns=features, fill_value=0)
    y = df["Label"].astype(str)

    # Holdout evaluation (same split strategy as training notebook)
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    X_test_scaled = scaler.transform(X_test)
    y_pred_raw = model.predict(X_test_scaled)

    y_pred_text = np.array([str(v) for v in y_pred_raw])

    if np.issubdtype(np.array(y_pred_raw).dtype, np.integer):
        y_pred_text = label_encoder.inverse_transform(np.array(y_pred_raw, dtype=int))

    # Compare by label text to avoid encoded/non-encoded mismatch
    y_true_text = y_test.to_numpy()

    accuracy = accuracy_score(y_true_text, y_pred_text)
    print(f"Accuracy: {accuracy:.4f}")

    labels = sorted(set(y_true_text) | set(y_pred_text))
    print("\nClassification Report:")
    print(classification_report(y_true_text, y_pred_text, labels=labels, zero_division=0))

    print("Confusion Matrix:")
    print(confusion_matrix(y_true_text, y_pred_text, labels=labels))


if __name__ == "__main__":
    main()
