from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "cleaned.csv"
MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
FEATURES_PATH = MODELS_DIR / "features.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"


def normalize_label(text):
    value = str(text).strip()
    replacements = {
        "Web Attack ? Brute Force": "Web Attack - Brute Force",
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack ? Sql Injection": "Web Attack - Sql Injection",
        "Web Attack � Sql Injection": "Web Attack - Sql Injection",
        "Web Attack ? XSS": "Web Attack - XSS",
        "Web Attack � XSS": "Web Attack - XSS",
    }
    return replacements.get(value, value)


def load_data():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], 0).dropna()

    if "Label" not in df.columns:
        raise ValueError("Dataset must contain a 'Label' column")

    df["Label"] = df["Label"].astype(str).map(normalize_label)
    return df


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = load_data()
    X = df.drop(columns=["Label"])
    y_text = df["Label"]

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_text)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=20,
        random_state=42,
        n_jobs=1,
        class_weight="balanced_subsample",
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Holdout Accuracy: {accuracy:.4f}")

    y_test_text = label_encoder.inverse_transform(y_test)
    y_pred_text = label_encoder.inverse_transform(y_pred)

    print("\nClassification Report:")
    print(classification_report(y_test_text, y_pred_text, zero_division=0))

    labels = list(label_encoder.classes_)
    print("Confusion Matrix:")
    print(confusion_matrix(y_test_text, y_pred_text, labels=labels))

    # Save artifacts used by runtime predictor.
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(list(X.columns), FEATURES_PATH)
    joblib.dump(label_encoder, LABEL_ENCODER_PATH)

    print("\nSaved artifacts:")
    print(MODEL_PATH)
    print(SCALER_PATH)
    print(FEATURES_PATH)
    print(LABEL_ENCODER_PATH)


if __name__ == "__main__":
    main()
