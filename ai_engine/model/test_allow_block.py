from pathlib import Path
import sys

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ai_engine.model import predict

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "cleaned.csv"
FEATURES_PATH = BASE_DIR / "models" / "features.pkl"


def decision_from_label(label: str) -> str:
    return "allow" if str(label).strip().upper() == "BENIGN" else "block"


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError("Expected 'Label' column in cleaned.csv")

    benign_df = df[df["Label"].astype(str).str.upper() == "BENIGN"].head(10)
    attack_df = df[df["Label"].astype(str).str.upper() != "BENIGN"].head(10)

    if len(benign_df) < 10 or len(attack_df) < 10:
        raise ValueError("Not enough BENIGN/attack rows to run 10+10 test")

    test_df = pd.concat([benign_df, attack_df], ignore_index=True)

    total = 0
    passed = 0

    print("Running 10 allow + 10 block tests...\n")

    for idx, row in test_df.iterrows():
        true_label = str(row["Label"])
        expected_decision = decision_from_label(true_label)

        features = row.drop(labels=["Label"]).to_dict()
        output = predict({"features": features})

        pred_label = str(output.get("label", output.get("predicted_class", "UNKNOWN")))
        predicted_decision = decision_from_label(pred_label)

        ok = predicted_decision == expected_decision
        total += 1
        passed += int(ok)

        print(
            f"Test {idx + 1:02d} | expected={expected_decision:<5} | "
            f"predicted={predicted_decision:<5} | true_label={true_label} | "
            f"pred_label={pred_label} | {'PASS' if ok else 'FAIL'}"
        )

    print("\n====================================")
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    print("====================================")


if __name__ == "__main__":
    main()
