"""
ml/train.py — Train the Random Forest DDoS classifier

Run: python ml/train.py
Outputs: ml/model.pkl + prints accuracy metrics
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score,
    confusion_matrix, f1_score
)

# Ensure we can import the dataset generator
sys.path.insert(0, os.path.dirname(__file__))
from dataset_generator import generate, OUTPUT_PATH

FEATURES = [
    "packet_count", "total_bytes", "avg_packet_size",
    "packets_per_sec", "bytes_per_sec", "connection_count",
    "syn_count", "syn_ratio", "dst_port", "flow_duration",
]
LABEL = "label"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")


def train():
    # 1. Generate / load dataset
    if not os.path.exists(OUTPUT_PATH):
        print("Generating synthetic dataset...")
        generate()

    df = pd.read_csv(OUTPUT_PATH)
    print(f"\nDataset: {len(df)} samples  |  Attack ratio: {df[LABEL].mean():.1%}")

    X = df[FEATURES].values
    y = df[LABEL].values

    # 2. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. Train Random Forest
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=4,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    print("\nTraining Random Forest...")
    clf.fit(X_train, y_train)

    # 4. Evaluate
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print(f"\n{'='*50}")
    print(f"  Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print(f"  F1 Score : {f1:.4f}")
    print(f"{'='*50}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

    # Feature importance
    importances = clf.feature_importances_
    print("\nFeature Importances:")
    for feat, imp in sorted(zip(FEATURES, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"  {feat:<22} {imp:.4f}  {bar}")

    # 5. Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"\nModel saved to: {MODEL_PATH}")
    return clf


if __name__ == "__main__":
    train()
