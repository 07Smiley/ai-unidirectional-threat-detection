"""Train a binary threat detector from a converted unidirectional CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from src.features.unidirectional_features import UNIDIRECTIONAL_FEATURES


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a unidirectional threat model")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--positive-labels", required=True, help="Comma-separated threat labels")
    parser.add_argument("--label-column", default="Label")
    args = parser.parse_args()
    df = pd.read_csv(args.input)
    if args.label_column not in df.columns:
        raise SystemExit(f"Missing label column: {args.label_column}")
    missing = [c for c in UNIDIRECTIONAL_FEATURES if c not in df.columns]
    if missing:
        raise SystemExit(f"Missing unidirectional features: {missing}")
    positive = {x.strip().lower() for x in args.positive_labels.split(",") if x.strip()}
    labels = df[args.label_column].astype(str)
    y = labels.map(lambda value: "THREAT" if value.strip().lower() in positive else "BENIGN")
    X = df[UNIDIRECTIONAL_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    if y.nunique() < 2:
        raise SystemExit("Training data must contain both BENIGN and THREAT rows.")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced")
    model.fit(X_train, y_train)
    print(classification_report(y_test, model.predict(X_test), zero_division=0))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "model_type": "random_forest_unidirectional", "features": UNIDIRECTIONAL_FEATURES}, args.output)
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
