"""Train all seven project detectors from one or more CICIDS CSV files.

Usage:
    python -m src.models.train_all_unidirectional DATA_DIR OUTPUT_DIR

DATA_DIR may contain CSV files from CICIDS/CICFlowMeter. Each detector is
trained one-vs-rest against the label column. No traffic data is committed
to the repository.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from src.features.unidirectional_features import UNIDIRECTIONAL_FEATURES, transform_dataframe


DETECTOR_LABELS = {
    "bot": ("bot", "botnet"),
    "ddos": ("ddos",),
    "dos": ("dos hulk", "dos goldeneye", "dos slowloris", "dos slowhttp", "heartbleed"),
    "infiltration": ("infiltration",),
    "patator": ("ftp-patator", "ssh-patator", "patator"),
    "portscan": ("portscan", "port scan"),
    "webattack": ("web attack", "webattack", "brute force", "xss", "sql injection"),
}


def _find_label_column(df: pd.DataFrame) -> str:
    for name in ("Label", "label", " Label", "label "):
        if name in df.columns:
            return name
    raise ValueError("No Label column found in CICIDS CSV.")


def _load_csvs(source: Path) -> pd.DataFrame:
    files = sorted(source.glob("*.csv")) if source.is_dir() else [source]
    if not files:
        raise FileNotFoundError(f"No CSV files found in {source}")

    frames = []
    for path in files:
        print(f"Reading {path} ...")
        df = pd.read_csv(path, low_memory=False)
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def _normalize_labels(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip().str.lower()


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _train_one(name: str, df: pd.DataFrame, label_column: str, output_dir: Path) -> None:
    labels = _normalize_labels(df[label_column])
    positive_terms = DETECTOR_LABELS[name]
    y = labels.map(lambda value: "THREAT" if _contains_any(value, positive_terms) else "BENIGN")

    counts = y.value_counts()
    if counts.get("THREAT", 0) < 2 or counts.get("BENIGN", 0) < 2:
        print(f"[skip] {name}: insufficient BENIGN/THREAT rows ({counts.to_dict()})")
        return

    converted = transform_dataframe(df)
    X = converted[UNIDIRECTIONAL_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)

    # Keep only finite rows so malformed CICFlowMeter values do not poison training.
    mask = X.replace([float("inf"), float("-inf")], pd.NA).notna().all(axis=1)
    X = X.loc[mask]
    y = y.loc[mask]

    if y.nunique() < 2 or y.value_counts().min() < 2:
        print(f"[skip] {name}: insufficient rows after cleaning")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print(f"\n=== {name} ===")
    print(classification_report(y_test, predictions, zero_division=0))

    output = output_dir / f"{name}_unidirectional.pkl"
    joblib.dump(
        {
            "model": model,
            "model_type": "random_forest_unidirectional",
            "features": UNIDIRECTIONAL_FEATURES,
            "detector": name,
            "positive_labels": list(positive_terms),
        },
        output,
    )
    print(f"Saved: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train all seven unidirectional threat detectors")
    parser.add_argument("source", type=Path, help="CICIDS CSV file or directory containing CSV files")
    parser.add_argument("output_dir", type=Path, help="Directory for model artifacts")
    args = parser.parse_args()

    df = _load_csvs(args.source)
    label_column = _find_label_column(df)
    print(f"Loaded {len(df):,} rows with label column {label_column!r}.")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for name in DETECTOR_LABELS:
        _train_one(name, df, label_column, args.output_dir)


if __name__ == "__main__":
    main()
