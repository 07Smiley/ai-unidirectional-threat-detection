"""Canonical observed-direction (unidirectional) feature schema.

Training data may contain CICFlowMeter forward/backward fields.  We deliberately
use only the forward/observed direction and never construct features by adding,
averaging, or pooling forward and backward traffic.
"""

from __future__ import annotations

from typing import Mapping, Any

import pandas as pd

# Every feature here must be derivable from the observed/forward direction.
# Do not add Total Packets, Total Bytes, Flow Bytes/s, Flow Packets/s, or any
# other aggregate that can contain backward traffic.
UNIDIRECTIONAL_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Fwd Packets/s",
]

# Columns that are known to include both directions or are explicitly backward.
# These are never accepted as part of the canonical ML feature vector.
FORBIDDEN_BIDIRECTIONAL_FEATURES = {
    "Total Packets",
    "Total Bytes",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "PSH Flags",
    "URG Flags",
    "Header Length",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
}


def _num(row: Mapping[str, Any], name: str, default: float = 0.0) -> float:
    value = row.get(name, default)
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def from_row(row: Mapping[str, Any]) -> dict[str, float]:
    """Extract only features observable in the forward/selected direction."""
    return {
        "Destination Port": _num(row, "Destination Port"),
        "Flow Duration": _num(row, "Flow Duration"),
        "Total Fwd Packets": _num(row, "Total Fwd Packets"),
        "Total Length of Fwd Packets": _num(row, "Total Length of Fwd Packets"),
        "Fwd Packet Length Max": _num(row, "Fwd Packet Length Max"),
        "Fwd Packet Length Min": _num(row, "Fwd Packet Length Min"),
        "Fwd Packet Length Mean": _num(row, "Fwd Packet Length Mean"),
        "Fwd Packet Length Std": _num(row, "Fwd Packet Length Std"),
        "Fwd IAT Total": _num(row, "Fwd IAT Total"),
        "Fwd IAT Mean": _num(row, "Fwd IAT Mean"),
        "Fwd IAT Std": _num(row, "Fwd IAT Std"),
        "Fwd IAT Max": _num(row, "Fwd IAT Max"),
        "Fwd IAT Min": _num(row, "Fwd IAT Min"),
        "Fwd PSH Flags": _num(row, "Fwd PSH Flags"),
        "Fwd URG Flags": _num(row, "Fwd URG Flags"),
        "Fwd Header Length": _num(row, "Fwd Header Length"),
        "Fwd Packets/s": _num(row, "Fwd Packets/s"),
    }


def transform_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the canonical observed-direction schema, preserving labels."""
    if df is None:
        raise ValueError("A dataframe is required.")

    rows = [from_row(row) for row in df.to_dict("records")]
    result = pd.DataFrame(rows, columns=UNIDIRECTIONAL_FEATURES)

    if "Label" in df.columns:
        result["Label"] = df["Label"].values
    elif "label" in df.columns:
        result["label"] = df["label"].values

    return result
