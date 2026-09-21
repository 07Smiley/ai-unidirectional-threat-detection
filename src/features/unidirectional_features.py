"""Unidirectional feature schema shared by training and live inference.

The source CICIDS/CICFlowMeter data contains forward/backward splits. This module
collapses those directional fields into aggregate, direction-agnostic features.
"""

from __future__ import annotations

from typing import Mapping, Any

import pandas as pd

UNIDIRECTIONAL_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Packets",
    "Total Bytes",
    "Packet Length Max",
    "Packet Length Min",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "PSH Flags",
    "URG Flags",
    "Header Length",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
]


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


def _sum(row: Mapping[str, Any], *names: str) -> float:
    return sum(_num(row, name) for name in names)


def _max(row: Mapping[str, Any], *names: str) -> float:
    return max((_num(row, name) for name in names), default=0.0)


def _min_nonzero(row: Mapping[str, Any], *names: str) -> float:
    values = [_num(row, name) for name in names]
    positive = [value for value in values if value > 0]
    return min(positive) if positive else 0.0


def _weighted_mean(row: Mapping[str, Any], left: str, right: str, left_n: str, right_n: str) -> float:
    ln = _num(row, left_n)
    rn = _num(row, right_n)
    total = ln + rn
    if total <= 0:
        return 0.0
    return (_num(row, left) * ln + _num(row, right) * rn) / total


def _pooled_variance(row: Mapping[str, Any], left_std: str, right_std: str,
                     left_mean: str, right_mean: str,
                     left_n: str, right_n: str) -> float:
    """Pool two population variances without inventing directional labels."""
    ln = _num(row, left_n)
    rn = _num(row, right_n)
    total = ln + rn
    if total <= 0:
        return 0.0
    lm, rm = _num(row, left_mean), _num(row, right_mean)
    lv, rv = _num(row, left_std) ** 2, _num(row, right_std) ** 2
    mean = (lm * ln + rm * rn) / total
    return max((ln * (lv + (lm - mean) ** 2) + rn * (rv + (rm - mean) ** 2)) / total, 0.0)


def from_row(row: Mapping[str, Any]) -> dict[str, float]:
    """Convert one CICFlowMeter/CICFlow-style row to direction-agnostic features."""
    fwd = _num(row, "Total Fwd Packets")
    bwd = _num(row, "Total Backward Packets")
    total_packets = fwd + bwd
    total_bytes = _sum(row, "Total Length of Fwd Packets", "Total Length of Bwd Packets")
    variance = _pooled_variance(
        row, "Fwd Packet Length Std", "Bwd Packet Length Std",
        "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Total Fwd Packets", "Total Backward Packets",
    )
    packet_mean = _weighted_mean(
        row, "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Total Fwd Packets", "Total Backward Packets",
    )
    result = {
        "Destination Port": _num(row, "Destination Port"),
        "Flow Duration": _num(row, "Flow Duration"),
        "Total Packets": total_packets,
        "Total Bytes": total_bytes,
        "Packet Length Max": _max(row, "Fwd Packet Length Max", "Bwd Packet Length Max"),
        "Packet Length Min": _min_nonzero(row, "Fwd Packet Length Min", "Bwd Packet Length Min"),
        "Packet Length Mean": packet_mean,
        "Packet Length Std": variance ** 0.5,
        "Packet Length Variance": variance,
        "Flow Bytes/s": _num(row, "Flow Bytes/s"),
        "Flow Packets/s": _num(row, "Flow Packets/s"),
        "Flow IAT Mean": _num(row, "Flow IAT Mean"),
        "Flow IAT Std": _num(row, "Flow IAT Std"),
        "Flow IAT Max": _num(row, "Flow IAT Max"),
        "Flow IAT Min": _num(row, "Flow IAT Min"),
        "PSH Flags": _sum(row, "Fwd PSH Flags", "Bwd PSH Flags"),
        "URG Flags": _sum(row, "Fwd URG Flags", "Bwd URG Flags"),
        "Header Length": _sum(row, "Fwd Header Length", "Bwd Header Length"),
        "FIN Flag Count": _num(row, "FIN Flag Count"),
        "SYN Flag Count": _num(row, "SYN Flag Count"),
        "RST Flag Count": _num(row, "RST Flag Count"),
        "ACK Flag Count": _num(row, "ACK Flag Count"),
        "Average Packet Size": _num(row, "Average Packet Size") or (
            total_bytes / total_packets if total_packets else 0.0
        ),
    }
    return result


def transform_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the shared unidirectional feature schema, preserving Label."""
    rows = [from_row(row) for row in df.to_dict("records")]
    result = pd.DataFrame(rows, columns=UNIDIRECTIONAL_FEATURES)
    if "Label" in df.columns:
        result["Label"] = df["Label"].values
    elif "label" in df.columns:
        result["label"] = df["label"].values
    return result
