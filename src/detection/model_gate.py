"""Candidate gates for ML-only threat families.

These are intentionally conservative routing signals, not final classifiers.
They only decide whether a source has enough first-stage evidence to allow
packet-derived ML inference.
"""
from __future__ import annotations

import pandas as pd


def _required(frame: pd.DataFrame, columns: list[str]) -> bool:
    return all(column in frame.columns for column in columns)


def detect_dos_candidates(flows: pd.DataFrame, min_connections: int = 20) -> list[dict]:
    """Flag single-source high-connection bursts distinct from multi-source DDoS."""
    if flows is None or flows.empty or not _required(
        flows, ["id.orig_h", "id.resp_h"]
    ):
        return []
    grouped = flows.groupby(["id.orig_h", "id.resp_h"])
    events = []
    for (src_ip, dst_ip), group in grouped:
        if len(group) >= min_connections:
            events.append({
                "type": "possible_dos_candidate",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "connection_count": int(len(group)),
                "severity": "medium",
                "gate": "dos",
            })
    return events


def detect_patator_candidates(flows: pd.DataFrame, min_attempts: int = 8) -> list[dict]:
    """Flag repeated connections to one service as a brute-force candidate."""
    if flows is None or flows.empty or not _required(
        flows, ["id.orig_h", "id.resp_h", "id.resp_p"]
    ):
        return []
    grouped = flows.groupby(["id.orig_h", "id.resp_h", "id.resp_p"])
    events = []
    for (src_ip, dst_ip, dst_port), group in grouped:
        if len(group) >= min_attempts:
            events.append({
                "type": "possible_patator_candidate",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attempt_count": int(len(group)),
                "severity": "medium",
                "gate": "patator",
            })
    return events


def detect_webattack_candidates(flows: pd.DataFrame) -> list[dict]:
    """Use HTTP telemetry when available; conn-only data cannot classify web attacks."""
    if flows is None or flows.empty:
        return []
    telemetry = [c for c in ("method", "uri", "status_code", "id.resp_p") if c in flows.columns]
    if not any(c in flows.columns for c in ("method", "uri", "status_code")):
        return []

    events = []
    for _, row in flows.iterrows():
        method = str(row.get("method", "")).upper()
        uri = str(row.get("uri", "")).lower()
        status = pd.to_numeric(row.get("status_code"), errors="coerce")
        suspicious_uri = any(token in uri for token in ("../", "%2e", "union", "select", "<script", "cmd="))
        suspicious_method = method in {"TRACE", "CONNECT"}
        suspicious_status = pd.notna(status) and int(status) >= 500
        if suspicious_uri or suspicious_method or suspicious_status:
            events.append({
                "type": "possible_webattack_candidate",
                "src_ip": row.get("id.orig_h", "unknown"),
                "dst_ip": row.get("id.resp_h", "unknown"),
                "dst_port": row.get("id.resp_p"),
                "severity": "medium",
                "gate": "webattack",
            })
    return events


def detect_infiltration_candidates(flows: pd.DataFrame) -> list[dict]:
    """Use explicit Zeek telemetry when present; conn-only traffic is insufficient."""
    if flows is None or flows.empty:
        return []
    if "history" not in flows.columns and "conn_state" not in flows.columns:
        return []

    events = []
    for _, row in flows.iterrows():
        history = str(row.get("history", ""))
        state = str(row.get("conn_state", ""))
        missed = pd.to_numeric(row.get("missed_bytes"), errors="coerce")
        if state in {"REJ", "RSTO", "RSTR"} and ("S" in history or "R" in history):
            events.append({
                "type": "possible_infiltration_candidate",
                "src_ip": row.get("id.orig_h", "unknown"),
                "dst_ip": row.get("id.resp_h", "unknown"),
                "severity": "low",
                "gate": "infiltration",
            })
        elif pd.notna(missed) and float(missed) > 0:
            events.append({
                "type": "possible_infiltration_candidate",
                "src_ip": row.get("id.orig_h", "unknown"),
                "dst_ip": row.get("id.resp_h", "unknown"),
                "severity": "low",
                "gate": "infiltration",
            })
    return events


def detect_model_candidates(flows: pd.DataFrame) -> list[dict]:
    """Run candidate gates for ML families lacking dedicated classifiers."""
    return (
        detect_dos_candidates(flows)
        + detect_patator_candidates(flows)
        + detect_webattack_candidates(flows)
        + detect_infiltration_candidates(flows)
    )
