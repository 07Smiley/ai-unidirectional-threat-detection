"""Normalize ML/rule evidence to a 0-100 threat score."""

from __future__ import annotations

from typing import Iterable, Mapping


def calculate_threat_score(events: Iterable[Mapping[str, object]]) -> float:
    """Return the strongest malicious evidence as a 0-100 score.

    BENIGN/NORMAL predictions contribute zero. The score is intentionally
    transparent; later versions can add calibrated multi-model aggregation.
    """
    scores: list[float] = []
    for event in events:
        label = str(event.get("label", "")).lower()
        if label in {"", "benign", "normal"}:
            continue
        try:
            confidence = float(event.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        scores.append(max(0.0, min(1.0, confidence)) * 100.0)
    return round(max(scores, default=0.0), 2)


def calculate_threat_evidence(events: Iterable[Mapping[str, object]]) -> dict:
    """Return the strongest malicious prediction and its exact source flow.

    The response target is derived from the same prediction that produced the
    score. This prevents a high-confidence prediction for one IP from being
    paired with another prediction's IP when several models/flows are emitted
    in the same batch.
    """
    best: dict = {
        "score": 0.0,
        "source_ip": None,
        "destination_ip": None,
        "model": None,
        "label": None,
        "confidence": 0.0,
        "prediction": None,
    }
    for event in events:
        label = str(event.get("label", "")).lower()
        if label in {"", "benign", "normal"}:
            continue
        try:
            confidence = max(0.0, min(1.0, float(event.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence * 100.0 <= best["score"]:
            continue
        prediction = {
            "model": event.get("model"),
            "label": event.get("label"),
            "confidence": confidence,
            "probabilities": event.get("probabilities", {}),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
        }
        best.update({
            "score": round(confidence * 100.0, 2),
            "source_ip": event.get("src_ip"),
            "destination_ip": event.get("dst_ip"),
            "model": event.get("model"),
            "label": event.get("label"),
            "confidence": confidence,
            "prediction": prediction,
        })
    return best


def response_offer(score: float, threshold: float = 92.0) -> bool:
    """Whether the UI should offer a response action; never performs it."""
    return float(score) >= float(threshold)
