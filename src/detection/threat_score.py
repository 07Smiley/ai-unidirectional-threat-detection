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


def response_offer(score: float, threshold: float = 92.0) -> bool:
    """Whether the UI should offer a response action; never performs it."""
    return float(score) >= float(threshold)
