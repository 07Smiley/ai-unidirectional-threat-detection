from __future__ import annotations

from typing import Callable

import pandas as pd

from src.detection.alert_dedup import AlertDeduplicator
from src.detection.live_detector import LiveThreatDetector
from src.features.live_flow_processor import LiveFlowProcessor
from src.models.runtime import RuntimeModelRegistry
from src.detection.threat_score import calculate_threat_evidence, response_offer


class LiveDetectionPipeline:
    """End-to-end live Zeek -> features -> rules + optional ML pipeline."""

    def __init__(
        self,
        max_rows: int = 1000,
        model_paths: dict[str, str] | None = None,
        callback: Callable[[dict], None] | None = None,
    ) -> None:
        self.rule_detector = LiveThreatDetector(max_rows=max_rows)
        self.alert_dedup = AlertDeduplicator(window_seconds=30.0)
        self.models = RuntimeModelRegistry(model_paths)
        self.callback = callback
        self.feature_processor = LiveFlowProcessor(callback=self._process_features)

    def _emit(self, event: dict) -> None:
        if self.callback is not None:
            self.callback(event)

    @staticmethod
    def _metadata(row: pd.Series) -> dict:
        """Extract routing metadata without feeding it into the ML model."""
        mapping = {
            "src_ip": ("src_ip", "id.orig_h"),
            "dst_ip": ("dst_ip", "id.resp_h"),
            "src_port": ("src_port", "id.orig_p"),
            "dst_port": ("dst_port", "id.resp_p"),
            "protocol": ("protocol", "proto"),
            "timestamp": ("first_seen", "ts"),
        }
        result = {}
        for output, candidates in mapping.items():
            for column in candidates:
                if column in row.index and pd.notna(row[column]):
                    result[output] = row[column]
                    break
        return result

    def _emit_ml_predictions(self, features: pd.DataFrame) -> list[dict]:
        """Run all loaded models and preserve the row each prediction belongs to."""
        raw = self.models.predict(features)
        model_names = list(getattr(self.models, "models", {}))
        rows_per_model = len(features)
        events = []

        if not model_names:
            # Test doubles and alternate registries may return one prediction
            # per row without exposing their internal model collection.
            for row_index, event in enumerate(raw[:rows_per_model]):
                item = dict(event)
                item["flow_index"] = row_index
                item.update(self._metadata(features.iloc[row_index]))
                events.append(item)
            return events

        offset = 0
        for _model_name in model_names:
            for row_index in range(rows_per_model):
                if offset + row_index >= len(raw):
                    break
                event = dict(raw[offset + row_index])
                event["flow_index"] = row_index
                event.update(self._metadata(features.iloc[row_index]))
                events.append(event)
            offset += rows_per_model

        return events

    def _emit_scored_ml(self, features: pd.DataFrame) -> list[dict]:
        try:
            ml_events = self._emit_ml_predictions(features)
        except (ValueError, RuntimeError) as exc:
            self._emit(
                {
                    "source": "ml",
                    "type": "ml_inference_error",
                    "severity": "low",
                    "error": str(exc),
                }
            )
            return []

        for event in ml_events:
            self._emit(
                {
                    "source": "ml",
                    "type": "ml_prediction",
                    "severity": "high"
                    if event.get("label", "").lower() not in {"benign", "normal"}
                    else "info",
                    **event,
                }
            )

        evidence = calculate_threat_evidence(ml_events)
        score = evidence["score"]
        self._emit(
            {
                "source": "scoring",
                "type": "threat_score",
                "score": score,
                "response_available": response_offer(score),
                "source_ip": evidence["source_ip"],
                "destination_ip": evidence["destination_ip"],
                "prediction": evidence["prediction"],
            }
        )
        return ml_events

    def _process_features(self, features: pd.DataFrame) -> None:
        rule_events = self.rule_detector.process(features)

        for event in rule_events:
            # Rule detectors operate on a rolling window, so the same alert
            # can otherwise be emitted on every incoming batch. Suppress only
            # duplicate alert signatures; raw flows and ML predictions remain
            # fully visible.
            if self.alert_dedup.is_duplicate(event):
                continue
            self._emit({"source": "rule", **event})

        self._emit_scored_ml(features)

    @property
    def model_status(self) -> dict:
        return self.models.status()

    def process_packet_features(self, features: pd.DataFrame) -> None:
        """Run packet-derived CICFlow features through the trained ML models."""
        if features is None or features.empty:
            return
        self._emit_scored_ml(features)

    def process_batch(self, batch: pd.DataFrame) -> pd.DataFrame:
        """Process one LiveZeekReader batch."""
        return self.feature_processor.process(batch)

    def run(self, reader, stop_event=None) -> None:
        """Follow a LiveZeekReader until stop_event is set."""
        self.feature_processor.process_reader(reader, stop_event=stop_event)
