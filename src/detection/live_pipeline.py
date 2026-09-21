from __future__ import annotations

from typing import Callable

import pandas as pd

from src.detection.live_detector import LiveThreatDetector
from src.features.live_flow_processor import LiveFlowProcessor
from src.models.runtime import RuntimeModelRegistry


class LiveDetectionPipeline:
    """End-to-end live Zeek -> features -> rules + optional ML pipeline."""

    def __init__(
        self,
        max_rows: int = 1000,
        model_paths: dict[str, str] | None = None,
        callback: Callable[[dict], None] | None = None,
    ) -> None:
        self.rule_detector = LiveThreatDetector(max_rows=max_rows)
        self.models = RuntimeModelRegistry(model_paths)
        self.callback = callback
        self.feature_processor = LiveFlowProcessor(callback=self._process_features)

    def _emit(self, event: dict) -> None:
        if self.callback is not None:
            self.callback(event)

    def _process_features(self, features: pd.DataFrame) -> None:
        rule_events = self.rule_detector.process(features)

        for event in rule_events:
            enriched = {"source": "rule", **event}
            self._emit(enriched)

        try:
            ml_events = self.models.predict(features)
        except (ValueError, RuntimeError) as exc:
            self._emit(
                {
                    "source": "ml",
                    "type": "ml_inference_error",
                    "severity": "low",
                    "error": str(exc),
                }
            )
            return

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

    @property
    def model_status(self) -> dict:
        return self.models.status()

    def process_packet_features(self, features: pd.DataFrame) -> None:
        """Run packet-derived CICFlow features through the trained ML models."""
        if features is None or features.empty:
            return

        try:
            ml_events = self.models.predict(features)
        except (ValueError, RuntimeError) as exc:
            self._emit(
                {
                    "source": "ml",
                    "type": "ml_inference_error",
                    "severity": "low",
                    "error": str(exc),
                }
            )
            return

        for index, event in enumerate(ml_events):
            self._emit(
                {
                    "source": "ml",
                    "type": "ml_prediction",
                    "severity": "high"
                    if event.get("label", "").lower() not in {"benign", "normal"}
                    else "info",
                    "flow_index": index,
                    **event,
                }
            )

    def process_batch(self, batch: pd.DataFrame) -> pd.DataFrame:
        """Process one LiveZeekReader batch."""
        return self.feature_processor.process(batch)

    def run(self, reader, stop_event=None) -> None:
        """Follow a LiveZeekReader until stop_event is set."""
        self.feature_processor.process_reader(reader, stop_event=stop_event)
