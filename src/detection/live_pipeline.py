from __future__ import annotations

from typing import Callable

import pandas as pd
import time

from src.detection.alert_dedup import AlertDeduplicator
from src.detection.live_detector import LiveThreatDetector
from src.features.live_flow_processor import LiveFlowProcessor
from src.models.runtime import RuntimeModelRegistry
from src.detection.threat_score import calculate_threat_evidence, response_offer


class LiveDetectionPipeline:
    """End-to-end live Zeek -> rules + packet-derived unidirectional ML pipeline.

The live detection gate runs the available detectors in src/detection before ML.
Scanning, DDoS, beaconing, DGA (when DNS query telemetry is present),
forward-only exfiltration, and TLS/QUIC traffic identification can all flag a
source. Packet-derived ML runs only after a source is flagged by this layer.
"""

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
        self._flagged_sources: set[str] = set()
        # Packet capture and Zeek rule processing are asynchronous. Keep a
        # short, bounded queue so a packet seen before its source is flagged
        # is not silently discarded. ML still runs only after rule flagging.
        self._pending_packet_features: list[tuple[float, pd.DataFrame]] = []
        self._pending_packet_max_rows = 2000
        self._pending_packet_ttl_seconds = 15.0

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

    @staticmethod
    def _source_ip(row: pd.Series) -> str | None:
        for column in ("src_ip", "id.orig_h"):
            if column in row.index and pd.notna(row[column]):
                return str(row[column])
        return None

    def _remember_flagged_sources(self, rule_events: list[dict], features: pd.DataFrame) -> None:
        flagged = {str(event["src_ip"]) for event in rule_events if event.get("src_ip")}
        ddos_destinations = {str(event["dst_ip"]) for event in rule_events if event.get("type") == "possible_ddos" and event.get("dst_ip")}
        if ddos_destinations and "id.resp_h" in features.columns:
            flagged.update(
                str(row["id.orig_h"])
                for _, row in features[features["id.resp_h"].astype(str).isin(ddos_destinations)].iterrows()
                if pd.notna(row.get("id.orig_h"))
            )
        self._flagged_sources.update(flagged)

    def _expire_pending_packet_features(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        cutoff = now - self._pending_packet_ttl_seconds
        self._pending_packet_features = [
            (created_at, frame)
            for created_at, frame in self._pending_packet_features
            if created_at >= cutoff and not frame.empty
        ]

    def _queue_pending_packet_features(self, features: pd.DataFrame) -> None:
        if features.empty:
            return
        now = time.monotonic()
        self._expire_pending_packet_features(now)
        self._pending_packet_features.append((now, features.copy()))
        total = sum(len(frame) for _, frame in self._pending_packet_features)
        while total > self._pending_packet_max_rows and self._pending_packet_features:
            _, oldest = self._pending_packet_features.pop(0)
            total -= len(oldest)

    def _flush_pending_for_flagged_sources(self) -> None:
        if not self._pending_packet_features or not self._flagged_sources:
            return
        self._expire_pending_packet_features()
        remaining: list[tuple[float, pd.DataFrame]] = []
        for created_at, frame in self._pending_packet_features:
            source_column = "src_ip" if "src_ip" in frame.columns else "id.orig_h"
            if source_column not in frame.columns:
                remaining.append((created_at, frame))
                continue
            flagged = frame[frame[source_column].astype(str).isin(self._flagged_sources)].copy()
            if not flagged.empty:
                self._emit_scored_ml(flagged)
            unflagged = frame[~frame[source_column].astype(str).isin(self._flagged_sources)].copy()
            if not unflagged.empty:
                remaining.append((created_at, unflagged))
        self._pending_packet_features = remaining

    def _process_features(self, features: pd.DataFrame) -> None:
        rule_events = self.rule_detector.process(features)
        self._remember_flagged_sources(rule_events, features)
        self._flush_pending_for_flagged_sources()

        for event in rule_events:
            # Rule detectors operate on a rolling window, so the same alert
            # can otherwise be emitted on every incoming batch. Suppress only
            # duplicate alert signatures; raw flows and ML predictions remain
            # fully visible.
            if self.alert_dedup.is_duplicate(event):
                continue
            self._emit({"source": "rule", **event})

        # Zeek/rule detection is the first gate. Packet ML is only allowed to
        # judge source IPs that the rule layer has already flagged.

    @property
    def model_status(self) -> dict:
        return self.models.status()

    def process_packet_features(self, features: pd.DataFrame) -> None:
        """Run packet features through ML only after rule-based flagging.

        Packet capture can race ahead of the Zeek rule stream, so unflagged
        rows are buffered briefly and replayed when their source is flagged.
        """
        if features is None or features.empty:
            return
        source_column = "src_ip" if "src_ip" in features.columns else "id.orig_h"
        if source_column not in features.columns:
            return
        self._expire_pending_packet_features()
        flagged = features[features[source_column].astype(str).isin(self._flagged_sources)].copy()
        if not flagged.empty:
            self._emit_scored_ml(flagged)
        unflagged = features[~features[source_column].astype(str).isin(self._flagged_sources)].copy()
        if not unflagged.empty:
            self._queue_pending_packet_features(unflagged)

    def reset(self) -> None:
        """Clear rolling rule state and previously flagged sources."""
        self.rule_detector.reset()
        self._flagged_sources.clear()
        self._pending_packet_features.clear()

    def process_batch(self, batch: pd.DataFrame) -> pd.DataFrame:
        """Process one LiveZeekReader batch."""
        return self.feature_processor.process(batch)

    def run(self, reader, stop_event=None) -> None:
        """Follow a LiveZeekReader until stop_event is set."""
        self.feature_processor.process_reader(reader, stop_event=stop_event)
