from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import hashlib

from src.detection.beaconing import detect_beaconing
from src.detection.ddos import detect_ddos
from src.detection.scanning import detect_scanning
from src.main import load_flow_features

try:
    from src.detection.exfiltration import detect_exfiltration
except ImportError:
    detect_exfiltration = None

try:
    from src.detection.dga import detect_dga
except ImportError:
    detect_dga = None

from backend.schemas import ThreatAnalysisResponse, ThreatEvent


REPO_ROOT = Path(__file__).resolve().parent.parent


class DetectionInputError(ValueError):
    pass


def run_rule_detectors(
    flows,
    *,
    conn_log: Path | None = None,
    dns_log: Path | None = None,
) -> list[dict]:
    """Run the canonical offline/Zeek rule detector set.

    Live packet ML is handled separately by LiveDetectionPipeline. This
    function is the shared orchestration layer for offline/Zeek dashboard
    analysis so individual web frontends cannot drift into different
    detector combinations or thresholds.
    """
    threats: list[dict] = []

    try:
        threats.extend(
            detect_scanning(flows, min_unique_ports=8, min_connections=8)
        )
    except Exception as exc:
        print(f"[DetectionService] Scanning detector error: {exc}")

    try:
        threats.extend(detect_ddos(flows))
    except Exception as exc:
        print(f"[DetectionService] DDoS detector error: {exc}")

    try:
        threats.extend(
            detect_beaconing(
                flows,
                min_connections=8,
                min_span_seconds=15.0,
                max_interval_cv=0.35,
            )
        )
    except Exception as exc:
        print(f"[DetectionService] Beaconing detector error: {exc}")

    if detect_exfiltration is not None and conn_log is not None:
        try:
            threats.extend(detect_exfiltration(conn_log))
        except Exception as exc:
            print(f"[DetectionService] Exfiltration detector error: {exc}")

    if detect_dga is not None and dns_log is not None and dns_log.exists():
        try:
            threats.extend(detect_dga(dns_log))
        except Exception as exc:
            print(f"[DetectionService] DGA detector error: {exc}")

    return threats



def _resolve_input_path(input_path: str) -> Path:
    if not input_path or not input_path.strip():
        raise DetectionInputError("input_path is required.")

    candidate = Path(input_path.strip())
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate

    return candidate.resolve()


def _event_id(input_path: Path, detector_type: str, result: dict) -> str:
    signature = "|".join(
        [
            str(input_path),
            detector_type,
            str(result.get("src_ip", "")),
            str(result.get("dst_ip", "")),
            str(result.get("connection_count", "")),
            str(result.get("unique_destination_ports", "")),
            str(result.get("unique_sources", "")),
            str(result.get("average_interval", "")),
        ]
    )
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]


def _build_description(result: dict) -> str:
    event_type = result["type"]

    if event_type == "possible_port_scan":
        return (
            "Source contacted the same destination across many destination ports."
        )
    if event_type == "possible_ddos":
        return "Destination received many connections from multiple source IPs."
    if event_type == "possible_beaconing":
        return "Repeated source-to-destination connections suggest periodic beaconing."
    return "Threat detected by the rule-based detection pipeline."


def _normalize_threat(input_path: Path, result: dict) -> ThreatEvent:
    timestamp_value = result.get("timestamp")
    if timestamp_value is None:
        timestamp = datetime.now(UTC).isoformat()
    else:
        timestamp = str(timestamp_value)

    details = {
        key: value
        for key, value in result.items()
        if key not in {"type", "severity", "src_ip", "dst_ip", "timestamp"}
    }

    return ThreatEvent(
        id=_event_id(input_path, result["type"], result),
        type=result["type"],
        severity=str(result.get("severity", "unknown")).upper(),
        source_ip=result.get("src_ip"),
        destination_ip=result.get("dst_ip"),
        timestamp=timestamp,
        description=_build_description(result),
        details=details,
    )


@dataclass
class ThreatAnalysisStore:
    latest_input_path: str | None = None
    latest_threats: list[ThreatEvent] = field(default_factory=list)

    def set(self, input_path: str, threats: list[ThreatEvent]) -> None:
        self.latest_input_path = input_path
        self.latest_threats = threats

    def get(self) -> ThreatAnalysisResponse:
        return ThreatAnalysisResponse(
            input_path=self.latest_input_path or "",
            threat_count=len(self.latest_threats),
            threats=list(self.latest_threats),
        )


class DetectionService:
    def analyze(self, input_path: str) -> ThreatAnalysisResponse:
        resolved_path = _resolve_input_path(input_path)

        if not resolved_path.exists():
            raise FileNotFoundError(f"Input file not found: {resolved_path}")

        flows = load_flow_features(resolved_path)
        raw_results = run_rule_detectors(
            flows,
            conn_log=resolved_path if resolved_path.name == "conn.log" else None,
        )
        threats = [
            _normalize_threat(resolved_path, result)
            for result in raw_results
        ]

        return ThreatAnalysisResponse(
            input_path=str(resolved_path),
            threat_count=len(threats),
            threats=threats,
        )

