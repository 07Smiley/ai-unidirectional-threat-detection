from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Any

import numpy as np
from scapy.layers.inet import IP, TCP, UDP


CICFLOW_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
]


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (
        float(mean(values)),
        float(pstdev(values)) if len(values) > 1 else 0.0,
        float(max(values)),
        float(min(values)),
    )


def _iat_stats(times: list[float]) -> tuple[float, float, float, float, float]:
    """Return IAT statistics in microseconds, matching CICFlowMeter semantics."""
    if len(times) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    gaps = (np.diff(times).astype(float) * 1_000_000.0).tolist()
    return (
        float(sum(gaps)),
        float(mean(gaps)),
        float(pstdev(gaps)) if len(gaps) > 1 else 0.0,
        float(max(gaps)),
        float(min(gaps)),
    )


@dataclass
class _FlowState:
    first_seen: float
    last_seen: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    fwd_sizes: list[float] = field(default_factory=list)
    bwd_sizes: list[float] = field(default_factory=list)
    fwd_times: list[float] = field(default_factory=list)
    bwd_times: list[float] = field(default_factory=list)
    fwd_header_lengths: list[float] = field(default_factory=list)
    bwd_header_lengths: list[float] = field(default_factory=list)
    flags: dict[str, int] = field(
        default_factory=lambda: {
            "FIN": 0,
            "SYN": 0,
            "RST": 0,
            "PSH": 0,
            "ACK": 0,
            "URG": 0,
        }
    )
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0

    def add(self, timestamp: float, packet_size: int, forward: bool, header_len: int, flags: str = "") -> None:
        self.last_seen = timestamp
        if forward:
            self.fwd_sizes.append(float(packet_size))
            self.fwd_times.append(timestamp)
            self.fwd_header_lengths.append(float(header_len))
            self.fwd_psh += int("P" in flags)
            self.fwd_urg += int("U" in flags)
        else:
            self.bwd_sizes.append(float(packet_size))
            self.bwd_times.append(timestamp)
            self.bwd_header_lengths.append(float(header_len))
            self.bwd_psh += int("P" in flags)
            self.bwd_urg += int("U" in flags)

        for flag in self.flags:
            self.flags[flag] += int(flag[0] in flags)


class CICFlowExtractor:
    """Builds packet-derived CICFlow-style features for one packet-direction flow.

    This deliberately emits only values that can be derived from observed packets.
    It does not fabricate unavailable features.
    """

    def __init__(self) -> None:
        self._flows: dict[tuple[Any, ...], _FlowState] = {}

    @staticmethod
    def _packet_parts(packet):
        if IP not in packet:
            return None

        if TCP in packet:
            layer = packet[TCP]
            proto = "tcp"
            src_port, dst_port = int(layer.sport), int(layer.dport)
            header_len = int(layer.dataofs or 5) * 4
            payload_bytes = int(len(layer.payload))
            flags = str(layer.flags)
        elif UDP in packet:
            layer = packet[UDP]
            proto = "udp"
            src_port, dst_port = int(layer.sport), int(layer.dport)
            header_len = 8
            payload_bytes = int(len(layer.payload))
            flags = ""
        else:
            proto = str(packet[IP].proto)
            src_port = dst_port = 0
            header_len = int(packet[IP].ihl or 5) * 4
            payload_bytes = max(int(len(packet[IP].payload)), 0)
            flags = ""

        return (
            float(packet.time),
            packet[IP].src,
            packet[IP].dst,
            src_port,
            dst_port,
            proto,
            payload_bytes,
            header_len,
            flags,
        )

    def add_packet(self, packet) -> None:
        parts = self._packet_parts(packet)
        if parts is None:
            return

        ts, src, dst, src_port, dst_port, proto, payload_bytes, header_len, flags = parts
        key = (src, dst, src_port, dst_port, proto)
        reverse = (dst, src, dst_port, src_port, proto)

        if key in self._flows:
            state = self._flows[key]
            forward = True
        elif reverse in self._flows:
            state = self._flows[reverse]
            forward = False
        else:
            state = _FlowState(
                first_seen=ts,
                last_seen=ts,
                src_ip=src,
                dst_ip=dst,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
            )
            self._flows[key] = state
            forward = True

        state.add(ts, payload_bytes, forward, header_len, flags)

    def rows(self) -> list[dict[str, Any]]:
        return [self._row(state) for state in self._flows.values()]

    def flush(self) -> list[dict[str, Any]]:
        """Emit and clear every currently tracked flow."""
        rows = self.rows()
        self._flows.clear()
        return rows

    def pop_completed(self, idle_timeout: float, now: float | None = None) -> list[dict[str, Any]]:
        if now is None:
            import time
            now = time.time()

        completed = []
        for key, state in list(self._flows.items()):
            if now - state.last_seen >= idle_timeout:
                completed.append(self._row(state))
                del self._flows[key]
        return completed

    @staticmethod
    def _row(state: _FlowState) -> dict[str, Any]:
        duration = max(state.last_seen - state.first_seen, 0.0)
        all_sizes = state.fwd_sizes + state.bwd_sizes
        all_times = sorted(state.fwd_times + state.bwd_times)

        fwd_mean, fwd_std, fwd_max, fwd_min = _stats(state.fwd_sizes)
        bwd_mean, bwd_std, bwd_max, bwd_min = _stats(state.bwd_sizes)
        pkt_mean, pkt_std, pkt_max, pkt_min = _stats(all_sizes)
        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_times)
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(state.fwd_times)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(state.bwd_times)

        total_packets = len(all_sizes)
        total_bytes = sum(all_sizes)

        def rate(value: float) -> float:
            return value / duration if duration > 0 else 0.0

        return {
            # Metadata is carried alongside the feature vector for alert routing.
            # Runtime model input selects only CICFLOW_FEATURES, so these fields
            # never become training features.
            "src_ip": state.src_ip,
            "dst_ip": state.dst_ip,
            "src_port": state.src_port,
            "dst_port": state.dst_port,
            "protocol": state.proto,
            "first_seen": state.first_seen,
            "last_seen": state.last_seen,
            "Destination Port": state.dst_port,
            "Flow Duration": duration * 1_000_000.0,
            "Total Fwd Packets": len(state.fwd_sizes),
            "Total Backward Packets": len(state.bwd_sizes),
            "Total Length of Fwd Packets": sum(state.fwd_sizes),
            "Total Length of Bwd Packets": sum(state.bwd_sizes),
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": rate(total_bytes),
            "Flow Packets/s": rate(total_packets),
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": state.fwd_psh,
            "Bwd PSH Flags": state.bwd_psh,
            "Fwd URG Flags": state.fwd_urg,
            "Bwd URG Flags": state.bwd_urg,
            "Fwd Header Length": sum(state.fwd_header_lengths),
            "Bwd Header Length": sum(state.bwd_header_lengths),
            "Fwd Packets/s": rate(len(state.fwd_sizes)),
            "Bwd Packets/s": rate(len(state.bwd_sizes)),
            "Min Packet Length": pkt_min,
            "Max Packet Length": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": pkt_std * pkt_std,
            "FIN Flag Count": state.flags["FIN"],
            "SYN Flag Count": state.flags["SYN"],
            "RST Flag Count": state.flags["RST"],
            "PSH Flag Count": state.flags["PSH"],
            "ACK Flag Count": state.flags["ACK"],
            "URG Flag Count": state.flags["URG"],
            "Average Packet Size": total_bytes / total_packets if total_packets else 0.0,
        }
