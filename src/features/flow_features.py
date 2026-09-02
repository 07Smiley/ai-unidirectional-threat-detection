from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.layers.inet import ICMP, IP, TCP, UDP


FLOW_COLUMNS = [
    "ts",
    "id.orig_h",
    "id.resp_h",
    "id.orig_p",
    "id.resp_p",
    "proto",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "missed_bytes",
]

REQUIRED_ZEEK_COLUMNS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
]


def _build_empty_feature_frame():
    return pd.DataFrame(columns=FLOW_COLUMNS + [
        "flow_duration",
        "total_packets",
        "total_bytes",
        "packet_rate",
        "byte_rate",
        "average_packet_size",
        "byte_ratio",
        "packet_ratio",
    ])


def _ensure_required_columns(df, required_columns):
    missing = [column for column in required_columns if column not in df.columns]
    if missing:
        missing_str = ", ".join(missing)
        raise ValueError(f"Missing required flow columns: {missing_str}")


def _packet_proto_and_ports(packet):
    if TCP in packet:
        return "tcp", int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return "udp", int(packet[UDP].sport), int(packet[UDP].dport)
    if ICMP in packet:
        return "icmp", None, None
    return str(packet[IP].proto), None, None


def _packets_to_flow_dataframe(packets):
    flows = defaultdict(lambda: {
        "ts": None,
        "id.orig_h": None,
        "id.resp_h": None,
        "id.orig_p": None,
        "id.resp_p": None,
        "proto": None,
        "duration": 0.0,
        "orig_bytes": 0,
        "resp_bytes": 0,
        "orig_pkts": 0,
        "resp_pkts": 0,
        "orig_ip_bytes": 0,
        "resp_ip_bytes": 0,
        "missed_bytes": 0,
        "_first_seen": None,
        "_last_seen": None,
    })

    usable_packets = 0

    for packet in packets:
        if IP not in packet:
            continue

        proto, src_port, dst_port = _packet_proto_and_ports(packet)
        timestamp = float(packet.time)
        packet_size = int(len(packet))
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows[key]

        if flow["_first_seen"] is None:
            flow["ts"] = timestamp
            flow["id.orig_h"] = src_ip
            flow["id.resp_h"] = dst_ip
            flow["id.orig_p"] = src_port
            flow["id.resp_p"] = dst_port
            flow["proto"] = proto
            flow["_first_seen"] = timestamp

        flow["_last_seen"] = timestamp
        flow["orig_pkts"] += 1
        flow["orig_bytes"] += packet_size
        flow["orig_ip_bytes"] += packet_size
        usable_packets += 1

    if usable_packets == 0:
        raise ValueError("No usable network packets were found in the supplied PCAP.")

    rows = []
    for flow in flows.values():
        flow["duration"] = max(flow["_last_seen"] - flow["_first_seen"], 0.0)
        rows.append({column: flow[column] for column in FLOW_COLUMNS})

    return pd.DataFrame(rows, columns=FLOW_COLUMNS)


def extract_flow_features(df):
    """
    Convert Zeek-style connection records into derived flow features.
    """

    if df is None:
        raise ValueError("Flow data is required.")

    _ensure_required_columns(df, REQUIRED_ZEEK_COLUMNS)

    if df.empty:
        return _build_empty_feature_frame()

    features = df.copy()

    numeric_columns = [
        "ts",
        "id.orig_p",
        "id.resp_p",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "missed_bytes",
    ]

    for column in numeric_columns:
        if column in features.columns:
            features[column] = pd.to_numeric(features[column], errors="coerce")

    for column in ["orig_ip_bytes", "resp_ip_bytes", "missed_bytes"]:
        if column not in features.columns:
            features[column] = 0

    fill_zero_columns = [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "missed_bytes",
    ]

    for column in fill_zero_columns:
        features[column] = features[column].fillna(0)

    features["flow_duration"] = features["duration"]
    features["total_packets"] = features["orig_pkts"] + features["resp_pkts"]
    features["total_bytes"] = features["orig_bytes"] + features["resp_bytes"]

    features["packet_rate"] = np.where(
        features["flow_duration"] > 0,
        features["total_packets"] / features["flow_duration"],
        0,
    )
    features["byte_rate"] = np.where(
        features["flow_duration"] > 0,
        features["total_bytes"] / features["flow_duration"],
        0,
    )
    features["average_packet_size"] = np.where(
        features["total_packets"] > 0,
        features["total_bytes"] / features["total_packets"],
        0,
    )
    features["byte_ratio"] = np.where(
        features["resp_bytes"] > 0,
        features["orig_bytes"] / features["resp_bytes"],
        features["orig_bytes"],
    )
    features["packet_ratio"] = np.where(
        features["resp_pkts"] > 0,
        features["orig_pkts"] / features["resp_pkts"],
        features["orig_pkts"],
    )

    return features


def extract_flow_features(packets):
    """
    Aggregate a PCAP packet sequence into Zeek-like flow rows and derive features.
    """

    flow_df = _packets_to_flow_dataframe(packets)
    return extract_flow_features(flow_df)
