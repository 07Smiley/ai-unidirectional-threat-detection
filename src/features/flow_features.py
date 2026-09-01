import pandas as pd
import numpy as np


def create_flow_features(df):
    """
    Convert raw Zeek connection data into
    machine-learning-friendly network features.
    """

    # Make a copy so we don't modify the original DataFrame
    features = df.copy()

    # --------------------------------------------------
    # 1. Convert numeric columns
    # --------------------------------------------------

    numeric_columns = [
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "missed_bytes"
    ]

    for column in numeric_columns:
        if column in features.columns:
            features[column] = pd.to_numeric(
                features[column],
                errors="coerce"
            ).fillna(0)

    # --------------------------------------------------
    # 2. Flow duration
    # --------------------------------------------------

    features["flow_duration"] = features["duration"]

    # --------------------------------------------------
    # 3. Total packets
    # --------------------------------------------------

    features["total_packets"] = (
        features["orig_pkts"] +
        features["resp_pkts"]
    )

    # --------------------------------------------------
    # 4. Total bytes
    # --------------------------------------------------

    features["total_bytes"] = (
        features["orig_bytes"] +
        features["resp_bytes"]
    )

    # --------------------------------------------------
    # 5. Packet rate
    # --------------------------------------------------

    features["packet_rate"] = np.where(
        features["flow_duration"] > 0,
        features["total_packets"] / features["flow_duration"],
        0
    )

    # --------------------------------------------------
    # 6. Byte rate
    # --------------------------------------------------

    features["byte_rate"] = np.where(
        features["flow_duration"] > 0,
        features["total_bytes"] / features["flow_duration"],
        0
    )

    # --------------------------------------------------
    # 7. Average packet size
    # --------------------------------------------------

    features["average_packet_size"] = np.where(
        features["total_packets"] > 0,
        features["total_bytes"] / features["total_packets"],
        0
    )

    # --------------------------------------------------
    # 8. Outbound / inbound byte ratio
    # --------------------------------------------------

    features["byte_ratio"] = np.where(
        features["resp_bytes"] > 0,
        features["orig_bytes"] / features["resp_bytes"],
        features["orig_bytes"]
    )

    # --------------------------------------------------
    # 9. Packet ratio
    # --------------------------------------------------

    features["packet_ratio"] = np.where(
        features["resp_pkts"] > 0,
        features["orig_pkts"] / features["resp_pkts"],
        features["orig_pkts"]
    )

    return features


if __name__ == "__main__":

    from src.ingest.pcap_reader import read_zeek_log

    log_file = "data/processed/zeek/conn.log"

    # Read Zeek data
    df = read_zeek_log(log_file)

    # Create security features
    feature_df = create_flow_features(df)

    print("\n=== Generated Network Features ===")

    selected_columns = [
        "id.orig_h",
        "id.resp_h",
        "id.orig_p",
        "id.resp_p",
        "proto",
        "flow_duration",
        "total_packets",
        "total_bytes",
        "packet_rate",
        "byte_rate",
        "average_packet_size",
        "byte_ratio",
        "packet_ratio"
    ]

    print(feature_df[selected_columns])

    print("\n=== Feature Names ===")
    print(feature_df.columns.tolist())
    # Create security features
if __name__ == "__main__":
    feature_df = create_flow_features(df)

    output_file = "data/processed/features.csv"
    feature_df.to_csv(output_file, index=False)

    print(f"Features saved to {output_file}")