import pandas as pd


def detect_beaconing(flows, min_connections=5):
    """
    Detect possible command-and-control (C2) communication.

    Looks for repeated connections from the same source to the
    same destination, which can be a basic indicator of C2.
    """

    if flows is None:
        raise ValueError("Flow data is required for beaconing detection.")

    required_columns = ["id.orig_h", "id.resp_h", "ts"]
    missing = [column for column in required_columns if column not in flows.columns]
    if missing:
        missing_str = ", ".join(missing)
        raise ValueError(f"Beaconing detection requires columns: {missing_str}")

    if flows.empty:
        return []

    results = []

    flows = flows.copy()

    flows["ts"] = pd.to_numeric(flows["ts"], errors="coerce")

    # Group by source and destination
    grouped = flows.groupby(["id.orig_h", "id.resp_h"])

    for (src_ip, dst_ip), group in grouped:

        connection_count = len(group)

        if connection_count >= min_connections:
            timestamps = group["ts"].dropna().sort_values(kind="mergesort")

            if len(timestamps) >= 2:
                intervals = timestamps.diff().dropna()
                average_interval = (
                    float(intervals.mean()) if not intervals.empty else None
                )
            else:
                average_interval = None

            results.append({
                "type": "possible_beaconing",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "connection_count": connection_count,
                "average_interval": average_interval,
                "severity": "medium"
            })

    return results


def detect_c2(flows, min_connections=5):
    return detect_beaconing(flows, min_connections=min_connections)


if __name__ == "__main__":

    from src.ingest.pcap_reader import read_zeek_log

    log_file = "data/processed/zeek/live/conn.log"

    flows = read_zeek_log(log_file)

    print("\n=== C2 Detection ===")
    print(f"Connections analyzed: {len(flows)}")

    alerts = detect_beaconing(flows)

    if not alerts:
        print("No C2-like activity detected.")
    else:
        print(f"Possible C2 activity: {len(alerts)}")

        for alert in alerts:
            print(alert)
