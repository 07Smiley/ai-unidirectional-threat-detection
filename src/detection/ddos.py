import pandas as pd


def detect_ddos(
    flows,
    min_connections=20,
    min_unique_sources=5
):
    """
    Detect possible DDoS-like behavior from Zeek connection data.

    The detector looks for:
    - Many connections to the same destination
    - Traffic originating from multiple source IPs
    """

    if flows is None:
        raise ValueError("Flow data is required for DDoS detection.")

    required_columns = ["id.resp_h", "id.orig_h"]
    missing = [column for column in required_columns if column not in flows.columns]
    if missing:
        missing_str = ", ".join(missing)
        raise ValueError(f"DDoS detection requires columns: {missing_str}")

    if flows.empty:
        return []

    results = []

    flows = flows.copy()

    # Group traffic by destination
    grouped = flows.groupby("id.resp_h")

    for dst_ip, group in grouped:

        connection_count = len(group)
        unique_sources = group["id.orig_h"].nunique()

        # DDoS suspicion condition
        if (
            connection_count >= min_connections
            and unique_sources >= min_unique_sources
        ):
            results.append({
                "type": "possible_ddos",
                "dst_ip": dst_ip,
                "connection_count": connection_count,
                "unique_sources": unique_sources,
                "severity": "high"
            })

    return results


if __name__ == "__main__":

    from src.ingest.pcap_reader import read_zeek_log

    log_file = "data/processed/zeek/live/conn.log"

    # Read real Zeek traffic
    flows = read_zeek_log(log_file)

    print("\n=== DDoS Detection ===")
    print(f"Connections analyzed: {len(flows)}")

    alerts = detect_ddos(flows)

    if not alerts:
        print("No DDoS-like activity detected.")
    else:
        print(f"Possible DDoS activity: {len(alerts)}")

        for alert in alerts:
            print(alert)
