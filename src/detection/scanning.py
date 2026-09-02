import pandas as pd


def detect_scanning(flows, min_unique_ports=5):
    """
    Detect possible port-scanning behavior from Zeek connection data.

    A source is suspicious when it contacts the same destination
    using many different destination ports.
    """

    if flows is None:
        raise ValueError("Flow data is required for scanning detection.")

    required_columns = ["id.orig_h", "id.resp_h", "id.resp_p"]
    missing = [column for column in required_columns if column not in flows.columns]
    if missing:
        missing_str = ", ".join(missing)
        raise ValueError(f"Scanning detection requires columns: {missing_str}")

    if flows.empty:
        return []

    results = []

    # Make sure port column is numeric
    flows = flows.copy()
    flows["id.resp_p"] = pd.to_numeric(flows["id.resp_p"], errors="coerce")

    grouped = flows.groupby(["id.orig_h", "id.resp_h"])

    for (src_ip, dst_ip), group in grouped:

        unique_ports = group["id.resp_p"].dropna().nunique()
        connection_count = len(group)

        if unique_ports >= min_unique_ports:

            results.append({
                "type": "possible_port_scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "unique_destination_ports": unique_ports,
                "connection_count": connection_count,
                "severity": "medium"
            })

    return results


if __name__ == "__main__":

    feature_file = "data/processed/features.csv"

    flows = pd.read_csv(feature_file)

    print("\n=== Port Scanning Detection ===")

    alerts = detect_scanning(flows)

    if not alerts:
        print("No scanning activity detected.")
    else:
        for alert in alerts:
            print(alert)
