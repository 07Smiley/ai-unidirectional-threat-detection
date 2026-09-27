from pathlib import Path
import pandas as pd

from src.ingest.pcap_reader import read_zeek_log


def detect_exfiltration(log_file):
    log_file = Path(log_file)

    if not log_file.exists():
        raise FileNotFoundError(f"Could not read Zeek log: file not found: {log_file}")

    df = read_zeek_log(log_file)

    if df.empty:
        return []

    # Only the observed/originating direction is used. Reverse traffic may
    # be unavailable in a one-way monitoring deployment.
    if "orig_bytes" not in df.columns:
        raise ValueError(
            "Exfiltration detection requires the 'orig_bytes' column."
        )
    df["orig_bytes"] = pd.to_numeric(
        df["orig_bytes"], errors="coerce"
    ).fillna(0)

    alerts = []

    for _, flow in df.iterrows():

        outbound = float(flow.get("orig_bytes", 0))

        # Possible large observed-direction transfer. No reverse-direction
        # bytes are used to qualify or score the event.
        if outbound >= 1_000_000:

            alerts.append({
                "type": "possible_exfiltration",
                "src_ip": flow.get("id.orig_h", "unknown"),
                "dst_ip": flow.get("id.resp_h", "unknown"),
                "outbound_bytes": int(outbound),
                "severity": "medium"
            })

    return alerts


if __name__ == "__main__":

    log_file = "data/processed/zeek/live/conn.log"

    print("\n=== Exfiltration Detection ===")

    alerts = detect_exfiltration(log_file)

    print(f"Connections analyzed: ", end="")

    # Count actual Zeek records
    with open(log_file, "r", errors="ignore") as f:
        count = sum(
            1 for line in f
            if line.strip() and not line.startswith("#")
        )

    print(count)

    if not alerts:
        print("No possible exfiltration activity detected.")
    else:
        print(f"Possible exfiltration activity: {len(alerts)}")

        for alert in alerts[:20]:
            print(alert)
