from pathlib import Path
import pandas as pd


def detect_exfiltration(log_file):
    log_file = Path(log_file)

    if not log_file.exists():
        print(f"Log file not found: {log_file}")
        return []

    fields = None
    rows = []

    with open(log_file, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip()

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            if line.startswith("#") or not line:
                continue

            if fields:
                values = line.split("\t")

                if len(values) == len(fields):
                    rows.append(dict(zip(fields, values)))

    if not rows:
        return []

    df = pd.DataFrame(rows)

    # Convert byte fields to numbers
    for column in ["orig_bytes", "resp_bytes"]:
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    alerts = []

    for _, flow in df.iterrows():

        outbound = flow.get("orig_bytes", 0)
        inbound = flow.get("resp_bytes", 0)

        total = outbound + inbound

        if total == 0:
            continue

        # Outbound traffic dominates the connection
        outbound_ratio = outbound / total

        # Possible large outbound transfer
        if outbound >= 1_000_000 and outbound_ratio >= 0.80:

            alerts.append({
                "type": "possible_exfiltration",
                "src_ip": flow.get("id.orig_h", "unknown"),
                "dst_ip": flow.get("id.resp_h", "unknown"),
                "outbound_bytes": int(outbound),
                "inbound_bytes": int(inbound),
                "outbound_ratio": round(outbound_ratio, 3),
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