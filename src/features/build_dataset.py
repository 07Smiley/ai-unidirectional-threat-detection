import csv
from pathlib import Path

from scapy.all import rdpcap
from src.features.flow_features import extract_flow_features


PCAP_LABELS = {
    "sample.pcap": "normal",
    "flow_test.pcap": "scanning",
    "ddos_test.pcap": "ddos",
    "beacon_test.pcap": "beaconing",
}


def build_dataset():
    samples_dir = Path("data/samples")
    output_file = Path("data/processed/training_data.csv")

    rows = []

    for filename, label in PCAP_LABELS.items():
        pcap_path = samples_dir / filename

        if not pcap_path.exists():
            print(f"[!] Skipping missing file: {pcap_path}")
            continue

        print(f"[+] Processing: {pcap_path}")

        packets = rdpcap(str(pcap_path))
        flows = extract_flow_features(packets)

        for flow in flows.to_dict("records"):
            rows.append({
                "packet_count": flow["total_packets"],
                "total_bytes": flow["total_bytes"],
                "duration": flow["flow_duration"],
                "packet_rate": flow["packet_rate"],
                "average_packet_size": flow["average_packet_size"],
                "label": label,
            })

    output_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "packet_count",
        "total_bytes",
        "duration",
        "packet_rate",
        "average_packet_size",
        "label",
    ]

    with open(output_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print()
    print("======================================")
    print(" ML DATASET CREATED")
    print("======================================")
    print(f"Samples written: {len(rows)}")
    print(f"Output: {output_file}")


if __name__ == "__main__":
    build_dataset()
