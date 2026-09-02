from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import rdpcap

from src.features.flow_features import create_flow_features, extract_flow_features
from src.detection.scanning import detect_scanning
from src.detection.ddos import detect_ddos
from src.detection.beaconing import detect_beaconing
from src.ingest.pcap_reader import read_zeek_log


PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
ZEEK_SUFFIXES = {".log", ".tsv"}


def load_flow_features(input_path):
    suffix = input_path.suffix.lower()

    if suffix in PCAP_SUFFIXES:
        packets = rdpcap(str(input_path))
        print(f"Packets loaded: {len(packets)}")
        return extract_flow_features(packets)

    if suffix in ZEEK_SUFFIXES:
        zeek_flows = read_zeek_log(input_path)
        print(f"Zeek records loaded: {len(zeek_flows)}")
        return create_flow_features(zeek_flows)

    raise ValueError(
        "Unsupported input type. Supply a PCAP (.pcap/.pcapng/.cap) "
        "or Zeek connection log (.log/.tsv)."
    )


def main():
    print("=" * 50)
    print(" AI Unidirectional Threat Detection")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python src/main.py <pcap_file>")
        return 1

    pcap_file = Path(sys.argv[1])

    if not pcap_file.exists():
        print(f"PCAP file not found: {pcap_file}")
        return 1

    print(f"\nInput: {pcap_file}")

    try:
        flows = load_flow_features(pcap_file)
    except FileNotFoundError as exc:
        print(exc)
        return 1
    except ValueError as exc:
        print(exc)
        return 1

    print(f"Flows extracted: {len(flows)}")

    try:
        scanning_results = detect_scanning(flows)
        ddos_results = detect_ddos(flows)
        beaconing_results = detect_beaconing(flows)
    except ValueError as exc:
        print(f"Detection pipeline failed: {exc}")
        return 1

    print("\n========== DETECTION RESULTS ==========")

    if scanning_results:
        print("\n[!] SCANNING DETECTED")
        for result in scanning_results:
            print(result)
    else:
        print("\n[+] Scanning: No suspicious activity")

    if ddos_results:
        print("\n[!] POSSIBLE DDoS DETECTED")
        for result in ddos_results:
            print(result)
    else:
        print("\n[+] DDoS: No suspicious activity")

    if beaconing_results:
        print("\n[!] POSSIBLE BEACONING DETECTED")
        for result in beaconing_results:
            print(result)
    else:
        print("\n[+] Beaconing: No suspicious activity")

    print("\n========================================")
    print("Analysis complete")
    print("========================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
