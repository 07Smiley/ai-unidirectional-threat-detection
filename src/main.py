import sys

from scapy.all import rdpcap

from src.features.flow_features import extract_flow_features
from src.detection.scanning import detect_scanning
from src.detection.ddos import detect_ddos
from src.detection.beaconing import detect_c2


def main():
    print("=" * 50)
    print(" AI Unidirectional Threat Detection")
    print("=" * 50)

    # Check for PCAP argument
    if len(sys.argv) < 2:
        print("Usage: python src/main.py <pcap_file>")
        return

    pcap_file = sys.argv[1]

    print(f"\nPCAP: {pcap_file}")

    # Load packets from PCAP
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[ERROR] PCAP file not found: {pcap_file}")
        return
    except Exception as exc:
        print(f"[ERROR] Could not read PCAP: {exc}")
        return

    print(f"Packets loaded: {len(packets)}")

    if len(packets) == 0:
        print("[ERROR] PCAP contains no packets.")
        return

    # Convert packet sequence into flow features
    try:
        flows = extract_flow_features(packets)
    except Exception as exc:
        print(f"[ERROR] Feature extraction failed: {exc}")
        return

    print(f"Flows extracted: {len(flows)}")

    if len(flows) == 0:
        print("[INFO] No usable flows were extracted.")
        return

    # Run individual detectors
    try:
        scanning_results = detect_scanning(flows)
    except Exception as exc:
        print(f"[ERROR] Scanning detection failed: {exc}")
        scanning_results = []

    try:
        ddos_results = detect_ddos(flows)
    except Exception as exc:
        print(f"[ERROR] DDoS detection failed: {exc}")
        ddos_results = []

    try:
        beaconing_results = detect_c2(flows)
    except Exception as exc:
        print(f"[ERROR] C2 detection failed: {exc}")
        beaconing_results = []

    # Display results
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
        print("\n[!] POSSIBLE C2 / BEACONING DETECTED")
        for result in beaconing_results:
            print(result)
    else:
        print("\n[+] C2 / Beaconing: No suspicious activity")

    print("\n========================================")
    print("Analysis complete")
    print("========================================")


if __name__ == "__main__":
    main()