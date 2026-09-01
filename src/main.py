import sys
from scapy.all import rdpcap

from src.features.flow_features import create_flow_features
from src.detection.scanning import detect_scanning
from src.detection.ddos import detect_ddos
from src.detection.beaconing import detect_c2


def main():
    print("=" * 50)
    print(" AI Unidirectional Threat Detection")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python src/main.py <pcap_file>")
        return

    pcap_file = sys.argv[1]

    print(f"\nPCAP: {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"Packets loaded: {len(packets)}")

    flows = create_flow_features(packets)

    print(f"Flows extracted: {len(flows)}")

    scanning_results = detect_scanning(flows)
    ddos_results = detect_ddos(flows)
    beaconing_results = detect_c2(flows)

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


if __name__ == "__main__":
    main()