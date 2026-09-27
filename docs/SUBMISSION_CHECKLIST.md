# Submission & Live Demo Checklist

## Implemented

- Passive Zeek-based live monitoring.
- Unidirectional-aware flow extraction.
- Exact 15-feature forward-only ML contract.
- Seven deployed unidirectional Random Forest artifacts.
- Live ML predictions for the observed flow.
- Live rule detection for scanning, DDoS and beaconing.
- Zeek-log DGA and observed-direction exfiltration analysis.
- Threat score based on the strongest malicious model confidence.
- 92% response threshold.
- Explicit user confirmation before firewall blocking.
- Dashboard/WebSocket live status and alerts.
- Automated regression tests and GitHub Actions CI.

## Before the demo

1. Clone the repository.
2. Install Python dependencies.
3. Make sure Zeek and packet-capture permissions are available.
4. Copy `.env.example` to `.env` only if Gemini analysis is required.
5. Start with `python app.py`.
6. Open `http://127.0.0.1:9000`.
7. Select the actual capture interface and start live monitoring.
8. Generate only controlled traffic on a network you own or are authorized to test.
9. Confirm that live status reports Zeek and the unidirectional ML engine as ready.

## Demonstrate

### Normal traffic

- Show the selected interface and live sensor status.
- Show observed-direction flow information.
- Confirm that backward-direction ML features are not displayed or used.

### Detection

Use controlled test traffic or sample PCAPs for the supported detectors. Show the source IP, destination IP, protocol/port, observed packets/bytes, detector label, ML confidence where available, threat score, and responsible detector/model.

### Response policy

Only a threat score at or above 92% creates a response offer. Demonstrate that the dashboard asks for explicit confirmation, the backend validates the current source IP and score, and no automatic block occurs. Ignore is session-only.

## Capability boundaries

Do not claim these as fully live capabilities unless separately validated:

- Live DNS-stream DGA detection.
- Live TLS/QUIC anomaly detection.
- Cross-platform packet-capture validation that has not been physically tested.
- A calibrated ensemble probability.

The current threat score is the strongest malicious model confidence for the observed flow; it is not an ensemble probability.

## Final validation

GitHub Actions must be green on the final commit. A real deployment still requires a controlled real-NIC smoke test on the machine used for the demonstration. Repository tests cannot substitute for that physical test.

## Security

- Test only traffic you are authorized to monitor.
- Never commit `.env`, credentials, live logs, sensitive PCAPs or generated caches.
- Keep captured network metadata protected.
- Use the minimum privileges required for packet capture.
