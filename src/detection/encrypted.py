from pathlib import Path


def read_zeek_log(log_file):
    log_file = Path(log_file)

    if not log_file.exists():
        return [], []

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

    return fields or [], rows


def detect_encrypted_traffic(ssl_file, quic_file):

    ssl_fields, ssl_rows = read_zeek_log(ssl_file)
    quic_fields, quic_rows = read_zeek_log(quic_file)

    results = []

    # TLS connections
    for row in ssl_rows:
        results.append({
            "type": "TLS",
            "src_ip": row.get("id.orig_h", "unknown"),
            "dst_ip": row.get("id.resp_h", "unknown"),
            "version": row.get("version", "unknown"),
            "server_name": row.get("server_name", "unknown"),
        })

    # QUIC connections
    for row in quic_rows:
        results.append({
            "type": "QUIC",
            "src_ip": row.get("id.orig_h", "unknown"),
            "dst_ip": row.get("id.resp_h", "unknown"),
            "server_name": row.get("server_name", "unknown"),
        })

    return results


if __name__ == "__main__":

    ssl_file = "data/processed/zeek/live/ssl.log"
    quic_file = "data/processed/zeek/live/quic.log"

    print("\n=== TLS / QUIC Detection ===")

    results = detect_encrypted_traffic(ssl_file, quic_file)

    tls_count = sum(1 for x in results if x["type"] == "TLS")
    quic_count = sum(1 for x in results if x["type"] == "QUIC")

    print(f"TLS connections analyzed: {tls_count}")
    print(f"QUIC connections analyzed: {quic_count}")

    if results:
        print("\nEncrypted traffic observed:")

        for result in results[:20]:
            print(result)
    else:
        print("No TLS/QUIC traffic observed.")