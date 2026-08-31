import math
import re
from collections import Counter
from pathlib import Path

import pandas as pd


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def is_suspicious_domain(domain):
    if not isinstance(domain, str):
        return False

    domain = domain.lower().strip(".")

    # Ignore very short domains
    if len(domain) < 8:
        return False

    # Remove dots for character analysis
    name = domain.replace(".", "")

    score = 0

    # High character entropy
    if entropy(name) > 3.5:
        score += 1

    # Many digits
    digits = sum(c.isdigit() for c in name)
    if len(name) > 0 and digits / len(name) > 0.30:
        score += 1

    # Long random-looking label
    labels = domain.split(".")
    longest_label = max(labels, key=len)

    if len(longest_label) >= 20:
        score += 1

    # Excessive consonants
    letters = [c for c in longest_label if c.isalpha()]
    if len(letters) >= 10:
        vowels = sum(c in "aeiou" for c in letters)

        if vowels / len(letters) < 0.20:
            score += 1

    return score >= 2


def detect_dga(log_file):
    log_file = Path(log_file)

    if not log_file.exists():
        print(f"DNS log not found: {log_file}")
        return []

    # Zeek TSV files contain lines beginning with #
    rows = []

    with open(log_file, "r", errors="ignore") as f:
        fields = None

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

    if "query" not in df.columns:
        print("No DNS query field found.")
        return []

    alerts = []

    for _, row in df.iterrows():
        domain = row["query"]

        if is_suspicious_domain(domain):
            alerts.append({
                "type": "possible_dga",
                "domain": domain,
                "src_ip": row.get("id.orig_h", "unknown"),
                "dst_ip": row.get("id.resp_h", "unknown"),
                "severity": "medium"
            })

    return alerts


if __name__ == "__main__":

    log_file = "data/processed/zeek/live/dns.log"

    print("\n=== DGA / DNS Detection ===")

    alerts = detect_dga(log_file)

    print(f"DNS queries analyzed: {sum(1 for _ in open(log_file, errors='ignore') if not _.startswith('#')) if Path(log_file).exists() else 0}")

    if not alerts:
        print("No suspicious DGA-like domains detected.")
    else:
        print(f"Possible DGA activity: {len(alerts)}")

        for alert in alerts[:20]:
            print(alert)