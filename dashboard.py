from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# =============================================================================
# SAMPLE DATA — stands in for the real pipeline until Zeek + the ML model are
# wired up. Everything below the sample data is the part you replace:
#
#   get_groups()          -> pull distinct sources from Zeek conn logs + model
#                             verdicts, one row per source IP (+ host if known)
#   get_group_logs()       -> the individual flows Zeek logged for that source
#   get_group_analysis()   -> the model's structured verdict for that source
#   answer_group_chat()    -> a real model/LLM call, given ONLY that source's
#                             logs as context (never the whole dataset)
#
# The Flask routes at the bottom (api_groups, api_group_logs, etc.) are the
# stable contract the frontend already speaks — keep their response shapes
# and you can swap the implementations above freely.
# =============================================================================

SAMPLE_LOGS = [
    {
        "id": "fl_00931", "src_ip": "203.0.113.44", "host": "api.commerce.internal",
        "timestamp": "09:14:02", "dst_ip": "10.0.4.12", "dst_port": 80, "protocol": "TCP",
        "confidence": 0.99, "label": "DDoS", "packets_per_sec": 4820,
        "why": [
            "Forward packet size is abnormally uniform — near-identical payload length across the whole flow, unlike normal HTTP traffic",
            "Initial TCP window size sits far outside the range seen from real clients",
            "Backward inter-arrival time has almost no variance — packets arrive on a fixed mechanical cadence",
        ],
        "features": [
            {"name": "Fwd Packet Length Max", "value": "1460 B", "weight": 0.92},
            {"name": "Total Fwd Bytes", "value": "1.8M", "weight": 0.87},
            {"name": "Init Win Bytes Fwd", "value": "29200", "weight": 0.81},
            {"name": "Bwd IAT Std", "value": "0.4 ms", "weight": 0.74},
        ],
    },
    {
        "id": "fl_00887", "src_ip": "203.0.113.44", "host": "api.commerce.internal",
        "timestamp": "08:51:03", "dst_ip": "10.0.4.12", "dst_port": 80, "protocol": "TCP",
        "confidence": 0.98, "label": "DDoS", "packets_per_sec": 4695,
        "why": [
            "Forward packet size abnormally uniform across the flow",
            "Initial TCP window size outside normal client range",
        ],
        "features": [
            {"name": "Fwd Packet Length Max", "value": "1460 B", "weight": 0.91},
            {"name": "Init Win Bytes Fwd", "value": "29200", "weight": 0.78},
        ],
    },
    {
        "id": "fl_00928", "src_ip": "198.51.100.9", "host": None,
        "timestamp": "09:12:41", "dst_ip": "10.0.4.12", "dst_port": 80, "protocol": "TCP",
        "confidence": 0.97, "label": "DDoS", "packets_per_sec": 5110,
        "why": [
            "Forward byte volume is over 40x the flow's median legitimate session",
            "SYN flag ratio is unusually high relative to completed handshakes",
        ],
        "features": [
            {"name": "Total Fwd Bytes", "value": "2.1M", "weight": 0.90},
            {"name": "SYN Flag Count", "value": "312", "weight": 0.83},
            {"name": "Fwd Packet Length Max", "value": "1460 B", "weight": 0.79},
        ],
    },
    {
        "id": "fl_00919", "src_ip": "203.0.113.51", "host": None,
        "timestamp": "09:08:15", "dst_ip": "10.0.4.12", "dst_port": 80, "protocol": "TCP",
        "confidence": 0.95, "label": "DDoS", "packets_per_sec": 3980,
        "why": [
            "Forward packet size uniformity matches the flood-tool signature seen across this batch",
            "Backward IAT std deviation is near zero",
        ],
        "features": [
            {"name": "Bwd IAT Std", "value": "0.6 ms", "weight": 0.85},
            {"name": "Fwd Packet Length Max", "value": "1460 B", "weight": 0.80},
        ],
    },
    {
        "id": "fl_00902", "src_ip": "192.0.2.77", "host": "checkout.storefront.io",
        "timestamp": "08:59:30", "dst_ip": "10.0.4.12", "dst_port": 443, "protocol": "TCP",
        "confidence": 0.42, "label": "BENIGN", "packets_per_sec": 210,
        "why": [
            "Packet timing and size variance both fall within the normal client range",
            "SYN flag ratio is consistent with a completed handshake",
        ],
        "features": [
            {"name": "Fwd Packet Length Max", "value": "512 B", "weight": 0.31},
            {"name": "Bwd IAT Std", "value": "48 ms", "weight": 0.22},
        ],
    },
    {
        "id": "fl_00860", "src_ip": "198.51.100.14", "host": None,
        "timestamp": "08:40:52", "dst_ip": "10.0.4.12", "dst_port": 80, "protocol": "TCP",
        "confidence": 0.96, "label": "DDoS", "packets_per_sec": 4310,
        "why": [
            "Forward byte volume far exceeds the median legitimate session",
            "Backward inter-arrival time has near-zero variance",
        ],
        "features": [
            {"name": "Total Fwd Bytes", "value": "1.6M", "weight": 0.86},
            {"name": "Bwd IAT Std", "value": "0.5 ms", "weight": 0.75},
        ],
    },
]

MODEL_NAME = "XGBoost"
FLOWS_ANALYZED = 223082
FLOWS_ANALYZED_WINDOW = "Fri Jul 7 capture window"


def get_groups():
    """One row per source (src_ip [+ host]), aggregated from the raw flow logs.

    Replace this with a query against Zeek's conn.log (or whatever emits
    per-flow records) joined with the model's verdict per flow.
    """
    groups = {}
    for log in SAMPLE_LOGS:
        key = log["src_ip"]
        g = groups.setdefault(key, {
            "group_id": key,
            "src_ip": log["src_ip"],
            "host": log.get("host"),
            "request_count": 0,
            "label": "BENIGN",
            "confidence": 0.0,
            "last_seen": log["timestamp"],
        })
        g["request_count"] += 1
        g["confidence"] = max(g["confidence"], log["confidence"])
        if log["label"] == "DDoS":
            g["label"] = "DDoS"
        if log["timestamp"] > g["last_seen"]:
            g["last_seen"] = log["timestamp"]
    return sorted(groups.values(), key=lambda g: g["confidence"], reverse=True)


def get_group_logs(group_id):
    """All raw flows Zeek logged for this one source, newest first."""
    return sorted(
        [l for l in SAMPLE_LOGS if l["src_ip"] == group_id],
        key=lambda l: l["timestamp"],
        reverse=True,
    )


def get_group_analysis(group_id):
    """The model's structured verdict for this source — shown as the first
    message in that source's Analysis chat.
    """
    logs = get_group_logs(group_id)
    if not logs:
        return None
    worst = max(logs, key=lambda l: l["confidence"])
    ddos_count = sum(1 for l in logs if l["label"] == "DDoS")
    if worst["label"] == "DDoS":
        lead = (
            f"{ddos_count} of {len(logs)} logged flow(s) from this source were classified DDoS, "
            f"peaking at {worst['confidence']*100:.1f}% confidence."
        )
    else:
        lead = f"All {len(logs)} logged flow(s) from this source look benign — highest confidence seen was {worst['confidence']*100:.1f}%."
    return {
        "lead": lead,
        "bullets": worst["why"],
        "label": worst["label"],
        "confidence": worst["confidence"],
    }


def answer_group_chat(group_id, message):
    """Answer a follow-up question using ONLY this source's own logs.

    Replace this with a real model/LLM call — pass it get_group_logs(group_id)
    as its entire context so it structurally cannot answer from any other
    source's traffic.
    """
    logs = get_group_logs(group_id)
    q = (message or "").lower()

    id_match = next((l for l in logs if l["id"].lower() in q), None)
    if id_match:
        return {
            "lead": f"{id_match['id']}: {id_match['src_ip']} → {id_match['dst_ip']}:{id_match['dst_port']}, "
                    f"classified {id_match['label']} at {id_match['confidence']*100:.1f}% confidence.",
            "bullets": id_match["why"],
        }

    if any(w in q for w in ["how many", "count"]):
        n = sum(1 for l in logs if l["label"] == "DDoS")
        return {"lead": f"{n} of {len(logs)} flows from this source are flagged DDoS."}

    if any(w in q for w in ["highest", "worst", "most confident", "top"]):
        top = max(logs, key=lambda l: l["confidence"])
        return {
            "lead": f"Highest-confidence flow is {top['id']} at {top['confidence']*100:.1f}% ({top['label']}).",
            "bullets": top["why"],
        }

    if any(w in q for w in ["port", "target"]):
        ports = sorted({l["dst_port"] for l in logs})
        return {
            "lead": f"This source targeted port(s): {', '.join(str(p) for p in ports)}.",
            "bullets": ["Port is metadata only — it was never fed to the model as a feature."],
        }

    if any(w in q for w in ["why", "reason", "evidence"]):
        top = max(logs, key=lambda l: l["confidence"])
        return {"lead": f"Strongest evidence, from {top['id']}:", "bullets": top["why"]}

    return {
        "lead": "I can only answer from this source's own logs — try asking about a specific flow id, "
                "counts, confidence, ports, or why it was flagged."
    }


# =============================================================================
# ROUTES
# =============================================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    flagged = [l for l in SAMPLE_LOGS if l["label"] == "DDoS"]
    avg_conf = (sum(l["confidence"] for l in flagged) / len(flagged)) if flagged else 0.0
    return jsonify({
        "flows_analyzed": FLOWS_ANALYZED,
        "flows_analyzed_window": FLOWS_ANALYZED_WINDOW,
        "flagged": len(flagged),
        "flagged_sources": len({g["group_id"] for g in get_groups() if g["label"] == "DDoS"}),
        "avg_confidence": round(avg_conf, 4),
        "model": MODEL_NAME,
    })


@app.route("/api/groups")
def api_groups():
    """One row per source. GET /api/groups"""
    return jsonify(get_groups())


@app.route("/api/groups/<group_id>/logs")
def api_group_logs(group_id):
    """Every raw flow for one source. GET /api/groups/<src_ip>/logs"""
    logs = get_group_logs(group_id)
    if not logs:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(logs)


@app.route("/api/groups/<group_id>/analysis")
def api_group_analysis(group_id):
    """The model's structured verdict for one source. GET /api/groups/<src_ip>/analysis"""
    analysis = get_group_analysis(group_id)
    if analysis is None:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(analysis)


@app.route("/api/groups/<group_id>/chat", methods=["POST"])
def api_group_chat(group_id):
    """Ask a follow-up question scoped to one source only.

    POST /api/groups/<src_ip>/chat   body: { "message": "<user text>" }
    response: { "lead": "<one-line answer>", "bullets": ["...", ...] }  // bullets optional
    """
    if not get_group_logs(group_id):
        return jsonify({"error": "unknown group"}), 404
    body = request.get_json(silent=True) or {}
    return jsonify(answer_group_chat(group_id, body.get("message", "")))


if __name__ == "__main__":
    app.run(debug=True, port=9000)