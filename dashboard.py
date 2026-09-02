import json
import os
import sqlite3
import time
import hashlib
import traceback
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request
from google import genai
from google.genai import types
from google.genai.errors import ServerError

# Load variables from a .env file in the current working directory (if
# present) into os.environ. This MUST happen before get_gemini_client()
# reads GEMINI_API_KEY, or the key will never be picked up even if it's
# sitting right there in .env.
load_dotenv()

app = Flask(__name__)

# =============================================================================
# GEMINI CLIENT
#
# Reads the API key from the GEMINI_API_KEY environment variable — put that
# in your .env (loaded above via python-dotenv) or export it before running.
# The client is created once at import time; every chat request reuses it.
#
# Kept on gemini-3.5-flash rather than a lighter/faster tier on purpose —
# this bot is judging DDoS vs benign from log evidence, and flash-lite
# trades reasoning quality for speed in a way that isn't worth it here.
# =============================================================================

GEMINI_MODEL = "gemini-3.5-flash"
_gemini_client = None


def get_gemini_client():
    global _gemini_client
    if _gemini_client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set — add it to your .env or environment."
            )
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


# =============================================================================
# CHAT PERSISTENCE (SQLite) — two tables, two different jobs
#
#   chat_history  -> the raw Gemini Content history for a source, in the
#                     exact shape the SDK needs to resume a chat session
#                     (client.chats.create(..., history=...)). This is what
#                     gives the MODEL memory across restarts.
#
#   chat_display  -> a simple ordered list of {sender, lead, bullets} turns
#                     for a source, in the exact shape the frontend renders
#                     as chat bubbles. This is what gives the UI something
#                     to replay after a page refresh — chat_history alone
#                     isn't enough for that, because its first turn has the
#                     raw log-dump/system-prompt text baked in rather than
#                     the clean question the user actually typed, and its
#                     model turns are JSON strings rather to be re-parsed
#                     on every render.
#
# No setup needed: sqlite3 is in the Python standard library, and the .db
# file plus both tables are created automatically on first run at
# CHAT_DB_PATH (defaults to chat_history.db next to this file).
# =============================================================================

CHAT_DB_PATH = os.environ.get("CHAT_DB_PATH", "chat_history.db")


def _db():
    conn = sqlite3.connect(CHAT_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_history (
            group_id TEXT PRIMARY KEY,
            history TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_display (
            group_id TEXT PRIMARY KEY,
            entries TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    return conn


def load_history(group_id):
    """Return this source's saved conversation as a list of Content objects
    ready to hand back to the SDK, or None if nothing's been saved yet.
    """
    conn = _db()
    try:
        row = conn.execute(
            "SELECT history FROM chat_history WHERE group_id = ?", (group_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    raw_turns = json.loads(row[0])
    return [types.Content.model_validate(turn) for turn in raw_turns]


def save_history(group_id, chat):
    """Persist the chat session's current full history to disk."""
    turns = [c.model_dump(exclude_none=True, mode="json") for c in chat.get_history()]
    conn = _db()
    try:
        conn.execute(
            """
            INSERT INTO chat_history (group_id, history, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(group_id) DO UPDATE SET
                history = excluded.history,
                updated_at = excluded.updated_at
            """,
            (group_id, json.dumps(turns), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def load_display_history(group_id):
    """Return this source's chat bubbles, oldest first, as a plain list of
    {"sender": "user"|"bot", "lead": str, "bullets": [str, ...]?} — exactly
    what the frontend needs to replay the conversation after a refresh.
    """
    conn = _db()
    try:
        row = conn.execute(
            "SELECT entries FROM chat_display WHERE group_id = ?", (group_id,)
        ).fetchone()
    finally:
        conn.close()
    return json.loads(row[0]) if row else []


def append_display_turns(group_id, user_message, bot_payload):
    """Append one user turn and one bot turn to this source's display
    history. Called once per chat request, regardless of whether the bot's
    reply was a real answer or an error message — either way it's what the
    user actually saw, so a refresh should show the same thing.
    """
    entries = load_display_history(group_id)
    entries.append({"sender": "user", "lead": user_message})
    bot_entry = {"sender": "bot", "lead": bot_payload.get("lead", "")}
    if bot_payload.get("bullets"):
        bot_entry["bullets"] = bot_payload["bullets"]
    entries.append(bot_entry)

    conn = _db()
    try:
        conn.execute(
            """
            INSERT INTO chat_display (group_id, entries, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(group_id) DO UPDATE SET
                entries = excluded.entries,
                updated_at = excluded.updated_at
            """,
            (group_id, json.dumps(entries), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


# =============================================================================
# PER-SOURCE CHAT MEMORY
#
# One Gemini `chat` session per group_id, kept in _gemini_chats for the life
# of the process (fast path — no disk I/O for turns already loaded this
# run), and mirrored to SQLite after every turn so it survives restarts.
#
# A source's first-ever question folds the log context + system prompt into
# that same message rather than sending it as a separate priming round-trip
# first — one model call instead of two, same context, same accuracy.
# =============================================================================

_gemini_chats = {}  # group_id -> chat session (in-process cache)


def _send_with_retry(chat, message, max_attempts=3):
    """Send a message on an existing chat session, retrying transient
    Gemini server errors with backoff. Returns (raw_text, error).
    Exactly one of the two is None.
    """
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = chat.send_message(message)
            return (response.text or "").strip(), None
        except ServerError as e:
            last_error = e
            print(f"[Gemini server error, attempt {attempt}/{max_attempts}] {e}")
            if attempt < max_attempts:
                time.sleep(1.0 * attempt)  # 1s, then 2s
        except Exception as e:
            last_error = e
            print(f"[Gemini call failed] {type(e).__name__}: {e}")
            break
    return None, last_error


def get_or_create_group_chat(group_id, client):
    """Return (chat, is_new). is_new is True only for a source that has
    never been talked to before (no in-process session, nothing on disk) —
    the caller uses that to decide whether this message needs the log
    context folded in. No network call happens here; opening/resuming a
    chat session is local, so this never adds latency on its own.
    """
    chat = _gemini_chats.get(group_id)
    if chat is not None:
        return chat, False

    saved_history = load_history(group_id)
    if saved_history:
        chat = client.chats.create(model=GEMINI_MODEL, history=saved_history)
        _gemini_chats[group_id] = chat
        return chat, False

    chat = client.chats.create(model=GEMINI_MODEL)
    _gemini_chats[group_id] = chat
    return chat, True


# =============================================================================
# REAL DATA PROVIDER — replaces the hardcoded SAMPLE_LOGS with live Zeek
# log ingestion, feature extraction, and rule-based detection results.
#
# Architecture:
#   Zeek logs (conn.log, dns.log, ssl.log)
#       ↓
#   read_zeek_log()          — parse TSV to DataFrame
#       ↓
#   create_flow_features()   — derive flow-level features
#       ↓
#   detect_scanning / detect_ddos / detect_beaconing  — rule-based detectors
#       ↓
#   RealDataProvider         — caches results, maps to dashboard format
#       ↓
#   Flask API routes         — serve to existing frontend
#
# The provider re-reads Zeek logs when the file modification time changes
# or the cache TTL (default 5s) expires, ensuring newly appended data is
# picked up without manual restarts. Detection logic stays in src/detection
# and is NOT duplicated here.
# =============================================================================

import pandas as pd

# These imports bring in the existing Phase 1 pipeline — the dashboard
# consumes their output, never duplicates their logic.
from src.ingest.pcap_reader import read_zeek_log
from src.features.flow_features import create_flow_features
from src.detection.scanning import detect_scanning
from src.detection.ddos import detect_ddos
from src.detection.beaconing import detect_beaconing

# Optional detectors — may not be importable if dependencies are missing,
# so we guard them with try/except and disable gracefully.
try:
    from src.detection.exfiltration import detect_exfiltration
    _HAS_EXFILTRATION = True
except ImportError:
    _HAS_EXFILTRATION = False

try:
    from src.detection.dga import detect_dga
    _HAS_DGA = True
except ImportError:
    _HAS_DGA = False


# Resolve the project root relative to this file
_REPO_ROOT = Path(__file__).resolve().parent

# Zeek log directory — configurable via ZEEK_LOG_DIR env var, with
# sensible fallbacks to the known project locations.
_ZEEK_LOG_DIR_CANDIDATES = [
    os.environ.get("ZEEK_LOG_DIR", ""),
    str(_REPO_ROOT / "data" / "processed" / "zeek" / "live"),
    str(_REPO_ROOT / "data" / "processed" / "zeek"),
    str(_REPO_ROOT),
]

# Cache TTL in seconds — how often to re-check Zeek logs for new data.
_CACHE_TTL = float(os.environ.get("DASHBOARD_CACHE_TTL", "5"))


def _find_zeek_log_dir():
    """Return the first candidate directory that contains a conn.log file."""
    for candidate in _ZEEK_LOG_DIR_CANDIDATES:
        if not candidate:
            continue
        p = Path(candidate)
        if p.is_dir() and (p / "conn.log").exists():
            return p
    return None


def _safe_float(val, default=0.0):
    """Convert a value to float, returning default on failure."""
    try:
        f = float(val)
        if pd.isna(f):
            return default
        return f
    except (ValueError, TypeError):
        return default


def _format_timestamp(ts_epoch):
    """Convert a Unix epoch timestamp to a human-readable HH:MM:SS string."""
    try:
        ts = float(ts_epoch)
        if pd.isna(ts):
            return "—"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
    except (ValueError, TypeError, OSError):
        return "—"


def _format_iso_timestamp(ts_epoch):
    """Convert a Unix epoch timestamp to ISO 8601 for sorting."""
    try:
        ts = float(ts_epoch)
        if pd.isna(ts):
            return ""
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return ""


class RealDataProvider:
    """Reads Zeek logs, runs the Phase 1 detection pipeline, and caches
    the results. The cache is invalidated when the conn.log file's mtime
    changes or the TTL expires.
    """

    def __init__(self):
        self._flows = []          # list of dashboard-format flow dicts
        self._threats = []        # list of raw detector result dicts
        self._flow_df = None      # the raw feature DataFrame
        self._conn_log_path = None
        self._last_mtime = 0
        self._last_refresh = 0
        self._last_error = None   # string describing last load error, or None
        self._hostname_map = {}   # dst_ip -> hostname from DNS/SSL logs
        self._zeek_dir = None

    def _should_refresh(self):
        """Return True if the cached data is stale."""
        now = time.time()
        if now - self._last_refresh < _CACHE_TTL:
            return False

        zeek_dir = _find_zeek_log_dir()
        if zeek_dir is None:
            # No Zeek logs found — if we had data before, keep it;
            # if not, report the error on next access.
            if not self._flows:
                self._last_error = "No Zeek conn.log found in any search path."
            return False

        conn_log = zeek_dir / "conn.log"
        try:
            current_mtime = conn_log.stat().st_mtime
        except OSError:
            return False

        if current_mtime != self._last_mtime or self._zeek_dir != zeek_dir:
            return True

        # TTL passed but file hasn't changed — update timestamp, skip reload
        self._last_refresh = now
        return False

    def _load_hostname_map(self, zeek_dir):
        """Build a mapping from destination IP → hostname using DNS and
        SSL log files, if available. Does NOT fabricate hostnames.
        """
        hostname_map = {}

        # Try DNS log first (query → answers contain IPs)
        dns_log = zeek_dir / "dns.log"
        if dns_log.exists():
            try:
                dns_df = read_zeek_log(dns_log)
                if not dns_df.empty and "query" in dns_df.columns and "answers" in dns_df.columns:
                    for _, row in dns_df.iterrows():
                        query = row.get("query", "")
                        answers = str(row.get("answers", ""))
                        if query and answers and answers != "-":
                            # answers is comma-separated; map each IP → query domain
                            for answer in answers.split(","):
                                answer = answer.strip()
                                # Only map if it looks like an IP address
                                if answer and answer[0].isdigit():
                                    hostname_map[answer] = query
            except Exception as e:
                print(f"[Dashboard] Warning: Could not parse DNS log: {e}")

        # Also try SSL log (server_name field maps to dst IP)
        ssl_log = zeek_dir / "ssl.log"
        if ssl_log.exists():
            try:
                ssl_df = read_zeek_log(ssl_log)
                if not ssl_df.empty and "server_name" in ssl_df.columns and "id.resp_h" in ssl_df.columns:
                    for _, row in ssl_df.iterrows():
                        server_name = row.get("server_name", "")
                        dst_ip = row.get("id.resp_h", "")
                        if server_name and server_name != "-" and dst_ip and dst_ip != "-":
                            hostname_map[dst_ip] = server_name
            except Exception as e:
                print(f"[Dashboard] Warning: Could not parse SSL log: {e}")

        return hostname_map

    def refresh(self):
        """Reload Zeek logs and re-run the detection pipeline."""
        zeek_dir = _find_zeek_log_dir()
        if zeek_dir is None:
            self._last_error = "No Zeek conn.log found in any search path."
            self._last_refresh = time.time()
            return

        conn_log = zeek_dir / "conn.log"
        try:
            self._conn_log_path = conn_log
            self._zeek_dir = zeek_dir

            # 1) Read connection log and extract flow features
            zeek_df = read_zeek_log(conn_log)
            flow_df = create_flow_features(zeek_df)
            self._flow_df = flow_df

            # 2) Load hostname mapping from DNS/SSL logs
            self._hostname_map = self._load_hostname_map(zeek_dir)

            # 3) Run rule-based detectors on the flow features
            threats = []
            try:
                threats += detect_scanning(flow_df)
            except Exception as e:
                print(f"[Dashboard] Scanning detector error: {e}")
            try:
                threats += detect_ddos(flow_df)
            except Exception as e:
                print(f"[Dashboard] DDoS detector error: {e}")
            try:
                threats += detect_beaconing(flow_df)
            except Exception as e:
                print(f"[Dashboard] Beaconing detector error: {e}")

            # Optional detectors that need separate log files
            if _HAS_EXFILTRATION:
                try:
                    threats += detect_exfiltration(conn_log)
                except Exception as e:
                    print(f"[Dashboard] Exfiltration detector error: {e}")

            if _HAS_DGA:
                dns_log = zeek_dir / "dns.log"
                if dns_log.exists():
                    try:
                        threats += detect_dga(dns_log)
                    except Exception as e:
                        print(f"[Dashboard] DGA detector error: {e}")

            self._threats = threats

            # 4) Build a set of "involved" source IPs from threat results
            threat_src_ips = set()
            threat_dst_ips = set()
            for t in threats:
                if t.get("src_ip"):
                    threat_src_ips.add(t["src_ip"])
                if t.get("dst_ip"):
                    threat_dst_ips.add(t["dst_ip"])

            # 5) Convert each flow row to the dashboard format
            flows = []
            for idx, row in flow_df.iterrows():
                src_ip = str(row.get("id.orig_h", ""))
                dst_ip = str(row.get("id.resp_h", ""))
                dst_port = row.get("id.resp_p")
                proto = str(row.get("proto", "")).upper()
                ts = row.get("ts")
                duration = _safe_float(row.get("duration"), 0.0)
                orig_pkts = _safe_float(row.get("orig_pkts"), 0)
                resp_pkts = _safe_float(row.get("resp_pkts"), 0)
                total_pkts = _safe_float(row.get("total_packets"), 0)
                packet_rate = _safe_float(row.get("packet_rate"), 0)
                orig_bytes = _safe_float(row.get("orig_bytes"), 0)
                resp_bytes = _safe_float(row.get("resp_bytes"), 0)

                # Determine label from threat results involving this flow
                label = "BENIGN"
                why = []
                threat_type = None
                severity = None

                for t in threats:
                    t_src = t.get("src_ip", "")
                    t_dst = t.get("dst_ip", "")
                    ttype = t.get("type", "")

                    matched = False
                    if ttype == "possible_port_scan" and t_src == src_ip and t_dst == dst_ip:
                        matched = True
                    elif ttype == "possible_ddos" and t_dst == dst_ip:
                        matched = True
                    elif ttype == "possible_beaconing" and t_src == src_ip and t_dst == dst_ip:
                        matched = True
                    elif ttype == "possible_exfiltration" and t_src == src_ip and t_dst == dst_ip:
                        matched = True
                    elif ttype == "possible_dga" and t_src == src_ip:
                        matched = True

                    if matched:
                        label = ttype.replace("possible_", "").upper()
                        threat_type = ttype
                        severity = t.get("severity", "medium")
                        # Build "why" reasons from the threat details
                        if ttype == "possible_port_scan":
                            why.append(f"Source contacted {t.get('unique_destination_ports', '?')} unique ports on {t_dst}")
                            why.append(f"{t.get('connection_count', '?')} connections in this src→dst pair")
                        elif ttype == "possible_ddos":
                            why.append(f"Destination received {t.get('connection_count', '?')} connections from {t.get('unique_sources', '?')} unique sources")
                        elif ttype == "possible_beaconing":
                            avg_interval = t.get("average_interval")
                            why.append(f"{t.get('connection_count', '?')} repeated connections from this source to {t_dst}")
                            if avg_interval is not None:
                                why.append(f"Average interval between connections: {avg_interval:.2f}s")
                        elif ttype == "possible_exfiltration":
                            why.append(f"Large outbound transfer: {t.get('outbound_bytes', '?')} bytes sent")
                            why.append(f"Outbound ratio: {t.get('outbound_ratio', '?')}")
                        elif ttype == "possible_dga":
                            why.append(f"Suspicious domain queried: {t.get('domain', '?')}")
                        break  # Use first matching threat

                # Look up hostname from DNS/SSL mapping
                host = self._hostname_map.get(dst_ip)

                # Build flow ID from Zeek UID if available, else hash
                uid = row.get("uid", "")
                if uid and str(uid) != "-" and not pd.isna(uid) if isinstance(uid, float) else uid:
                    flow_id = str(uid)
                else:
                    raw_id = f"{src_ip}:{dst_ip}:{dst_port}:{ts}"
                    flow_id = "fl_" + hashlib.md5(raw_id.encode()).hexdigest()[:8]

                # Compute a severity-derived confidence for flagged flows.
                # Rule-based detectors don't produce a probability, so we
                # derive a rough indicator from severity level.
                # BENIGN flows get confidence = None (honestly absent).
                if label != "BENIGN":
                    if severity == "high":
                        confidence = 0.85
                    elif severity == "medium":
                        confidence = 0.65
                    else:
                        confidence = 0.50
                else:
                    confidence = None

                try:
                    dst_port_int = int(float(dst_port)) if dst_port and str(dst_port) != "-" and not (isinstance(dst_port, float) and pd.isna(dst_port)) else None
                except (ValueError, TypeError):
                    dst_port_int = None

                flows.append({
                    "id": flow_id,
                    "src_ip": src_ip,
                    "host": host,
                    "timestamp": _format_timestamp(ts),
                    "timestamp_epoch": _safe_float(ts, 0),
                    "dst_ip": dst_ip,
                    "dst_port": dst_port_int,
                    "protocol": proto if proto and proto != "-" else None,
                    "confidence": confidence,
                    "label": label,
                    "packets_per_sec": round(packet_rate, 1),
                    "why": why,
                    "features": [
                        {"name": "Duration", "value": f"{duration:.3f}s"},
                        {"name": "Orig Bytes", "value": f"{int(orig_bytes)}"},
                        {"name": "Resp Bytes", "value": f"{int(resp_bytes)}"},
                        {"name": "Total Packets", "value": f"{int(total_pkts)}"},
                        {"name": "Packet Rate", "value": f"{packet_rate:.1f} pkt/s"},
                    ],
                })

            self._flows = flows
            self._last_mtime = conn_log.stat().st_mtime
            self._last_refresh = time.time()
            self._last_error = None

            print(f"[Dashboard] Loaded {len(flow_df)} flows from {conn_log}, "
                  f"{len(threats)} threat events detected, "
                  f"{len([f for f in flows if f['label'] != 'BENIGN'])} flagged flows")

        except Exception as e:
            self._last_error = f"Detection pipeline error: {type(e).__name__}: {e}"
            self._last_refresh = time.time()
            print(f"[Dashboard] {self._last_error}")
            traceback.print_exc()

    def _ensure_fresh(self):
        """Refresh if the data is stale."""
        if self._should_refresh() or not self._flows:
            self.refresh()

    def get_flows(self):
        """Return all dashboard-format flow dicts, refreshing if needed."""
        self._ensure_fresh()
        return self._flows

    def get_threats(self):
        """Return raw detector results."""
        self._ensure_fresh()
        return self._threats

    def get_error(self):
        """Return the last error string, or None if everything is OK."""
        self._ensure_fresh()
        return self._last_error

    def get_conn_log_path(self):
        """Return the path to the active conn.log, or None."""
        self._ensure_fresh()
        return self._conn_log_path

    def get_zeek_dir(self):
        """Return the active Zeek log directory, or None."""
        self._ensure_fresh()
        return self._zeek_dir


# Global singleton — created once, shared by all routes.
_data_provider = RealDataProvider()


# =============================================================================
# DATA FUNCTIONS — same signatures as before, now backed by real data.
# =============================================================================

def get_groups():
    """One row per source (src_ip [+ host]), aggregated from the real flow logs.
    Replaces the old SAMPLE_LOGS-based implementation.
    """
    flows = _data_provider.get_flows()
    groups = {}
    for flow in flows:
        key = flow["src_ip"]
        g = groups.setdefault(key, {
            "group_id": key,
            "src_ip": flow["src_ip"],
            "host": flow.get("host"),
            "request_count": 0,
            "label": "BENIGN",
            "confidence": None,
            "last_seen": flow["timestamp"],
            "_last_epoch": flow.get("timestamp_epoch", 0),
        })
        g["request_count"] += 1
        # Promote to the worst threat label seen
        if flow["label"] != "BENIGN":
            g["label"] = flow["label"]
        # Track highest confidence (only for flagged flows)
        if flow["confidence"] is not None:
            if g["confidence"] is None or flow["confidence"] > g["confidence"]:
                g["confidence"] = flow["confidence"]
        # Track the latest timestamp
        flow_epoch = flow.get("timestamp_epoch", 0)
        if flow_epoch > g["_last_epoch"]:
            g["last_seen"] = flow["timestamp"]
            g["_last_epoch"] = flow_epoch
        # Inherit hostname if we don't have one yet
        if g["host"] is None and flow.get("host"):
            g["host"] = flow["host"]

    # Clean up internal fields and sort — flagged sources first, then by count
    result = []
    for g in groups.values():
        del g["_last_epoch"]
        result.append(g)

    return sorted(result, key=lambda g: (
        0 if g["label"] != "BENIGN" else 1,
        -(g["confidence"] or 0),
        -g["request_count"],
    ))


def get_group_logs(group_id):
    """All raw flows for this one source, newest first."""
    flows = _data_provider.get_flows()
    source_flows = [f for f in flows if f["src_ip"] == group_id]
    return sorted(
        source_flows,
        key=lambda f: f.get("timestamp_epoch", 0),
        reverse=True,
    )


def get_group_analysis(group_id):
    """The rule-based detection verdict for this source — shown as the first
    message in that source's Analysis chat.
    """
    logs = get_group_logs(group_id)
    if not logs:
        return None

    flagged = [l for l in logs if l["label"] != "BENIGN"]
    total = len(logs)

    if flagged:
        worst = max(flagged, key=lambda l: l.get("confidence") or 0)
        # Collect all unique threat types and reasons
        all_types = set(l["label"] for l in flagged)
        all_why = []
        seen_why = set()
        for l in flagged:
            for reason in l.get("why", []):
                if reason not in seen_why:
                    all_why.append(reason)
                    seen_why.add(reason)

        type_str = ", ".join(sorted(all_types))
        conf_str = f" (severity-derived confidence: {worst['confidence']*100:.0f}%)" if worst.get("confidence") else ""
        lead = (
            f"{len(flagged)} of {total} flow(s) from this source were flagged as "
            f"{type_str}{conf_str}."
        )
        return {
            "lead": lead,
            "bullets": all_why if all_why else ["Flagged by rule-based detection engine."],
            "label": worst["label"],
            "confidence": worst.get("confidence"),
        }
    else:
        lead = f"All {total} flow(s) from this source look benign — no rule-based detections triggered."
        return {
            "lead": lead,
            "bullets": [],
            "label": "BENIGN",
            "confidence": None,
        }


CHAT_SYSTEM_PROMPT = """You are Sentry's per-source flow analyst. You are given ONLY the raw \
logged flows for a single traffic source (never any other source's data) as JSON, plus a \
question from a security analyst. Answer using only what's in the provided flows — never \
invent flow ids, ports, or numbers that aren't present in the data. Remember earlier turns in \
this conversation and use them for context on follow-up questions (e.g. "the one you just \
mentioned", "that flow", "what about the other one").

Respond with ONLY a JSON object, no markdown fences, no commentary outside the JSON, in \
exactly this shape:
{"lead": "<one or two sentence answer>", "bullets": ["<optional supporting point>", ...]}

"bullets" is optional — omit it (or use an empty list) when the answer doesn't need supporting \
points. Keep "lead" concise and specific to the question asked. Every reply must follow that \
exact JSON shape."""


def answer_group_chat(group_id, message):
    """Answer a follow-up question using ONLY this source's own logs, with
    memory of earlier turns — resumed from SQLite if the server restarted
    since the last question about this source.

    For a source's first-ever question, the log context and system prompt
    are folded into this same call rather than sent as a separate priming
    round-trip first — one model call instead of two, no context lost.
    """
    logs = get_group_logs(group_id)
    if not logs:
        return {"lead": "No logged flows for this source."}

    try:
        client = get_gemini_client()
    except RuntimeError as e:
        # GEMINI_API_KEY missing — surfaced directly so it's obvious in the UI.
        print(f"[Gemini config error] {e}")
        return {"lead": str(e)}

    try:
        chat, is_new = get_or_create_group_chat(group_id, client)
    except Exception as e:
        print(f"[Gemini session open failed] {type(e).__name__}: {e}")
        return {"lead": "Couldn't reach Gemini right now — try again in a moment."}

    if is_new:
        outgoing = (
            f"{CHAT_SYSTEM_PROMPT}\n\n"
            f"Flows for source {group_id}:\n{json.dumps(logs, indent=2)}\n\n"
            f"Question: {message}\n\n"
            f"(Respond with ONLY the JSON object as instructed.)"
        )
    else:
        outgoing = f"{message}\n\n(Respond with ONLY the JSON object as instructed.)"

    raw, err = _send_with_retry(chat, outgoing)
    if raw is None:
        # Drop the broken in-process session so the next question resumes
        # from the last good state saved on disk instead of retrying a
        # chat that's in a bad state.
        _gemini_chats.pop(group_id, None)
        if isinstance(err, ServerError):
            return {"lead": "Gemini is temporarily overloaded — please try again in a moment."}
        return {"lead": "Couldn't reach Gemini right now — try again in a moment."}

    # Successful turn — persist the updated conversation immediately so it
    # survives a restart even if the very next request never happens.
    save_history(group_id, chat)

    try:
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(raw)
        lead = parsed.get("lead") or "I couldn't find a clear answer in this source's logs."
        bullets = parsed.get("bullets") or None
        return {"lead": lead, "bullets": bullets} if bullets else {"lead": lead}
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"[Gemini parse error] {e}")
        return {"lead": "Got a response I couldn't parse — try rephrasing the question."}


# =============================================================================
# ROUTES
# =============================================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    error = _data_provider.get_error()
    if error:
        return jsonify({
            "flows_analyzed": 0,
            "flows_analyzed_window": f"Error: {error}",
            "flagged": 0,
            "flagged_sources": 0,
            "avg_confidence": 0.0,
            "model": "Rule-Based Engine",
            "error": error,
        })

    flows = _data_provider.get_flows()
    flagged_flows = [f for f in flows if f["label"] != "BENIGN"]
    flagged_with_conf = [f for f in flagged_flows if f.get("confidence") is not None]
    avg_conf = (
        sum(f["confidence"] for f in flagged_with_conf) / len(flagged_with_conf)
    ) if flagged_with_conf else 0.0

    groups = get_groups()
    flagged_sources = len([g for g in groups if g["label"] != "BENIGN"])

    conn_log = _data_provider.get_conn_log_path()
    window = str(conn_log) if conn_log else "Unknown"

    return jsonify({
        "flows_analyzed": len(flows),
        "flows_analyzed_window": window,
        "flagged": len(flagged_flows),
        "flagged_sources": flagged_sources,
        "avg_confidence": round(avg_conf, 4),
        "model": "Rule-Based Engine",
    })


@app.route("/api/groups")
def api_groups():
    """One row per source. GET /api/groups"""
    error = _data_provider.get_error()
    if error:
        return jsonify({"error": error}), 503
    return jsonify(get_groups())


@app.route("/api/groups/<group_id>/logs")
def api_group_logs(group_id):
    """Every raw flow for one source. GET /api/groups/<src_ip>/logs"""
    error = _data_provider.get_error()
    if error:
        return jsonify({"error": error}), 503
    logs = get_group_logs(group_id)
    if not logs:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(logs)


@app.route("/api/groups/<group_id>/analysis")
def api_group_analysis(group_id):
    """The rule-based verdict for one source. GET /api/groups/<src_ip>/analysis"""
    error = _data_provider.get_error()
    if error:
        return jsonify({"error": error}), 503
    analysis = get_group_analysis(group_id)
    if analysis is None:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(analysis)


@app.route("/api/groups/<group_id>/chat/history")
def api_group_chat_history(group_id):
    """The chat bubbles already exchanged for this source, oldest first —
    used to replay the conversation after a page refresh.

    GET /api/groups/<src_ip>/chat/history
    response: [{ "sender": "user"|"bot", "lead": "...", "bullets": [...]? }, ...]
    """
    if not get_group_logs(group_id):
        return jsonify({"error": "unknown group"}), 404
    return jsonify(load_display_history(group_id))


@app.route("/api/groups/<group_id>/chat", methods=["POST"])
def api_group_chat(group_id):
    """Ask a follow-up question scoped to one source only. Remembers earlier
    turns for that source, resuming from disk across restarts, and records
    the turn so a page refresh can replay it via /chat/history.

    POST /api/groups/<src_ip>/chat   body: { "message": "<user text>" }
    response: { "lead": "<one-line answer>", "bullets": ["...", ...] }  // bullets optional
    """
    if not get_group_logs(group_id):
        return jsonify({"error": "unknown group"}), 404
    body = request.get_json(silent=True) or {}
    message = body.get("message", "")
    result = answer_group_chat(group_id, message)
    append_display_turns(group_id, message, result)
    return jsonify(result)


if __name__ == "__main__":
    # Force an initial data load so startup errors are visible immediately
    print("[Dashboard] Starting initial data load...")
    _data_provider.refresh()
    error = _data_provider.get_error()
    if error:
        print(f"[Dashboard] WARNING: {error}")
        print("[Dashboard] The dashboard will start but show no data until Zeek logs are available.")
    else:
        print(f"[Dashboard] Ready — serving {len(_data_provider.get_flows())} flows")

    # threaded=True so one slow in-flight Gemini call doesn't block every
    # other request on this process — cheap concurrency win for the dev
    # server. For real production traffic, run this behind gunicorn/uWSGI
    # with multiple workers instead of python app.py directly.
    app.run(debug=True, port=9000, threaded=True)