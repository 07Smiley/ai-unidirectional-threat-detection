import json
import os
import sqlite3
import threading
import time
import hashlib
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request, Response
from google import genai
from google.genai import types
from google.genai.errors import APIError, ServerError

# Load .env BEFORE anything reads GEMINI_API_KEY / GEMINI_MODEL.
_ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(_ENV_FILE, override=True)  # .env next to this file
load_dotenv()                          # plus any .env found from the cwd


def _load_env_robust():
    """Fallback loader for .env files python-dotenv chokes on: UTF-8 BOM,
    UTF-16 (Windows Notepad), `.env.txt`, or a .env in a parent folder.
    Returns [(path, [variable names found])] — names only, never values."""
    here = Path(__file__).resolve().parent
    folders = [here, *list(here.parents)[:2], Path.cwd()]
    seen, report = set(), []
    for folder in folders:
        for name in (".env", ".env.txt", ".env.local", "env"):
            p = folder / name
            if not p.is_file() or p in seen:
                continue
            seen.add(p)
            raw = p.read_bytes()
            enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                report.append((p, ["<unreadable encoding>"]))
                continue
            keys = []
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.replace("export ", "").strip().lstrip("\ufeff")
                v = v.strip().strip("\"'").strip()
                if k:
                    keys.append(k)
                    if v:
                        os.environ[k] = v
            report.append((p, keys))
    return report


_ENV_DIAG = _load_env_robust()


def _env_diag_text():
    if not _ENV_DIAG:
        return (f"No .env file found (looked in {_ENV_FILE.parent}, its parents, and {Path.cwd()}).")
    return "Env files read: " + "; ".join(
        f"{p} → variables: {', '.join(keys) or 'none'}" for p, keys in _ENV_DIAG
    )

app = Flask(__name__)

# =============================================================================
# LIVE SENSOR API
#
# The FastAPI sensor runs at BACKEND_HOST:BACKEND_PORT. The browser talks to it
# through the /live-api/* proxy below (same origin, so no CORS setup needed).
# Only the WebSocket goes straight to the sensor.
# =============================================================================

_BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
_BACKEND_PORT = os.environ.get("BACKEND_PORT", "8000")
LIVE_API_URL = f"http://{_BACKEND_HOST}:{_BACKEND_PORT}"


# =============================================================================
# GEMINI CLIENT
#
# Reads GEMINI_API_KEY from the environment (.env loaded above). Model comes
# from GEMINI_MODEL; default is gemini-3.5-flash. If your .env sets
# GEMINI_MODEL, that value wins over this default.
# =============================================================================

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
_gemini_client = None


def _gemini_key():
    """GEMINI_API_KEY (or GOOGLE_API_KEY), trimmed of spaces/quotes."""
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        val = (os.environ.get(name) or "").strip().strip("\"'").strip()
        if val:
            return val
    return ""


def get_gemini_client():
    global _gemini_client
    if _gemini_client is None:
        api_key = _gemini_key()
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. " + _env_diag_text()
            )
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


def _gemini_error_text(err):
    """Turn a Gemini SDK exception into a message that says what's wrong."""
    if isinstance(err, ServerError):
        return "Gemini is temporarily overloaded — please try again in a moment."
    if isinstance(err, APIError):
        code = getattr(err, "code", None)
        msg = str(getattr(err, "message", None) or err)[:240]
        hint = ""
        if code == 404:
            hint = f" Model '{GEMINI_MODEL}' was not found — set GEMINI_MODEL to a valid model id."
        elif code in (401, 403):
            hint = " Check GEMINI_API_KEY."
        elif code == 429:
            hint = " Quota or rate limit hit."
        elif code == 400:
            hint = " Bad request — check the model id and API key."
        return f"Gemini API error {code}: {msg}{hint}"
    return f"Couldn't reach Gemini: {type(err).__name__}: {str(err)[:240]}"


# =============================================================================
# CHAT PERSISTENCE (SQLite)
#
#   chat_history  -> raw Gemini Content history per source (model memory).
#   chat_display  -> clean bubbles per source (UI replay after refresh).
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
    conn = _db()
    try:
        row = conn.execute(
            "SELECT history FROM chat_history WHERE group_id = ?", (group_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        raw_turns = json.loads(row[0])
        return [types.Content.model_validate(turn) for turn in raw_turns]
    except Exception as e:
        # Corrupt/incompatible saved history must not break chat forever.
        print(f"[Chat] Ignoring unreadable saved history for {group_id}: {e}")
        return None


def save_history(group_id, chat):
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
    conn = _db()
    try:
        row = conn.execute(
            "SELECT entries FROM chat_display WHERE group_id = ?", (group_id,)
        ).fetchone()
    finally:
        conn.close()
    return json.loads(row[0]) if row else []


def append_display_turns(group_id, user_message, bot_payload):
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
# =============================================================================

_gemini_chats = {}  # group_id -> chat session (in-process cache)
MAX_FLOWS_IN_PROMPT = 60  # newest flows only; smaller prompt = faster reply

# Speed knobs (override in .env):
#   GEMINI_MODEL      e.g. gemini-3.1-flash-lite for the fastest replies
#   GEMINI_THINKING   minimal | low | high | off  (default: minimal)
#   GEMINI_MAX_OUTPUT reply token cap (default 800)
GEMINI_THINKING = os.environ.get("GEMINI_THINKING", "minimal").strip().lower()
GEMINI_MAX_OUTPUT = int(os.environ.get("GEMINI_MAX_OUTPUT", "800"))
_flags = {"thinking_ok": True}  # flipped off automatically if the model rejects it


def _build_config():
    kwargs = dict(
        system_instruction=CHAT_SYSTEM_PROMPT
        + "\n\nBe fast and brief: lead max 2 short sentences, at most 3 bullets, no preamble.",
        response_mime_type="application/json",
        temperature=0.2,
        max_output_tokens=GEMINI_MAX_OUTPUT,
    )
    if _flags["thinking_ok"] and GEMINI_THINKING not in ("", "off", "none"):
        try:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_level=GEMINI_THINKING)
        except Exception:
            pass  # older SDK without thinking_level
    return types.GenerateContentConfig(**kwargs)


def _send_with_retry(chat, message, max_attempts=3):
    """Returns (raw_text, error). Exactly one is None."""
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = chat.send_message(message)
            return (response.text or "").strip(), None
        except ServerError as e:
            last_error = e
            print(f"[Gemini server error, attempt {attempt}/{max_attempts}] {e}")
            if attempt < max_attempts:
                time.sleep(1.0 * attempt)
        except Exception as e:
            last_error = e
            print(f"[Gemini call failed] {type(e).__name__}: {e}")
            break
    return None, last_error


def get_or_create_group_chat(group_id, client):
    """Return (chat, is_new). No network call happens here."""
    chat = _gemini_chats.get(group_id)
    if chat is not None:
        return chat, False

    saved_history = load_history(group_id)
    if saved_history:
        chat = client.chats.create(model=GEMINI_MODEL, history=saved_history, config=_build_config())
        _gemini_chats[group_id] = chat
        return chat, False

    chat = client.chats.create(model=GEMINI_MODEL, config=_build_config())
    _gemini_chats[group_id] = chat
    return chat, True


# =============================================================================
# SHARED HELPERS
# =============================================================================

DASHBOARD_TIMEZONE = ZoneInfo("Asia/Kolkata")


def _safe_float(val, default=0.0):
    try:
        f = float(val)
        if pd.isna(f):
            return default
        return f
    except (ValueError, TypeError):
        return default


def _format_timestamp(ts_epoch):
    """Unix epoch -> local dashboard time (IST)."""
    try:
        ts = float(ts_epoch)
        if pd.isna(ts):
            return "—"
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(DASHBOARD_TIMEZONE).strftime("%H:%M:%S")
    except (ValueError, TypeError, OSError):
        return "—"


def _format_activity_duration(seconds):
    try:
        total = max(0, int(round(float(seconds))))
    except (ValueError, TypeError):
        return "0s"
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _score_from_severity(label, severity):
    """Rule detectors give no calibrated probability; derive a 0-100 score
    from severity only. Benign flows score 0 and have no confidence."""
    if label == "BENIGN":
        return 0.0
    if severity == "high":
        return 85.0
    if severity == "medium":
        return 65.0
    return 50.0


def _make_features(duration, orig_bytes, resp_bytes, total_pkts, packet_rate):
    return [
        {"name": "Duration", "value": f"{duration:.3f}s"},
        {"name": "Orig Bytes", "value": f"{int(orig_bytes)}"},
        {"name": "Resp Bytes", "value": f"{int(resp_bytes)}"},
        {"name": "Total Packets", "value": f"{int(total_pkts)}"},
        {"name": "Packet Rate", "value": f"{packet_rate:.1f} pkt/s"},
    ]


# =============================================================================
# REAL DATA PROVIDER — Zeek logs -> features -> rule detectors -> dashboard
# format. Detection logic stays in src/ and backend/ and is NOT duplicated.
# =============================================================================

try:
    from src.ingest.pcap_reader import read_zeek_log
    from src.features.flow_features import create_flow_features
    from backend.services import run_rule_detectors
    _PIPELINE_ERROR = None
except Exception as _imp_err:
    read_zeek_log = create_flow_features = run_rule_detectors = None
    _PIPELINE_ERROR = f"Detection pipeline import failed: {type(_imp_err).__name__}: {_imp_err}"
    print(f"[Dashboard] {_PIPELINE_ERROR}")

_REPO_ROOT = Path(__file__).resolve().parent

_ZEEK_LOG_DIR_CANDIDATES = [
    os.environ.get("ZEEK_LOG_DIR", ""),
    str(_REPO_ROOT / "data" / "processed" / "zeek" / "live"),
]

_CACHE_TTL = float(os.environ.get("DASHBOARD_CACHE_TTL", "5"))


def _find_zeek_log_dir():
    for candidate in _ZEEK_LOG_DIR_CANDIDATES:
        if not candidate:
            continue
        p = Path(candidate)
        if p.is_dir() and (p / "conn.log").exists():
            return p
    return None


def _threat_matches_flow(threat, src_ip, dst_ip, dst_port, flow_ts):
    """Match a detector alert to the specific Zeek flow it describes."""
    t_src = threat.get("src_ip", "")
    t_dst = threat.get("dst_ip", "")
    ttype = threat.get("type", "")

    if ttype == "possible_port_scan":
        return t_src == src_ip and t_dst == dst_ip
    if ttype == "possible_ddos":
        return t_dst == dst_ip
    if ttype in {"possible_beaconing", "possible_exfiltration"}:
        return t_src == src_ip and t_dst == dst_ip
    if ttype == "possible_dga":
        t_ts = _safe_float(threat.get("ts"), None)
        flow_ts = _safe_float(flow_ts, None)
        t_port = threat.get("dst_port")
        try:
            t_port_int = int(float(t_port)) if t_port not in (None, "", "-") else None
        except (TypeError, ValueError):
            t_port_int = None
        try:
            flow_port_int = int(float(dst_port)) if dst_port not in (None, "", "-") else None
        except (TypeError, ValueError):
            flow_port_int = None
        time_match = (
            t_ts is not None
            and flow_ts is not None
            and abs(t_ts - flow_ts) <= 5.0
        )
        port_match = t_port_int is None or flow_port_int == t_port_int
        return (
            t_src == src_ip
            and t_dst == dst_ip
            and port_match
            and time_match
        )
    return False


class RealDataProvider:
    """Reads Zeek logs, runs the detection pipeline, caches the results.
    Cache refreshes when conn.log's mtime changes or the TTL expires."""

    def __init__(self):
        self._flows = []
        self._threats = []
        self._flow_df = None
        self._conn_log_path = None
        self._last_mtime = 0
        self._last_refresh = 0
        self._last_error = None
        self._hostname_map = {}
        self._zeek_dir = None
        self._lock = threading.Lock()

    def _should_refresh(self):
        now = time.time()
        if now - self._last_refresh < _CACHE_TTL:
            return False

        zeek_dir = _find_zeek_log_dir()
        if zeek_dir is None:
            if not self._flows:
                self._last_error = "Waiting for Zeek logs — no conn.log found yet. Press Start."
            return False

        conn_log = zeek_dir / "conn.log"
        try:
            current_mtime = conn_log.stat().st_mtime
        except OSError:
            return False

        if current_mtime != self._last_mtime or self._zeek_dir != zeek_dir:
            return True

        self._last_refresh = now
        return False

    def _load_hostname_map(self, zeek_dir):
        """dst IP -> hostname from DNS/SSL logs. Never fabricates names."""
        hostname_map = {}

        dns_log = zeek_dir / "dns.log"
        if dns_log.exists():
            try:
                dns_df = read_zeek_log(dns_log)
                if not dns_df.empty and "query" in dns_df.columns and "answers" in dns_df.columns:
                    for _, row in dns_df.iterrows():
                        query = row.get("query", "")
                        answers = str(row.get("answers", ""))
                        if query and answers and answers != "-":
                            for answer in answers.split(","):
                                answer = answer.strip()
                                if answer and answer[0].isdigit():
                                    hostname_map[answer] = query
            except Exception as e:
                print(f"[Dashboard] Warning: Could not parse DNS log: {e}")

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
        if _PIPELINE_ERROR:
            self._last_error = _PIPELINE_ERROR
            self._last_refresh = time.time()
            return

        zeek_dir = _find_zeek_log_dir()
        if zeek_dir is None:
            self._last_error = "Waiting for Zeek logs — no conn.log found yet. Press Start."
            self._last_refresh = time.time()
            return

        conn_log = zeek_dir / "conn.log"
        try:
            self._conn_log_path = conn_log
            self._zeek_dir = zeek_dir

            zeek_df = read_zeek_log(conn_log)
            flow_df = create_flow_features(zeek_df)
            self._flow_df = flow_df

            self._hostname_map = self._load_hostname_map(zeek_dir)

            self._threats = run_rule_detectors(
                flow_df,
                conn_log=conn_log,
                dns_log=zeek_dir / "dns.log",
            )
            threats = self._threats

            flows = []
            for idx, row in flow_df.iterrows():
                src_ip = str(row.get("id.orig_h", ""))
                dst_ip = str(row.get("id.resp_h", ""))
                dst_port = row.get("id.resp_p")
                proto = str(row.get("proto", "")).upper()
                ts = row.get("ts")
                duration = _safe_float(row.get("duration"), 0.0)
                total_pkts = _safe_float(row.get("total_packets"), 0)
                packet_rate = _safe_float(row.get("packet_rate"), 0)
                orig_bytes = _safe_float(row.get("orig_bytes"), 0)
                resp_bytes = _safe_float(row.get("resp_bytes"), 0)

                label = "BENIGN"
                why = []
                severity = None

                for t in threats:
                    if _threat_matches_flow(t, src_ip, dst_ip, dst_port, ts):
                        ttype = t.get("type", "")
                        t_dst = t.get("dst_ip", "")
                        label = ttype.replace("possible_", "").upper()
                        severity = t.get("severity", "medium")
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
                        break

                host = self._hostname_map.get(dst_ip)

                # Flow id: Zeek UID when present, else a stable hash.
                uid = row.get("uid", "")
                if isinstance(uid, str) and uid and uid != "-":
                    flow_id = uid
                else:
                    raw_id = f"{src_ip}:{dst_ip}:{dst_port}:{ts}"
                    flow_id = "fl_" + hashlib.md5(raw_id.encode()).hexdigest()[:8]

                threat_score = _score_from_severity(label, severity)
                confidence = (threat_score / 100.0) if label != "BENIGN" else None

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
                    "threat_score": threat_score,
                    "label": label,
                    "packets_per_sec": round(packet_rate, 1),
                    "packets": int(total_pkts),
                    "why": why,
                    "features": _make_features(duration, orig_bytes, resp_bytes, total_pkts, packet_rate),
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
        with self._lock:
            stale_empty = (not self._flows) and (time.time() - self._last_refresh >= _CACHE_TTL)
            if self._should_refresh() or stale_empty:
                self.refresh()

    def get_flows(self):
        self._ensure_fresh()
        return self._flows

    def get_threats(self):
        self._ensure_fresh()
        return self._threats

    def get_error(self):
        self._ensure_fresh()
        # A failed refresh (e.g. conn.log mid-write) must not blank the UI
        # while we still hold good flows from the last successful read.
        if self._flows and not _PIPELINE_ERROR:
            return None
        return self._last_error

    def get_conn_log_path(self):
        self._ensure_fresh()
        return self._conn_log_path

    def get_zeek_dir(self):
        self._ensure_fresh()
        return self._zeek_dir


_data_provider = RealDataProvider()


def _src():
    """Live data only."""
    return _data_provider


# =============================================================================
# DATA FUNCTIONS
# =============================================================================

def get_groups():
    """One row per source (src_ip), aggregated from the active flow set."""
    flows = _src().get_flows()
    groups = {}
    for flow in flows:
        key = flow["src_ip"]
        g = groups.setdefault(key, {
            "group_id": key,
            "src_ip": flow["src_ip"],
            "host": flow.get("host"),
            "request_count": 0,
            "flagged_flows": 0,
            "label": "BENIGN",
            "confidence": None,
            "threat_score": 0.0,
            "last_seen": flow["timestamp"],
            "last_seen_epoch": flow.get("timestamp_epoch", 0),
            "_last_epoch": flow.get("timestamp_epoch", 0),
        })
        g["request_count"] += 1
        flow_score = float(flow.get("threat_score", 0.0) or 0.0)
        if flow_score > g["threat_score"]:
            g["threat_score"] = flow_score
            if flow["label"] != "BENIGN":
                g["label"] = flow["label"]
        if flow["label"] != "BENIGN":
            g["flagged_flows"] += 1
        if flow["confidence"] is not None:
            if g["confidence"] is None or flow["confidence"] > g["confidence"]:
                g["confidence"] = flow["confidence"]
        flow_epoch = flow.get("timestamp_epoch", 0)
        if flow_epoch > g["_last_epoch"]:
            g["last_seen"] = flow["timestamp"]
            g["last_seen_epoch"] = flow_epoch
            g["_last_epoch"] = flow_epoch
        if g["host"] is None and flow.get("host"):
            g["host"] = flow["host"]

    result = []
    for g in groups.values():
        del g["_last_epoch"]
        result.append(g)

    return sorted(result, key=lambda g: (
        -g["threat_score"],
        -(g["confidence"] or 0),
        -g["request_count"],
        g["src_ip"],
    ))


def get_group_logs(group_id):
    """All raw flows for one source, newest first."""
    flows = _src().get_flows()
    source_flows = [f for f in flows if f["src_ip"] == group_id]
    return sorted(
        source_flows,
        key=lambda f: f.get("timestamp_epoch", 0),
        reverse=True,
    )


def get_group_analysis(group_id):
    """Source-detail evidence shown in the dashboard."""
    logs = get_group_logs(group_id)
    if not logs:
        return None

    flagged = [l for l in logs if l["label"] != "BENIGN"]
    total = len(logs)
    reference = flagged or logs

    protocols = [str(l.get("protocol") or "").upper() for l in reference if l.get("protocol")]
    protocol = max(set(protocols), key=protocols.count) if protocols else "—"

    ports = []
    for l in reference:
        port = l.get("dst_port")
        if port not in (None, "", "-"):
            try:
                port = int(float(port))
            except (TypeError, ValueError):
                port = str(port)
            if port not in ports:
                ports.append(port)

    timed_logs = [
        l for l in logs
        if l.get("timestamp_epoch") is not None
        and _safe_float(l.get("timestamp_epoch"), None) is not None
    ]
    if timed_logs:
        first_epoch = min(_safe_float(l.get("timestamp_epoch"), 0) for l in timed_logs)
        last_epoch = max(_safe_float(l.get("timestamp_epoch"), 0) for l in timed_logs)
        activity_duration = _format_activity_duration(last_epoch - first_epoch)
    else:
        activity_duration = "—"

    reasons = []
    seen_reasons = set()
    for l in flagged:
        for reason in l.get("why", []):
            if reason not in seen_reasons:
                reasons.append(reason)
                seen_reasons.add(reason)

    if flagged:
        worst = max(flagged, key=lambda l: l.get("confidence") or 0)
        all_types = sorted(set(l["label"] for l in flagged))
        type_str = ", ".join(all_types)
        conf_str = f" (severity-derived confidence: {worst['confidence']*100:.0f}%)" if worst.get("confidence") is not None else ""
        lead = f"{len(flagged)} of {total} flow(s) from this source were flagged as {type_str}{conf_str}."
        return {
            "lead": lead,
            "bullets": reasons or ["Flagged by rule-based detection engine."],
            "label": worst["label"],
            "confidence": worst.get("confidence"),
            "threat_score": max(float(l.get("threat_score", 0.0) or 0.0) for l in flagged),
            "total_flows": total,
            "flagged_flows": len(flagged),
            "protocol": protocol,
            "top_ports": ports[:8],
            "activity_duration": activity_duration,
            "top_flow": worst,
        }

    return {
        "lead": f"All {total} flow(s) from this source look benign — no rule-based detections triggered.",
        "bullets": [],
        "label": "BENIGN",
        "confidence": None,
        "threat_score": 0.0,
        "total_flows": total,
        "flagged_flows": 0,
        "protocol": protocol,
        "top_ports": ports[:8],
        "activity_duration": activity_duration,
        "top_flow": logs[0],
    }


CHAT_SYSTEM_PROMPT = """You are a cybersecurity flow-analysis assistant for a network monitoring dashboard.

Your job is to analyze ONLY the network flow/log data provided to you.

Explain the result in very simple English, like you are explaining it to a 10-year-old, but keep it professional. Do NOT use complicated cybersecurity words unless absolutely necessary. If you use a technical term, explain it in simple words.

Always give your answer in this exact structure:

### 1. What Happened?

Briefly explain what happened in the network.

Mention:

* What type of activity was detected
* Which system/flow was involved, if available
* Whether the activity looks normal or suspicious

### 2. When Did It Happen?

Give the exact date and time from the provided data if available.

If a timestamp is not available, say:
"Exact time is not available in the provided data."

Do NOT make up a time.

### 3. What Was Seen?

Explain the important signs in simple language.

For example:

* A very large amount of traffic appeared
* Many connections happened in a short period
* The traffic pattern suddenly changed
* One system was sending much more traffic than usual

Use actual values from the data whenever available.

### 4. What Does It Mean?

Explain what the activity means in simple words.

Example:
"This looks like a DDoS attack because a very large amount of traffic was sent toward the system in a short period of time."

Do not exaggerate or claim something is definitely an attack unless the provided detection result supports it.

### 5. How Serious Is It?

Use only one of:

* Low
* Medium
* High
* Critical

Give one short reason for the severity.

### 6. What Should Be Done?

Give 2–4 simple actions.

Examples:

* Check the affected system
* Block or limit suspicious traffic if appropriate
* Check whether the traffic is still happening
* Review nearby network activity
* Inform the network/security team

Keep recommendations practical and short.

### 7. One-Line Summary

End with one simple sentence:

"At [time], the system detected [activity], which appears to be [normal/suspicious/attack type]."

IMPORTANT RULES:

* Use only information present in the supplied flow/log data.
* Never invent IP addresses, timestamps, ports, attack details, or statistics.
* Do not invent missing information.
* Do not assume an attack happened just because traffic is unusual.
* Clearly distinguish between "detected", "suspicious", and "confirmed".
* Keep the explanation short and easy to understand.
* Prefer plain English over technical terminology.
* Do not give a long lecture about cybersecurity.
* Do not explain how to perform an attack.
* Focus on what happened, when it happened, what was observed, what it means, and what the operator should do.
* If the data is insufficient to determine something, explicitly say that the information is not available.

The final response should look clean and readable in a dashboard.
"""


def _source_summary(group_id):
    a = get_group_analysis(group_id) or {}
    keys = ("label", "threat_score", "total_flows", "flagged_flows",
            "protocol", "top_ports", "activity_duration")
    data = {k: a.get(k) for k in keys}
    data["reasons"] = (a.get("bullets") or [])[:5]
    return json.dumps(data, separators=(",", ":"))


def _compact_flows(logs):
    """Flows as compact rows instead of pretty-printed dicts — roughly a
    5-10x smaller prompt, which is the main cost of the first reply."""
    rows = []
    for f in logs[:MAX_FLOWS_IN_PROMPT]:
        feat = {x["name"]: x["value"] for x in f.get("features", [])}
        rows.append([
            f["id"], f["timestamp"], f["dst_ip"], f["dst_port"], f["protocol"],
            f.get("packets"), f["packets_per_sec"],
            feat.get("Orig Bytes"), feat.get("Resp Bytes"),
            f["label"], f["threat_score"],
        ])
    head = "columns: [id,time,dst,port,proto,pkts,pps,orig_bytes,resp_bytes,label,score]"
    if len(logs) > len(rows):
        head += f" (newest {len(rows)} of {len(logs)} flows)"
    return head + "\n" + json.dumps(rows, separators=(",", ":"))


def answer_group_chat(group_id, message):
    """Answer a question using ONLY this source's own flows, with memory of
    earlier turns (resumed from SQLite after a restart).

    Returns (payload, ok). On failure payload is {"error": "<why>"} and ok
    is False, so the route can return a non-200 and skip persisting it.
    """
    logs = get_group_logs(group_id)
    if not logs:
        return {"error": "No logged flows for this source."}, False

    try:
        client = get_gemini_client()
    except RuntimeError as e:
        print(f"[Gemini config error] {e}")
        return {"error": str(e)}, False

    try:
        chat, is_new = get_or_create_group_chat(group_id, client)
    except Exception as e:
        print(f"[Gemini session open failed] {type(e).__name__}: {e}")
        return {"error": _gemini_error_text(e)}, False

    def build_outgoing(first):
        if first:
            return (
                f"Source {group_id} summary: {_source_summary(group_id)}\n"
                f"Flows (newest first):\n{_compact_flows(logs)}\n\n"
                f"Question: {message}"
            )
        return message

    raw, err = _send_with_retry(chat, build_outgoing(is_new))

    # If the model rejects the thinking setting, switch it off once and retry.
    if (
        raw is None
        and _flags["thinking_ok"]
        and isinstance(err, APIError)
        and getattr(err, "code", None) == 400
        and "think" in str(err).lower()
    ):
        print("[Gemini] thinking_level rejected by this model — retrying without it")
        _flags["thinking_ok"] = False
        _gemini_chats.pop(group_id, None)
        try:
            chat, is_new = get_or_create_group_chat(group_id, client)
        except Exception as e:
            return {"error": _gemini_error_text(e)}, False
        raw, err = _send_with_retry(chat, build_outgoing(is_new))

    if raw is None:
        # Drop the in-process session; next question resumes from disk.
        _gemini_chats.pop(group_id, None)
        return {"error": _gemini_error_text(err)}, False

    save_history(group_id, chat)

    try:
        cleaned = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(cleaned)
        lead = parsed.get("lead") or "I couldn't find a clear answer in this source's logs."
        bullets = parsed.get("bullets") or None
        return ({"lead": lead, "bullets": bullets} if bullets else {"lead": lead}), True
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"[Gemini parse error] {e} | raw: {raw[:300]!r}")
        # Model answered but not as JSON — show its text rather than failing.
        if raw:
            return {"lead": raw[:1200]}, True
        return {"error": "Gemini returned an empty reply — try rephrasing."}, False


# =============================================================================
# ROUTES
# =============================================================================

@app.route("/")
def home():
    return render_template("index.html", live_api=LIVE_API_URL)


@app.route("/live-api/<path:path>", methods=["GET", "POST"])
def live_api_proxy(path):
    """Same-origin proxy to the FastAPI sensor — the Start/Stop buttons go
    through here so the browser never needs CORS to reach port 8000."""
    if not path.startswith("api/live/"):
        return jsonify({"detail": "Not allowed."}), 404
    data = request.get_data() if request.method == "POST" else None
    req = urllib.request.Request(
        f"{LIVE_API_URL}/{path}",
        data=data,
        method=request.method,
        headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return Response(
                r.read(), status=r.status,
                content_type=r.headers.get("Content-Type", "application/json"),
            )
    except urllib.error.HTTPError as e:
        return Response(
            e.read(), status=e.code,
            content_type=e.headers.get("Content-Type", "application/json"),
        )
    except Exception as e:
        return jsonify({"detail": f"Sensor API unreachable at {LIVE_API_URL}: {e}"}), 502


@app.route("/api/gemini/status")
def api_gemini_status():
    return jsonify({
        "configured": bool(_gemini_key()),
        "model": GEMINI_MODEL,
    })


def get_top_recent(flows, n=20):
    """Highest-scoring flow among the n most recent flows, plus how long
    that source has been attacking (first -> last flagged flow)."""
    if not flows:
        return None
    recent = sorted(flows, key=lambda f: f.get("timestamp_epoch", 0), reverse=True)[:n]
    top = max(recent, key=lambda f: (float(f.get("threat_score", 0.0) or 0.0), f.get("timestamp_epoch", 0)))
    score = float(top.get("threat_score", 0.0) or 0.0)
    if score <= 0:
        return None
    src = top["src_ip"]
    epochs = [f.get("timestamp_epoch") for f in flows
              if f["src_ip"] == src and f["label"] != "BENIGN" and f.get("timestamp_epoch")]
    duration = _format_activity_duration(max(epochs) - min(epochs)) if epochs else "0s"
    return {
        "score": round(score, 2),
        "src_ip": src,
        "label": top["label"],
        "duration": duration,
        "last_seen": top["timestamp"],
    }


@app.route("/api/stats")
def api_stats():
    provider = _src()
    error = provider.get_error()
    if error:
        return jsonify({
            "flows_analyzed": 0,
            "flows_analyzed_window": error,
            "flagged": 0,
            "flagged_sources": 0,
            "avg_confidence": 0.0,
            "model": "Rule-Based Engine",
            "mode": "live",
            "top_recent": None,
            "error": error,
        })

    flows = provider.get_flows()
    flagged_flows = [f for f in flows if f["label"] != "BENIGN"]
    flagged_with_conf = [f for f in flagged_flows if f.get("confidence") is not None]
    avg_conf = (
        sum(f["confidence"] for f in flagged_with_conf) / len(flagged_with_conf)
    ) if flagged_with_conf else 0.0
    max_threat_score = max(
        (float(f.get("threat_score", 0.0) or 0.0) for f in flows),
        default=0.0,
    )

    groups = get_groups()
    flagged_sources = len([g for g in groups if g["threat_score"] > 0])

    conn_log = provider.get_conn_log_path()
    window = str(conn_log) if conn_log else "Unknown"

    return jsonify({
        "flows_analyzed": len(flows),
        "flows_analyzed_window": window,
        "flagged": len(flagged_flows),
        "flagged_sources": flagged_sources,
        "avg_confidence": round(avg_conf, 4),
        "max_threat_score": round(max_threat_score, 2),
        "top_recent": get_top_recent(flows),
        "model": "Rule-Based Engine",
        "mode": "live",
    })


@app.route("/api/logs")
def api_logs():
    provider = _src()
    error = provider.get_error()
    if error:
        return jsonify({"error": error}), 503
    return jsonify(provider.get_flows())


@app.route("/api/groups")
def api_groups():
    error = _src().get_error()
    if error:
        return jsonify({"error": error}), 503
    return jsonify(get_groups())


@app.route("/api/groups/<group_id>/logs")
def api_group_logs(group_id):
    error = _src().get_error()
    if error:
        return jsonify({"error": error}), 503
    logs = get_group_logs(group_id)
    if not logs:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(logs)


@app.route("/api/groups/<group_id>/analysis")
def api_group_analysis(group_id):
    error = _src().get_error()
    if error:
        return jsonify({"error": error}), 503
    analysis = get_group_analysis(group_id)
    if analysis is None:
        return jsonify({"error": "unknown group"}), 404
    return jsonify(analysis)


@app.route("/api/groups/<group_id>/chat/history")
def api_group_chat_history(group_id):
    """Bubbles already exchanged for this source, oldest first."""
    if not get_group_logs(group_id):
        return jsonify({"error": "unknown group"}), 404
    return jsonify(load_display_history(group_id))


@app.route("/api/groups/<group_id>/chat", methods=["POST"])
def api_group_chat(group_id):
    """POST /api/groups/<src_ip>/chat  body: {"message": "..."}
    200 -> {"lead": "...", "bullets": [...]?}
    4xx/5xx -> {"error": "<reason>"}  (errors are NOT saved to chat history)
    """
    if not get_group_logs(group_id):
        return jsonify({"error": "unknown group"}), 404
    body = request.get_json(silent=True) or {}
    message = str(body.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Empty message."}), 400

    result, ok = answer_group_chat(group_id, message)
    if not ok:
        return jsonify(result), 502
    append_display_turns(group_id, message, result)
    return jsonify(result)


if __name__ == "__main__":
    print(f"[Dashboard] Live API {LIVE_API_URL} · Gemini model {GEMINI_MODEL}")
    print(f"[Dashboard] Gemini key: {'loaded' if _gemini_key() else 'MISSING'} · {_env_diag_text()}")
    print("[Dashboard] Starting initial data load...")
    _data_provider.refresh()
    error = _data_provider.get_error()
    if error:
        print(f"[Dashboard] NOTE: {error}")
    else:
        print(f"[Dashboard] Real data ready — {len(_data_provider.get_flows())} flows")

    app.run(
        host=os.environ.get("DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("DASHBOARD_PORT", "9000")),
        debug=os.environ.get("DASHBOARD_DEBUG", "0") == "1",
        threaded=True,
        use_reloader=False,
    )