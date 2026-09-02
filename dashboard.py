import json
import os
import sqlite3
import time
from datetime import datetime, timezone

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
# SAMPLE DATA — stands in for the real pipeline until Zeek + the ML model are
# wired up. Everything below the sample data is the part you replace:
#
#   get_groups()          -> pull distinct sources from Zeek conn logs + model
#                             verdicts, one row per source IP (+ host if known)
#   get_group_logs()       -> the individual flows Zeek logged for that source
#   get_group_analysis()   -> the model's structured verdict for that source
#   answer_group_chat()    -> calls Gemini, given ONLY that source's logs as
#                             context (never the whole dataset)
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
    # threaded=True so one slow in-flight Gemini call doesn't block every
    # other request on this process — cheap concurrency win for the dev
    # server. For real production traffic, run this behind gunicorn/uWSGI
    # with multiple workers instead of python app.py directly.
    app.run(debug=True, port=9000, threaded=True)