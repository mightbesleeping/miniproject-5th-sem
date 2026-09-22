"""
ui/app.py — Flask web dashboard for the EDR engine.

Launch with:
    uv run python ui/app.py
Then open http://localhost:5000
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

# Make sure the project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from edr.alerter import Alerter
from edr.collector import LogCollector
from edr.db import AlertStore
from edr.decoder import decode_event
from edr.engine import ThreatEngine
from edr.parser import EventAssembler, parse_line
from edr.utils import load_config, severity_gte

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["TEMPLATES_FOLDER"] = str(Path(__file__).parent / "templates")

# ---------------------------------------------------------------------------
# Global engine state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_alert_queues: list[queue.Queue] = []   # one per SSE subscriber
_stop_event = threading.Event()
_engine_thread: threading.Thread | None = None
_status: dict[str, Any] = {
    "running": False,
    "mode": None,          # "live" | "replay"
    "replay_file": None,
    "started_at": None,
    "alert_count": 0,
    "error": None,
}

# Shared persistent AlertStore — opened once, reused by engine thread + API routes
_shared_store: AlertStore | None = None


def _get_store() -> AlertStore | None:
    """Return the shared AlertStore, initializing it if needed."""
    global _shared_store
    if _shared_store is not None:
        return _shared_store
    cfg = load_config("config.yaml")
    db_cfg = cfg["edr"]["db"]
    if not db_cfg.get("enabled", True):
        return None
    try:
        _shared_store = AlertStore(db_cfg.get("path", "data/edr_alerts.duckdb"))
        return _shared_store
    except Exception as exc:
        logger.error("Failed to open shared AlertStore: %s", exc)
        return None


import logging
logger = logging.getLogger(__name__)


def _broadcast(payload: dict) -> None:
    """Push a dict to every active SSE subscriber."""
    msg = json.dumps(payload)
    with _lock:
        dead = []
        for q in _alert_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _alert_queues.remove(q)


# ---------------------------------------------------------------------------
# Custom alerter that also pushes to SSE
# ---------------------------------------------------------------------------
class DashboardAlerter(Alerter):
    def emit(self, rule, event: dict) -> None:
        super().emit(rule, event)
        fields = event.get("fields", {})
        payload = {
            "type": "alert",
            "alert_no": self._alert_no,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "fired_at": datetime.now(timezone.utc).isoformat(),
            "pid": fields.get("pid", "?"),
            "uid": fields.get("uid", "?"),
            "exe": fields.get("exe", "?"),
            "cmd": event.get("cmd", ""),
            "cwd": fields.get("cwd", "?"),
            "tags": rule.tags,
        }
        with _lock:
            _status["alert_count"] = self._alert_no
        _broadcast(payload)


# ---------------------------------------------------------------------------
# Engine thread
# ---------------------------------------------------------------------------
def _run_engine(cfg: dict, mode: str, replay_file: str | None) -> None:
    global _status
    edr_cfg = cfg["edr"]

    # Use the shared persistent store (already opened, batched writes)
    db_store = _get_store()
    if db_store is None and cfg["edr"]["db"].get("enabled", True):
        with _lock:
            _status["error"] = "DuckDB unavailable — running without persistence"

    alerter = DashboardAlerter(
        alert_log=edr_cfg.get("alert_log", "logs/alerts.jsonl"),
        use_color=False,
        db_store=db_store,
    )
    engine = ThreatEngine(rules_dir=edr_cfg.get("rules_dir", "rules"))
    assembler = EventAssembler()
    collector = LogCollector(edr_cfg.get("audit_log", "/var/log/audit/audit.log"))
    min_sev = edr_cfg.get("min_severity", "LOW").upper()

    _broadcast({"type": "status", "running": True, "mode": mode, "alert_count": 0})

    try:
        stream = (
            collector.replay(replay_file) if mode == "replay"
            else collector.tail()
        )

        prev_serial: str | None = None
        for raw_line in stream:
            if _stop_event.is_set():
                break
            record = parse_line(raw_line)
            if not record:
                continue
            serial = record["serial"]
            if prev_serial and serial != prev_serial:
                ev = assembler.flush_serial(prev_serial)
                if ev:
                    decode_event(ev)
                    for rule in engine.evaluate(ev):
                        if severity_gte(rule.severity, min_sev):
                            alerter.emit(rule, ev)
            assembler.feed(record)
            prev_serial = serial

        # Flush remainder
        for ev in assembler.flush_all():
            if _stop_event.is_set():
                break
            decode_event(ev)
            for rule in engine.evaluate(ev):
                if severity_gte(rule.severity, min_sev):
                    alerter.emit(rule, ev)

    except Exception as exc:
        with _lock:
            _status["error"] = str(exc)
        _broadcast({"type": "error", "message": str(exc)})
    finally:
        # Flush buffered alerts immediately — don't close the shared connection
        if db_store:
            db_store.flush()
        with _lock:
            _status["running"] = False
        _broadcast({"type": "status", "running": False})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stream")
def sse_stream():
    """Server-Sent Events endpoint — one persistent connection per browser tab."""
    q: queue.Queue = queue.Queue(maxsize=200)
    with _lock:
        _alert_queues.append(q)

    def generate():
        # Send current status on connect
        with _lock:
            current = dict(_status)
        yield f"data: {json.dumps({'type': 'status', **current})}\n\n"

        try:
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with _lock:
                try:
                    _alert_queues.remove(q)
                except ValueError:
                    pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify(dict(_status))


@app.route("/api/start", methods=["POST"])
def api_start():
    global _engine_thread, _stop_event

    with _lock:
        if _status["running"]:
            return jsonify({"ok": False, "error": "Engine already running"}), 409

    body = request.get_json(silent=True) or {}
    mode = body.get("mode", "replay")  # "live" | "replay"
    replay_file = body.get("replay_file")

    if mode == "replay" and not replay_file:
        return jsonify({"ok": False, "error": "replay_file required for replay mode"}), 400

    cfg = load_config("config.yaml")

    _stop_event = threading.Event()
    with _lock:
        _status.update({
            "running": True,
            "mode": mode,
            "replay_file": replay_file,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "alert_count": 0,
            "error": None,
        })

    _engine_thread = threading.Thread(
        target=_run_engine,
        args=(cfg, mode, replay_file),
        daemon=True,
    )
    _engine_thread.start()
    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    _stop_event.set()
    with _lock:
        _status["running"] = False
    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    store = _get_store()
    if store is None:
        return jsonify({"error": "DuckDB disabled or unavailable"}), 503
    try:
        store.flush()           # ensure latest buffered alerts are visible
        return jsonify(store.stats())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/recent")
def api_recent():
    store = _get_store()
    if store is None:
        return jsonify([])
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity") or None
    min_severity = request.args.get("min_severity") or None
    try:
        store.flush()
        rows = store.recent(limit=limit, severity=severity, min_severity=min_severity)
        # Serialize lists (tags) for JSON
        for r in rows:
            if isinstance(r.get("tags"), list):
                pass  # already serializable
        return jsonify(rows)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/timeline")
def api_timeline():
    """Alerts bucketed by time using DuckDB's date_trunc."""
    store = _get_store()
    if store is None:
        return jsonify([])
    bucket = request.args.get("bucket", "minute")
    last_n = int(request.args.get("last_n", 60))
    try:
        store.flush()
        return jsonify(store.timeline(bucket=bucket, last_n=last_n))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/heatmap")
def api_heatmap():
    """Alert count by hour-of-day × severity using DuckDB's hour() function."""
    store = _get_store()
    if store is None:
        return jsonify([])
    try:
        store.flush()
        return jsonify(store.heatmap())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/tags")
def api_tags():
    """MITRE ATT&CK tag frequency via unnest(tags) on the VARCHAR[] column."""
    store = _get_store()
    if store is None:
        return jsonify([])
    try:
        store.flush()
        return jsonify(store.tag_frequency())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/sessions")
def api_sessions():
    """Attack session correlation via DuckDB window functions."""
    store = _get_store()
    if store is None:
        return jsonify([])
    window = int(request.args.get("window", 5))
    try:
        store.flush()
        rows = store.attack_sessions(window_minutes=window)
        # Serialize lists inside rows
        for r in rows:
            if isinstance(r.get("rules_fired"), list):
                r["rules_fired"] = list(r["rules_fired"])
        return jsonify(rows)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/rules")
def api_rules():
    """Return list of all loaded rules."""
    cfg = load_config("config.yaml")
    engine = ThreatEngine(rules_dir=cfg["edr"].get("rules_dir", "rules"))
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "description": r.description.strip(),
            "tags": r.tags,
        }
        for r in engine.rules
    ]
    return jsonify(rules)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Change cwd to project root so config.yaml / rules/ / data/ resolve correctly
    os.chdir(Path(__file__).parent.parent)
    print("EDR Dashboard → http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
