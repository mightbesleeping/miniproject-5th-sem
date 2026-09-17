"""
edr/alerter.py — Terminal alert display + JSONL alert log + DuckDB persistence.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "INFO":     Fore.CYAN,
    "LOW":      Fore.GREEN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

_SEVERITY_ICON = {
    "INFO":     "ℹ",
    "LOW":      "⚠",
    "MEDIUM":   "⚠",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}


class Alerter:
    """
    Handles alert output:
      - Coloured terminal banner
      - Append-only JSONL log file
      - DuckDB row insertion (optional)
    """

    def __init__(
        self,
        alert_log: str = "logs/alerts.jsonl",
        use_color: bool = True,
        db_store=None,  # edr.db.AlertStore | None
    ) -> None:
        self._alert_log = Path(alert_log)
        self._use_color = use_color
        self._db = db_store
        self._alert_no = 0

        # Ensure log directory exists
        self._alert_log.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def emit(self, rule, event: dict[str, Any]) -> None:
        """Emit one alert for *rule* / *event*."""
        self._alert_no += 1
        fired_at = datetime.now(timezone.utc).isoformat()
        alert = self._build_alert(rule, event, fired_at)

        self._print_terminal(alert)
        self._write_jsonl(alert)
        if self._db:
            try:
                self._db.insert(alert)
            except Exception as exc:  # noqa: BLE001
                logger.error("DuckDB insert failed: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_alert(self, rule, event: dict, fired_at: str) -> dict[str, Any]:
        fields = event.get("fields", {})
        return {
            "alert_no": self._alert_no,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "tags": rule.tags,
            "fired_at": fired_at,
            "event": {
                "serial": event.get("serial"),
                "timestamp": event.get("timestamp"),
                "pid": fields.get("pid"),
                "uid": fields.get("uid"),
                "exe": fields.get("exe"),
                "comm": fields.get("comm"),
                "cmd": event.get("cmd", ""),
                "cwd": fields.get("cwd"),
            },
        }

    def _print_terminal(self, alert: dict) -> None:
        sev = alert["severity"]
        color = _SEVERITY_COLOR.get(sev, "") if self._use_color else ""
        icon = _SEVERITY_ICON.get(sev, "•")
        reset = Style.RESET_ALL if self._use_color else ""
        sep = "═" * 70

        print(f"\n{color}{sep}{reset}")
        print(
            f"{color}{icon} {sev:8s} │  "
            f"Rule: {alert['rule_id']} — {alert['rule_name']}{reset}"
        )
        print(f"{color}{sep}{reset}")
        print(f"  Description : {alert['description'].strip()}")
        print(f"  Fired At    : {alert['fired_at']}")
        print(f"  Tags        : {', '.join(alert['tags'])}")
        print(f"  {'─' * 66}")
        ev = alert["event"]
        print(f"  PID         : {ev.get('pid', '?')}")
        print(f"  UID         : {ev.get('uid', '?')}")
        exe = ev.get("exe", "?")
        comm = ev.get("comm", "?")
        print(f"  Process     : {comm}  [{exe}]")
        print(f"  CWD         : {ev.get('cwd', '?')}")
        print(f"  Command     : {ev.get('cmd', '?')}")
        print(f"{color}{sep}{reset}")

    def _write_jsonl(self, alert: dict) -> None:
        try:
            with open(self._alert_log, "a") as fh:
                fh.write(json.dumps(alert) + "\n")
        except OSError as exc:
            logger.error("Could not write alert log: %s", exc)
