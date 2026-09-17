"""
edr/db.py — DuckDB alert persistence layer.

Schema
------
CREATE SEQUENCE alerts_id_seq START 1;
CREATE TABLE alerts (
    id              INTEGER DEFAULT nextval('alerts_id_seq') PRIMARY KEY,
    alert_no        INTEGER NOT NULL,
    rule_id         VARCHAR(50) NOT NULL,
    rule_name       VARCHAR(255) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    description     TEXT,
    tags            VARCHAR(500),
    fired_at        TIMESTAMP,
    event_serial    VARCHAR(30),
    event_timestamp VARCHAR(30),
    event_pid       VARCHAR(20),
    event_uid       VARCHAR(20),
    event_exe       VARCHAR(500),
    event_comm      VARCHAR(255),
    event_cmd       TEXT,
    event_cwd       VARCHAR(500),
    created_at      TIMESTAMP DEFAULT current_timestamp
);
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb

logger = logging.getLogger(__name__)

_DDL = """
CREATE SEQUENCE IF NOT EXISTS alerts_id_seq START 1;

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER DEFAULT nextval('alerts_id_seq') PRIMARY KEY,
    alert_no        INTEGER NOT NULL,
    rule_id         VARCHAR(50) NOT NULL,
    rule_name       VARCHAR(255) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    description     TEXT,
    tags            VARCHAR(500),
    fired_at        TIMESTAMP,
    event_serial    VARCHAR(30),
    event_timestamp VARCHAR(30),
    event_pid       VARCHAR(20),
    event_uid       VARCHAR(20),
    event_exe       VARCHAR(500),
    event_comm      VARCHAR(255),
    event_cmd       TEXT,
    event_cwd       VARCHAR(500),
    created_at      TIMESTAMP DEFAULT current_timestamp
);
"""

_INSERT = """
INSERT INTO alerts (
    alert_no, rule_id, rule_name, severity, description, tags, fired_at,
    event_serial, event_timestamp, event_pid, event_uid,
    event_exe, event_comm, event_cmd, event_cwd
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


class AlertStore:
    """Thread-safe(-ish) DuckDB wrapper for alert persistence."""

    def __init__(self, db_path: str = "data/edr_alerts.duckdb") -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._con = duckdb.connect(str(self._path))
        self._init_schema()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def insert(self, alert: dict[str, Any]) -> None:
        """Insert one alert dict into the alerts table."""
        ev = alert.get("event", {})
        tags_str = ", ".join(alert.get("tags", []))
        self._con.execute(
            _INSERT,
            [
                alert.get("alert_no"),
                alert.get("rule_id"),
                alert.get("rule_name"),
                alert.get("severity"),
                alert.get("description"),
                tags_str,
                alert.get("fired_at"),
                ev.get("serial"),
                ev.get("timestamp"),
                ev.get("pid"),
                ev.get("uid"),
                ev.get("exe"),
                ev.get("comm"),
                ev.get("cmd"),
                ev.get("cwd"),
            ],
        )

    def recent(
        self,
        limit: int = 20,
        severity: str | None = None,
    ) -> list[dict]:
        """Return the most recent alerts as a list of dicts."""
        where = ""
        params: list[Any] = []
        if severity:
            where = "WHERE severity = ?"
            params.append(severity.upper())
        rows = self._con.execute(
            f"""
            SELECT id, alert_no, rule_id, rule_name, severity, fired_at,
                   event_pid, event_uid, event_exe, event_cmd
            FROM alerts
            {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()
        cols = [
            "id", "alert_no", "rule_id", "rule_name", "severity", "fired_at",
            "event_pid", "event_uid", "event_exe", "event_cmd",
        ]
        return [dict(zip(cols, row)) for row in rows]

    def stats(self) -> dict[str, Any]:
        """Return aggregate stats (total, per-severity counts, top rules)."""
        total = self._con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_sev = self._con.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC"
        ).fetchall()
        top_rules = self._con.execute(
            """
            SELECT rule_id, rule_name, COUNT(*) AS cnt
            FROM alerts
            GROUP BY rule_id, rule_name
            ORDER BY cnt DESC
            LIMIT 10
            """
        ).fetchall()
        return {
            "total": total,
            "by_severity": {row[0]: row[1] for row in by_sev},
            "top_rules": [
                {"rule_id": r[0], "rule_name": r[1], "count": r[2]} for r in top_rules
            ],
        }

    def count(self, severity: str | None = None) -> int:
        """Return total alert count, optionally filtered by severity."""
        if severity:
            return self._con.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = ?",
                [severity.upper()],
            ).fetchone()[0]
        return self._con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def close(self) -> None:
        self._con.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        self._con.execute(_DDL)
        logger.info("DuckDB schema ready at %s", self._path)
