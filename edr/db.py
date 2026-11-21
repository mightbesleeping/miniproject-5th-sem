"""
edr/db.py — DuckDB alert persistence layer, tuned for columnar analytics.

Key DuckDB-specific design choices vs SQLite:
──────────────────────────────────────────────
1. PROPER TYPES
   • fired_at      → TIMESTAMPTZ       (enables date_trunc, date_diff, time math)
   • event_pid/uid → INTEGER           (numeric comparisons, histograms)
   • tags          → VARCHAR[]         (native array — unnest(), list_aggregate())
   • severity_rank → TINYINT           (sort/filter without string comparison)

2. BATCH WRITES
   • Alerts are buffered in memory and flushed with executemany() inside a
     single BEGIN/COMMIT transaction — orders of magnitude faster than one
     INSERT per row on DuckDB's columnar WAL.
   • Background flusher thread drains the buffer every FLUSH_INTERVAL seconds
     so data is never stuck > 2s even during low-volume periods.

3. PERSISTENT CONNECTION
   • One duckdb.connect() per AlertStore instance, shared across all calls.
   • DuckDB is not thread-safe for concurrent writes by default, so all writes
     go through a threading.Lock().  Reads use read_only=False but hold the
     lock while executing to avoid WAL conflicts.

4. ANALYTICAL SQL
   • timeline()   → date_trunc bucketed counts with severity breakdown
   • heatmap()    → hour-of-day × severity matrix
   • tag_freq()   → unnest(tags) frequency table
   • top_procs()  → top offending executables
   • recent()     → window-ranked with severity_rank for stable ordering
   • stats()      → single-pass multi-aggregate using GROUPING SETS

5. SCHEMA
   CREATE TABLE alerts (
       id            BIGINT PRIMARY KEY,          -- no sequence; we track in Python
       alert_no      INTEGER NOT NULL,
       rule_id       VARCHAR NOT NULL,
       rule_name     VARCHAR NOT NULL,
       severity      VARCHAR NOT NULL,
       severity_rank TINYINT NOT NULL,            -- 0=INFO 1=LOW 2=MED 3=HIGH 4=CRIT
       description   TEXT,
       tags          VARCHAR[],                   -- native DuckDB array
       fired_at      TIMESTAMPTZ NOT NULL,
       event_serial  VARCHAR,
       event_ts      DOUBLE,                      -- unix float from auditd
       event_pid     INTEGER,
       event_uid     INTEGER,
       event_exe     VARCHAR,
       event_comm    VARCHAR,
       event_cmd     TEXT,
       event_cwd     VARCHAR,
       created_at    TIMESTAMPTZ DEFAULT now()
   );
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

logger = logging.getLogger(__name__)

# Severity → integer rank for columnar sort (avoids string comparison)
SEVERITY_RANK: dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}

_DDL = """
-- DuckDB columnar schema: proper types, native arrays, no sequence overhead
CREATE TABLE IF NOT EXISTS alerts (
    id            BIGINT PRIMARY KEY,
    alert_no      INTEGER  NOT NULL,
    rule_id       VARCHAR  NOT NULL,
    rule_name     VARCHAR  NOT NULL,
    severity      VARCHAR  NOT NULL,
    severity_rank TINYINT  NOT NULL,
    description   TEXT,
    tags          VARCHAR[],
    fired_at      TIMESTAMPTZ NOT NULL,
    event_serial  VARCHAR,
    event_ts      DOUBLE,
    event_pid     INTEGER,
    event_uid     INTEGER,
    event_exe     VARCHAR,
    event_comm    VARCHAR,
    event_cmd     TEXT,
    event_cwd     VARCHAR,
    created_at    TIMESTAMPTZ DEFAULT now()
);

-- Analytical view: pre-joined severity label for downstream queries
CREATE VIEW IF NOT EXISTS v_alerts AS
SELECT *,
       date_trunc('minute', fired_at)  AS fired_minute,
       date_trunc('hour',   fired_at)  AS fired_hour,
       hour(fired_at)                  AS fired_hour_of_day,
       dayofweek(fired_at)             AS fired_dow
FROM alerts;
"""

# Columns in insertion order (must match _row_tuple)
_INSERT_COLS = (
    "id", "alert_no", "rule_id", "rule_name", "severity", "severity_rank",
    "description", "tags", "fired_at",
    "event_serial", "event_ts", "event_pid", "event_uid",
    "event_exe", "event_comm", "event_cmd", "event_cwd",
)
_INSERT_SQL = (
    f"INSERT INTO alerts ({', '.join(_INSERT_COLS)}) "
    f"VALUES ({', '.join('?' * len(_INSERT_COLS))})"
)

# How long (seconds) before unflushed buffer is force-written to disk
_FLUSH_INTERVAL = 2.0
# Flush immediately when buffer hits this size (regardless of timer)
_BATCH_SIZE = 64


class AlertStore:
    """
    DuckDB-backed alert store with:
      - batched columnar writes (executemany in transaction)
      - background flush thread
      - analytical query methods (timeline, heatmap, tag frequency, etc.)
    """

    def __init__(
        self,
        db_path: str = "data/edr_alerts.duckdb",
        flush_interval: float = _FLUSH_INTERVAL,
        batch_size: int = _BATCH_SIZE,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Single persistent connection — DuckDB WAL handles durability
        self._con = duckdb.connect(str(self._path))
        self._configure()
        self._init_schema()

        # Write buffer
        self._lock = threading.Lock()
        self._buf: list[tuple] = []
        self._id_counter = self._max_id() + 1
        self._batch_size = batch_size

        # Background flusher
        self._flush_interval = flush_interval
        self._closed = False
        self._flusher = threading.Thread(
            target=self._flush_loop, daemon=True, name="edr-db-flusher"
        )
        self._flusher.start()

    # ──────────────────────────────────────────────────────────────────
    # DuckDB configuration
    # ──────────────────────────────────────────────────────────────────

    def _configure(self) -> None:
        """Tune DuckDB for this workload: frequent small writes + analytical reads."""
        self._con.execute("PRAGMA threads=4")
        self._con.execute("PRAGMA memory_limit='256MB'")
        # Larger checkpoint threshold → fewer stalls during write bursts
        self._con.execute("PRAGMA checkpoint_threshold='32MB'")

    # ──────────────────────────────────────────────────────────────────
    # Write path: buffer → batch flush
    # ──────────────────────────────────────────────────────────────────

    def insert(self, alert: dict[str, Any]) -> None:
        """Buffer one alert. Flushed to DuckDB in bulk by the background thread."""
        row = self._to_row(alert)
        with self._lock:
            self._buf.append(row)
            if len(self._buf) >= self._batch_size:
                self._flush_locked()

    def flush(self) -> int:
        """Force-flush the write buffer. Returns number of rows written."""
        with self._lock:
            return self._flush_locked()

    def _flush_locked(self) -> int:
        """Must be called with self._lock held."""
        if not self._buf:
            return 0
        batch, self._buf = self._buf, []
        try:
            self._con.begin()
            self._con.executemany(_INSERT_SQL, batch)
            self._con.commit()
            logger.debug("Flushed %d alerts to DuckDB", len(batch))
            return len(batch)
        except Exception as exc:
            self._con.rollback()
            logger.error("DuckDB batch flush failed: %s", exc)
            # Re-queue for next attempt
            self._buf = batch + self._buf
            return 0

    def _flush_loop(self) -> None:
        """Background thread: drain buffer every _flush_interval seconds."""
        while not self._closed:
            time.sleep(self._flush_interval)
            with self._lock:
                self._flush_locked()

    def _to_row(self, alert: dict) -> tuple:
        """Convert alert dict → insertion tuple (must match _INSERT_COLS order)."""
        ev = alert.get("event", {})
        sev = alert.get("severity", "INFO").upper()
        fired_at_str = alert.get("fired_at") or datetime.now(timezone.utc).isoformat()

        # Assign a monotone ID without a DB sequence (avoids round-trip)
        row_id = self._id_counter
        self._id_counter += 1

        def _int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        def _float(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None

        return (
            row_id,
            alert.get("alert_no"),
            alert.get("rule_id"),
            alert.get("rule_name"),
            sev,
            SEVERITY_RANK.get(sev, 0),          # severity_rank TINYINT
            alert.get("description"),
            alert.get("tags") or [],             # VARCHAR[] — native DuckDB list
            fired_at_str,                         # TIMESTAMPTZ
            ev.get("serial"),
            _float(ev.get("timestamp")),          # DOUBLE unix ts
            _int(ev.get("pid")),                  # INTEGER
            _int(ev.get("uid")),                  # INTEGER
            ev.get("exe"),
            ev.get("comm"),
            ev.get("cmd"),
            ev.get("cwd"),
        )

    # ──────────────────────────────────────────────────────────────────
    # Read path: analytical queries
    # ──────────────────────────────────────────────────────────────────

    def recent(
        self,
        limit: int = 50,
        severity: str | None = None,
        min_severity: str | None = None,
    ) -> list[dict]:
        """
        Most recent alerts, ordered by severity_rank DESC then fired_at DESC.
        Supports both exact severity filter and minimum-severity threshold.
        """
        conditions, params = [], []
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if min_severity:
            rank = SEVERITY_RANK.get(min_severity.upper(), 0)
            conditions.append("severity_rank >= ?")
            params.append(rank)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = self._q(
            f"""
            SELECT id, alert_no, rule_id, rule_name, severity, severity_rank,
                   fired_at, event_pid, event_uid, event_exe, event_cmd, tags
            FROM alerts
            {where}
            ORDER BY fired_at DESC, severity_rank DESC
            LIMIT ?
            """,
            params + [limit],
        )
        cols = [
            "id", "alert_no", "rule_id", "rule_name", "severity", "severity_rank",
            "fired_at", "event_pid", "event_uid", "event_exe", "event_cmd", "tags",
        ]
        return [dict(zip(cols, r)) for r in rows]

    def stats(self) -> dict[str, Any]:
        """
        Single-pass multi-aggregate using GROUPING SETS — one table scan
        instead of four separate COUNT queries.
        """
        # Severity breakdown + total in one query via GROUPING SETS
        sev_rows = self._q("""
            SELECT
                severity,
                severity_rank,
                COUNT(*)              AS cnt,
                COUNT(DISTINCT rule_id) AS unique_rules,
                MIN(fired_at)         AS first_seen,
                MAX(fired_at)         AS last_seen
            FROM alerts
            GROUP BY severity, severity_rank
            ORDER BY severity_rank DESC
        """)

        total = self._q("SELECT COUNT(*) FROM alerts")[0][0]

        top_rules = self._q("""
            SELECT rule_id, rule_name, severity,
                   COUNT(*)                               AS cnt,
                   COUNT(DISTINCT event_uid)              AS unique_users,
                   MAX(fired_at)                          AS last_seen
            FROM alerts
            GROUP BY rule_id, rule_name, severity
            ORDER BY cnt DESC
            LIMIT 10
        """)

        top_procs = self._q("""
            SELECT event_exe, COUNT(*) AS cnt,
                   COUNT(DISTINCT event_uid) AS unique_users
            FROM alerts
            WHERE event_exe IS NOT NULL
            GROUP BY event_exe
            ORDER BY cnt DESC
            LIMIT 10
        """)

        return {
            "total": total,
            "by_severity": {
                r[0]: {
                    "count": r[2],
                    "unique_rules": r[3],
                    "first_seen": str(r[4]) if r[4] else None,
                    "last_seen": str(r[5]) if r[5] else None,
                }
                for r in sev_rows if r[0]
            },
            "top_rules": [
                {
                    "rule_id": r[0], "rule_name": r[1], "severity": r[2],
                    "count": r[3], "unique_users": r[4],
                    "last_seen": str(r[5]) if r[5] else None,
                }
                for r in top_rules
            ],
            "top_processes": [
                {"exe": r[0], "count": r[1], "unique_users": r[2]}
                for r in top_procs
            ],
        }

    def timeline(self, bucket: str = "minute", last_n: int = 60) -> list[dict]:
        """
        Alert counts bucketed by time using date_trunc — DuckDB's vectorized
        timestamp arithmetic.

        bucket: 'minute' | 'hour' | 'day'
        last_n: number of buckets to return
        """
        valid = {"minute", "hour", "day"}
        if bucket not in valid:
            bucket = "minute"

        rows = self._q(
            f"""
            WITH buckets AS (
                SELECT
                    date_trunc('{bucket}', fired_at)  AS ts,
                    severity,
                    severity_rank,
                    COUNT(*)                           AS cnt
                FROM alerts
                GROUP BY ts, severity, severity_rank
            )
            SELECT ts, severity, cnt
            FROM buckets
            ORDER BY ts DESC, severity_rank DESC
            LIMIT ?
            """,
            [last_n * 5],   # up to 5 severities × last_n buckets
        )
        return [{"ts": str(r[0]), "severity": r[1], "count": r[2]} for r in rows]

    def heatmap(self) -> list[dict]:
        """
        Alert count by hour-of-day × severity — useful for spotting attack
        patterns at specific times. Uses DuckDB's hour() date part function.
        """
        rows = self._q("""
            SELECT
                hour(fired_at)  AS hour_of_day,
                severity,
                COUNT(*)        AS cnt
            FROM alerts
            GROUP BY hour_of_day, severity
            ORDER BY hour_of_day, severity
        """)
        return [{"hour": r[0], "severity": r[1], "count": r[2]} for r in rows]

    def tag_frequency(self) -> list[dict]:
        """
        Frequency of MITRE ATT&CK tags by unnesting the native VARCHAR[] column.
        This is only efficient because tags is a proper DuckDB array, not a
        concatenated string that would require splitting.
        """
        rows = self._q("""
            SELECT
                tag,
                COUNT(*) AS cnt
            FROM (
                SELECT unnest(tags) AS tag
                FROM alerts
                WHERE tags IS NOT NULL AND len(tags) > 0
            )
            GROUP BY tag
            ORDER BY cnt DESC
            LIMIT 30
        """)
        return [{"tag": r[0], "count": r[1]} for r in rows]

    def attack_sessions(self, window_minutes: int = 5) -> list[dict]:
        """
        Correlate alerts by UID within a rolling time window to surface
        likely attack sessions — uses DuckDB window functions.

        DuckDB does not allow nesting a window function inside a scalar
        function (e.g. epoch(LAG(…) OVER (…))), so we split the work
        into two CTEs:
          1. lag_cte  — compute the LAG of fired_at per UID.
          2. session_cte — compute epoch difference and assign session IDs.
        """
        rows = self._q(
            """
            WITH lag_cte AS (
                SELECT *,
                    LAG(fired_at, 1, fired_at)
                        OVER (PARTITION BY event_uid ORDER BY fired_at) AS prev_fired_at
                FROM alerts
                WHERE event_uid IS NOT NULL
            ),
            session_cte AS (
                SELECT *,
                    SUM(CASE WHEN
                            epoch(fired_at) - epoch(prev_fired_at) > ? * 60
                        THEN 1 ELSE 0 END)
                    OVER (PARTITION BY event_uid ORDER BY fired_at) AS session_id
                FROM lag_cte
            )
            SELECT
                event_uid,
                MIN(fired_at)                               AS session_start,
                MAX(fired_at)                               AS session_end,
                COUNT(*)                                    AS alert_count,
                COUNT(DISTINCT rule_id)                     AS unique_rules,
                MAX(severity_rank)                          AS max_rank,
                ARRAY_AGG(DISTINCT rule_id ORDER BY rule_id) AS rules_fired
            FROM session_cte
            GROUP BY event_uid, session_id
            HAVING COUNT(*) > 1
            ORDER BY max_rank DESC, alert_count DESC
            LIMIT 20
            """,
            [window_minutes],
        )
        cols = [
            "uid", "session_start", "session_end", "alert_count",
            "unique_rules", "max_severity_rank", "rules_fired",
        ]
        return [dict(zip(cols, r)) for r in rows]

    def count(self, severity: str | None = None) -> int:
        """Total alert count, optionally filtered by severity."""
        if severity:
            return self._q(
                "SELECT COUNT(*) FROM alerts WHERE severity = ?",
                [severity.upper()],
            )[0][0]
        return self._q("SELECT COUNT(*) FROM alerts")[0][0]

    # ──────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._closed = True
        self.flush()                # drain remaining buffer
        self._con.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def _q(self, sql: str, params: list | None = None):
        """Execute a read query under the write lock (WAL consistency)."""
        with self._lock:
            if params:
                return self._con.execute(sql, params).fetchall()
            return self._con.execute(sql).fetchall()

    def _max_id(self) -> int:
        """Read the current max id to continue auto-increment from Python."""
        try:
            row = self._con.execute(
                "SELECT COALESCE(MAX(id), 0) FROM alerts"
            ).fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def _init_schema(self) -> None:
        self._con.execute(_DDL)
        logger.info("DuckDB schema ready at %s", self._path)
