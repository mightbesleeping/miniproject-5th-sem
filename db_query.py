"""
db_query.py — Terminal query tool for the DuckDB alert store.

Sub-commands:
    recent   Show the most recent N alerts in table or JSON format
    stats    Aggregate statistics + top rules
    count    Total alert count

Examples:
    uv run python db_query.py recent
    uv run python db_query.py recent --limit 50 --severity CRITICAL --json
    uv run python db_query.py stats
    uv run python db_query.py count
    uv run python db_query.py count --severity HIGH
"""
from __future__ import annotations

import argparse
import json
import sys

from edr.db import AlertStore
from edr.utils import load_config


def _tabulate(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("(no results)")
        return
    # Compute column widths
    widths = {c: len(c) for c in cols}
    for row in rows:
        for c in cols:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))

    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for row in rows:
        print(" | ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols))


def cmd_recent(store: AlertStore, args: argparse.Namespace) -> None:
    rows = store.recent(limit=args.limit, severity=args.severity)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
    else:
        cols = ["id", "alert_no", "rule_id", "rule_name", "severity",
                "fired_at", "event_pid", "event_uid", "event_exe"]
        _tabulate(rows, cols)


def cmd_stats(store: AlertStore, _args: argparse.Namespace) -> None:
    s = store.stats()
    print(f"\nTotal alerts : {s['total']}")
    print("\nBy severity:")
    for sev, cnt in s["by_severity"].items():
        print(f"  {sev:10s} {cnt}")
    print("\nTop rules:")
    for rule in s["top_rules"]:
        print(f"  [{rule['rule_id']}] {rule['rule_name']:40s} {rule['count']}")


def cmd_count(store: AlertStore, args: argparse.Namespace) -> None:
    n = store.count(severity=args.severity)
    label = f"(severity={args.severity})" if args.severity else ""
    print(f"Alert count {label}: {n}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="db_query",
        description="Query the EDR DuckDB alert store",
    )
    p.add_argument("--config", default="config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    # recent
    r = sub.add_parser("recent", help="Show recent alerts")
    r.add_argument("--limit", type=int, default=20)
    r.add_argument("--severity", help="Filter by severity (e.g. HIGH)")
    r.add_argument("--json", action="store_true", help="Output as JSON")

    # stats
    sub.add_parser("stats", help="Aggregate statistics")

    # count
    c = sub.add_parser("count", help="Total alert count")
    c.add_argument("--severity", help="Filter by severity")

    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(args.config)
    db_cfg = cfg["edr"]["db"]

    if not db_cfg.get("enabled", True):
        print("DuckDB is disabled in config.", file=sys.stderr)
        sys.exit(1)

    with AlertStore(db_cfg.get("path", "data/edr_alerts.duckdb")) as store:
        {"recent": cmd_recent, "stats": cmd_stats, "count": cmd_count}[args.cmd](
            store, args
        )


if __name__ == "__main__":
    main()
