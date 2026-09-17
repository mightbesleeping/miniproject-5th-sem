"""
main.py — CLI entry point for the EDR engine.

Usage:
    uv run python main.py                         # live mode (requires root)
    uv run python main.py --replay <file>         # replay a saved audit log
    uv run python main.py --min-severity HIGH     # raise alert threshold
    uv run python main.py --no-color              # plain output
    uv run python main.py --log-level DEBUG       # verbose internal logging
"""
from __future__ import annotations

import argparse
import logging
import sys

from edr.alerter import Alerter
from edr.collector import LogCollector
from edr.db import AlertStore
from edr.decoder import decode_event
from edr.engine import ThreatEngine
from edr.parser import EventAssembler, parse_line
from edr.utils import load_config, setup_logging, severity_gte

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="edr",
        description="Automated Endpoint Threat Detection Engine",
    )
    p.add_argument("--config", metavar="FILE", default="config.yaml",
                   help="Path to config YAML (default: config.yaml)")
    p.add_argument("--replay", metavar="LOG_FILE",
                   help="Replay a historical audit log file instead of live tailing")
    p.add_argument("--min-severity",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Minimum severity to display/store (overrides config)")
    p.add_argument("--rules-dir", metavar="DIR",
                   help="Override rules directory from config")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output")
    p.add_argument("--log-level",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   default="WARNING",
                   help="Internal logging verbosity (default: WARNING)")
    return p


def run(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    cfg = load_config(args.config)
    edr_cfg = cfg["edr"]
    db_cfg = edr_cfg["db"]

    # CLI flags override config
    min_sev = (args.min_severity or edr_cfg.get("min_severity", "LOW")).upper()
    rules_dir = args.rules_dir or edr_cfg.get("rules_dir", "rules")
    use_color = not args.no_color

    # DuckDB setup
    db_store = None
    if db_cfg.get("enabled", True):
        try:
            db_store = AlertStore(db_cfg.get("path", "data/edr_alerts.duckdb"))
            logger.info("DuckDB connected: %s", db_cfg.get("path"))
        except Exception as exc:  # noqa: BLE001
            logger.error("DuckDB init failed — running without persistence: %s", exc)

    alerter = Alerter(
        alert_log=edr_cfg.get("alert_log", "logs/alerts.jsonl"),
        use_color=use_color,
        db_store=db_store,
    )
    engine = ThreatEngine(rules_dir=rules_dir)
    assembler = EventAssembler()
    collector = LogCollector(edr_cfg.get("audit_log", "/var/log/audit/audit.log"))

    try:
        _process_stream(
            stream=collector.replay(args.replay) if args.replay else collector.tail(),
            assembler=assembler,
            engine=engine,
            alerter=alerter,
            min_sev=min_sev,
        )
    except KeyboardInterrupt:
        pass
    finally:
        # Flush any remaining buffered events
        for event in assembler.flush_all():
            decode_event(event)
            _check_and_alert(event, engine, alerter, min_sev)
        if db_store:
            db_store.close()


def _process_stream(stream, assembler, engine, alerter, min_sev: str) -> None:
    """
    Core processing loop: parse → assemble → decode → match → alert.

    We flush older serials whenever a new serial arrives to ensure we don't
    hold records in the assembler buffer forever.
    """
    prev_serial: str | None = None

    for raw_line in stream:
        record = parse_line(raw_line)
        if not record:
            continue

        serial = record["serial"]

        # Heuristic: flush the previous serial when we see a new one
        if prev_serial and serial != prev_serial:
            event = assembler.flush_serial(prev_serial)
            if event:
                decode_event(event)
                _check_and_alert(event, engine, alerter, min_sev)

        assembler.feed(record)
        prev_serial = serial

    # End-of-stream flush
    if prev_serial:
        event = assembler.flush_serial(prev_serial)
        if event:
            decode_event(event)
            _check_and_alert(event, engine, alerter, min_sev)


def _check_and_alert(event: dict, engine, alerter, min_sev: str) -> None:
    for rule in engine.evaluate(event):
        if severity_gte(rule.severity, min_sev):
            alerter.emit(rule, event)


if __name__ == "__main__":
    run()
