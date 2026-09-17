"""
edr/utils.py — Configuration loading and shared helpers.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG: dict[str, Any] = {
    "edr": {
        "min_severity": "LOW",
        "audit_log": "/var/log/audit/audit.log",
        "rules_dir": "rules",
        "alert_log": "logs/alerts.jsonl",
        "db": {
            "enabled": True,
            "path": "data/edr_alerts.duckdb",
        },
    }
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    """Load YAML config, falling back to defaults for missing keys."""
    cfg = _deep_merge({}, _DEFAULT_CONFIG)
    config_path = Path(path)
    if config_path.exists():
        try:
            with open(config_path) as fh:
                user_cfg = yaml.safe_load(fh) or {}
            cfg = _deep_merge(cfg, user_cfg)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load config %s: %s — using defaults", path, exc)
    else:
        logger.info("Config file %s not found — using defaults", path)
    return cfg


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (mutates base)."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def setup_logging(level: str = "WARNING") -> None:
    """Configure root logger."""
    numeric = getattr(logging, level.upper(), logging.WARNING)
    logging.basicConfig(
        stream=sys.stderr,
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def severity_gte(sev: str, minimum: str) -> bool:
    """Return True if *sev* is >= *minimum* in the severity order."""
    sev = sev.upper()
    minimum = minimum.upper()
    try:
        return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


def ensure_dir(path: str | Path) -> Path:
    """Create parent directories for *path* (file) or *path* itself (dir)."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
