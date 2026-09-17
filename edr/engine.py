"""
edr/engine.py — YAML rule loading and threat matching engine.

Rule schema (YAML list of dicts):

    - id: EDR-001
      name: Reverse Shell via Bash
      severity: CRITICAL       # INFO | LOW | MEDIUM | HIGH | CRITICAL
      description: >
        Detected a bash reverse shell attempt.
      tags: [reverse-shell, execution]
      match:
        process: "^bash$"        # regex on exe basename (optional)
        cmd_regex: "/dev/tcp"    # regex on full command (optional)
        args_regex: "pattern"    # regex on any individual arg (optional)
        uid: 0                   # exact integer UID (optional)
        not_process: "^safe$"    # exclude if exe basename matches (optional)
        any_of:                  # OR block — any sub-matcher must match (optional)
          - cmd_regex: "pat_a"
          - args_regex: "pat_b"
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class Rule:
    """A compiled detection rule."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.name: str = raw["name"]
        self.severity: str = raw.get("severity", "MEDIUM").upper()
        self.description: str = raw.get("description", "")
        self.tags: list[str] = raw.get("tags", [])
        self._match = raw.get("match", {})
        self._compiled = self._compile(self._match)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def matches(self, event: dict[str, Any]) -> bool:
        return self._eval(self._compiled, event)

    def _eval(self, compiled: dict, event: dict) -> bool:
        fields = event.get("fields", {})
        exe = os.path.basename(fields.get("exe", ""))
        cmd = event.get("cmd", "")
        argv = event.get("argv", [])
        uid_str = fields.get("uid", "")

        # process (exe basename regex)
        if "process" in compiled:
            if not compiled["process"].search(exe):
                return False

        # not_process (exclude)
        if "not_process" in compiled:
            if compiled["not_process"].search(exe):
                return False

        # cmd_regex (full command)
        if "cmd_regex" in compiled:
            if not compiled["cmd_regex"].search(cmd):
                return False

        # args_regex (any individual arg)
        if "args_regex" in compiled:
            if not any(compiled["args_regex"].search(a) for a in argv):
                return False

        # uid (exact match)
        if "uid" in compiled:
            try:
                if int(uid_str) != compiled["uid"]:
                    return False
            except (ValueError, TypeError):
                return False

        # any_of (OR block)
        if "any_of" in compiled:
            if not any(self._eval(sub, event) for sub in compiled["any_of"]):
                return False

        return True

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    @staticmethod
    def _compile(match: dict) -> dict:
        compiled: dict[str, Any] = {}
        for key in ("process", "not_process", "cmd_regex", "args_regex"):
            if key in match:
                compiled[key] = re.compile(match[key])
        if "uid" in match:
            compiled["uid"] = int(match["uid"])
        if "any_of" in match:
            compiled["any_of"] = [Rule._compile(sub) for sub in match["any_of"]]
        return compiled

    def __repr__(self) -> str:
        return f"<Rule {self.id} [{self.severity}]>"


class ThreatEngine:
    """Loads rules from YAML files and evaluates events against them."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        self.load_rules()

    def load_rules(self) -> None:
        """(Re)load all *.yaml files from rules_dir."""
        self.rules = []
        if not self.rules_dir.is_dir():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return

        for path in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(path) as fh:
                    raw_rules = yaml.safe_load(fh) or []
                for raw in raw_rules:
                    self.rules.append(Rule(raw))
                logger.debug("Loaded %d rules from %s", len(raw_rules), path.name)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to load rules from %s: %s", path, exc)

        logger.info("Total rules loaded: %d", len(self.rules))

    def evaluate(self, event: dict[str, Any]) -> list[Rule]:
        """Return all rules that match *event*."""
        return [r for r in self.rules if r.matches(event)]
