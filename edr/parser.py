"""
edr/parser.py — Raw auditd line parser and multi-record assembler.

Auditd emits several record types per event, linked by the same serial number
(the number in parentheses after the timestamp).  This module:

  1. Parses a raw audit line into a {type, serial, fields} dict.
  2. Uses EventAssembler to merge SYSCALL + EXECVE + PATH records with the same
     serial number into a single unified event dict.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

# Matches:   type=SYSCALL msg=audit(1234567890.123:456): key=val ...
_AUDIT_LINE_RE = re.compile(
    r"^type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)"
)

# Matches:   key=val  or  key="val with spaces"
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

# Record types we care about
_INTERESTING = {"SYSCALL", "EXECVE", "PATH", "CWD", "PROCTITLE"}


def parse_line(line: str) -> dict[str, Any] | None:
    """
    Parse one raw audit log line.

    Returns a dict:
      {type, serial, timestamp, fields: {k: v, ...}}
    or None if the line doesn't match the audit format.
    """
    m = _AUDIT_LINE_RE.match(line)
    if not m:
        return None
    rec_type, ts, serial, rest = m.groups()
    if rec_type not in _INTERESTING:
        return None

    fields: dict[str, str] = {}
    for km in _KV_RE.finditer(rest):
        key = km.group(1)
        val = km.group(2) if km.group(2) is not None else km.group(3)
        fields[key] = val

    return {
        "type": rec_type,
        "serial": serial,
        "timestamp": ts,
        "fields": fields,
    }


class EventAssembler:
    """
    Accumulates records sharing the same serial number and emits a unified
    event dict when the SYSCALL record's EOE (end-of-event) marker is seen,
    or when a new serial is encountered (heuristic flush).

    In practice auditd groups records tightly, so a simple dict-keyed buffer
    works well.
    """

    def __init__(self) -> None:
        # serial → list of parsed records
        self._buf: dict[str, list[dict]] = defaultdict(list)

    def feed(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """
        Feed one parsed record.  Returns a merged event if the group is
        complete, otherwise None.
        """
        serial = record["serial"]
        self._buf[serial].append(record)

        # We emit as soon as we have a SYSCALL record (EXECVE / PATH follow
        # within the same kernel event and will arrive very quickly, but for
        # simplicity we flush on the second record of a different serial).
        if record["type"] == "SYSCALL":
            # Don't flush yet — wait for the rest of the group.
            # The heuristic: flush the *previous* serial when a new one shows up.
            # (handled by the caller via flush_serial / flush_all)
            return None

        # If we receive any record type after SYSCALL for the same serial,
        # hold it.  The engine will call flush_serial() explicitly.
        return None

    def flush_serial(self, serial: str) -> dict[str, Any] | None:
        """Merge and return all records for *serial*, then clear the buffer."""
        records = self._buf.pop(serial, [])
        return _merge(records) if records else None

    def flush_all(self) -> list[dict[str, Any]]:
        """Flush every buffered serial.  Call at end-of-stream."""
        result = []
        for serial in list(self._buf.keys()):
            merged = self.flush_serial(serial)
            if merged:
                result.append(merged)
        return result

    def pending_serials(self) -> list[str]:
        return list(self._buf.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _merge(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge a group of records into a single event dict."""
    # Sort so SYSCALL comes first
    order = {"SYSCALL": 0, "EXECVE": 1, "CWD": 2, "PATH": 3, "PROCTITLE": 4}
    records.sort(key=lambda r: order.get(r["type"], 9))

    base = records[0]
    event: dict[str, Any] = {
        "serial": base["serial"],
        "timestamp": base["timestamp"],
        "type": base["type"],
    }

    # Merge all field dicts (later records override earlier ones on collision)
    merged_fields: dict[str, str] = {}
    execve_args: list[str] = []

    for rec in records:
        if rec["type"] == "EXECVE":
            # Collect a0, a1, a2, … in order
            idx = 0
            while f"a{idx}" in rec["fields"]:
                execve_args.append(rec["fields"][f"a{idx}"])
                idx += 1
        else:
            merged_fields.update(rec["fields"])

    event["fields"] = merged_fields
    if execve_args:
        event["argv"] = execve_args

    return event
