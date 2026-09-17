"""
edr/decoder.py — Hex-field decoding and command reconstruction.

auditd encodes many string fields as hex when they contain spaces or special
characters.  This module:
  - Detects hex-encoded strings (all hex digits, even length)
  - Decodes them to UTF-8 (with fallback)
  - Reconstructs the full command line from EXECVE argv
"""
from __future__ import annotations

import re
import shlex

_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def is_hex(value: str) -> bool:
    """Return True if *value* looks like a hex-encoded auditd field."""
    return bool(value) and len(value) % 2 == 0 and bool(_HEX_RE.match(value))


def decode_field(value: str) -> str:
    """Decode a potentially hex-encoded auditd field value."""
    if is_hex(value):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            pass
    # Strip surrounding parentheses auditd sometimes adds
    if value.startswith("(") and value.endswith(")"):
        return value[1:-1]
    return value


def decode_event(event: dict) -> dict:
    """
    Decode all hex fields in *event["fields"]* and reconstruct the command
    line from *event["argv"]* (EXECVE args).

    Modifies and returns the same dict.
    """
    fields = event.get("fields", {})

    # Decode known string fields that auditd commonly hex-encodes
    for key in ("exe", "comm", "cwd", "key", "name", "proctitle"):
        if key in fields:
            fields[key] = decode_field(fields[key])

    # Decode argv args (from EXECVE records)
    argv = event.get("argv", [])
    decoded_argv = [decode_field(a) for a in argv]
    event["argv"] = decoded_argv

    # Build a human-readable command string
    if decoded_argv:
        event["cmd"] = reconstruct_command(decoded_argv)
    elif "proctitle" in fields:
        # proctitle is NUL-separated args encoded as hex
        raw = fields["proctitle"]
        event["cmd"] = raw.replace("\x00", " ").strip()

    return event


def reconstruct_command(argv: list[str]) -> str:
    """Join argv into a shell-quoted command string."""
    return " ".join(shlex.quote(a) for a in argv)
