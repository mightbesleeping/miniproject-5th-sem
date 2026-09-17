"""
edr/collector.py — Auditd log tail with rotation detection, plus replay mode.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Generator


class LogCollector:
    """
    Yields raw audit log lines from either:
      - live tail of *log_path* (with rotation detection)
      - one-shot replay of a file
    """

    POLL_INTERVAL = 0.1  # seconds between EOF polls

    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def tail(self) -> Generator[str, None, None]:
        """Continuously tail the audit log, handling log rotation."""
        fh = self._open()
        inode = self._inode(fh)

        while True:
            line = fh.readline()
            if line:
                yield line.rstrip("\n")
                continue

            # EOF — check for rotation
            time.sleep(self.POLL_INTERVAL)
            current_inode = self._current_inode()
            if current_inode and current_inode != inode:
                fh.close()
                fh = self._open()
                inode = self._inode(fh)

    def replay(self, path: str | None = None) -> Generator[str, None, None]:
        """Replay all lines from *path* (or the configured log) and return."""
        target = Path(path) if path else self.log_path
        with open(target) as fh:
            for line in fh:
                yield line.rstrip("\n")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _open(self):  # noqa: ANN202
        """Open the log file and seek to end."""
        fh = open(self.log_path)  # noqa: SIM115
        fh.seek(0, 2)  # seek to EOF
        return fh

    @staticmethod
    def _inode(fh) -> int:  # noqa: ANN001
        return os.fstat(fh.fileno()).st_ino

    def _current_inode(self) -> int | None:
        try:
            return self.log_path.stat().st_ino
        except FileNotFoundError:
            return None
