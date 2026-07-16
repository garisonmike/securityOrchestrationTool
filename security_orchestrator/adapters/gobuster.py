"""
adapters.gobuster
=================

Directory brute-force via gobuster. Injectable ``runner`` / ``which`` /
``exists`` (for the wordlist check) so the whole matrix - binary missing,
wordlist missing, timeout, non-zero exit, clean parse - is testable without
the tool or a real target.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from security_orchestrator.core.result import Result

_TIMEOUT_SECONDS = 300
_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


@dataclass
class GobusterScan:
    discovered_paths: List[str] = field(default_factory=list)
    raw_output: str = ""


class GobusterAdapter:
    def __init__(
        self,
        runner: Callable = subprocess.run,
        which: Callable[[str], Optional[str]] = shutil.which,
        exists: Callable[[str], bool] = os.path.exists,
    ) -> None:
        self._runner = runner
        self._which = which
        self._exists = exists

    def enumerate(self, url: str, wordlist: str = _DEFAULT_WORDLIST) -> Result[GobusterScan]:
        if self._which("gobuster") is None:
            return Result.err("gobuster not found in PATH")
        if not self._exists(wordlist):
            return Result.err(f"wordlist not found: {wordlist}")

        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-e"]
        try:
            proc = self._runner(cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return Result.err(f"gobuster scan timed out after {_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"gobuster execution failed: {type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return Result.err(f"gobuster exited {proc.returncode}: {detail}")

        output = proc.stdout or ""
        discovered = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and ("Status: 2" in line or "Status: 3" in line)
        ]
        return Result.ok(GobusterScan(discovered_paths=discovered, raw_output=output))
