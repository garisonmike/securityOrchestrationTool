"""
adapters.searchsploit
=====================

Queries searchsploit in ``--json`` mode and returns the raw exploit records.
Injectable ``runner`` / ``which``. Recency/verification/dedup *filtering* is
module logic (recon), tested there against fixed records; the adapter just
runs the tool and parses its JSON.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Callable, Dict, List, Optional

from security_orchestrator.core.result import Result

_TIMEOUT_SECONDS = 30


class SearchsploitAdapter:
    def __init__(
        self,
        runner: Callable = subprocess.run,
        which: Callable[[str], Optional[str]] = shutil.which,
    ) -> None:
        self._runner = runner
        self._which = which

    def search(self, query: str) -> Result[List[Dict]]:
        if self._which("searchsploit") is None:
            return Result.err("searchsploit not found in PATH")

        cmd = ["searchsploit", query, "--json"]
        try:
            proc = self._runner(cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return Result.err(f"searchsploit timed out after {_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"searchsploit execution failed: {type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return Result.err(f"searchsploit exited {proc.returncode}: {detail}")

        try:
            parsed = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return Result.err("searchsploit returned malformed JSON")

        return Result.ok(list(parsed.get("RESULTS_EXPLOIT", [])))
