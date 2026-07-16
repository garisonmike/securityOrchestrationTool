"""
adapters.nuclei
===============

Runs nuclei with JSONL output and parses each line into a finding dict.
Injectable ``runner`` / ``which``. The adapter is deliberately mechanical:
it takes the tags/severity/cookie the module already decided on and returns
the parsed findings (or an error). Tag *selection* is module logic and is
tested there, not here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from security_orchestrator.core.result import Result

_TIMEOUT_SECONDS = 600


@dataclass
class NucleiScan:
    findings: List[Dict] = field(default_factory=list)
    raw_output: str = ""


class NucleiAdapter:
    def __init__(
        self,
        runner: Callable = subprocess.run,
        which: Callable[[str], Optional[str]] = shutil.which,
    ) -> None:
        self._runner = runner
        self._which = which

    def scan(
        self,
        url: str,
        tags: Optional[List[str]] = None,
        severity: str = "critical,high",
        cookie: Optional[str] = None,
        templates_path: Optional[str] = None,
    ) -> Result[NucleiScan]:
        if self._which("nuclei") is None:
            return Result.err("nuclei not found in PATH")

        cmd = ["nuclei", "-u", url, "-jsonl", "-silent"]
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if severity:
            cmd.extend(["-severity", severity])
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
        if templates_path:
            cmd.extend(["-t", templates_path])

        try:
            proc = self._runner(cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return Result.err(f"nuclei scan timed out after {_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"nuclei execution failed: {type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return Result.err(f"nuclei exited {proc.returncode}: {detail}")

        output = proc.stdout or ""
        findings: List[Dict] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                # A non-JSON line is tolerated (banner leakage etc.); the
                # scan as a whole is still a success.
                continue
        return Result.ok(NucleiScan(findings=findings, raw_output=output))
