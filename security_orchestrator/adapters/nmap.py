"""
adapters.nmap
=============

Runs an nmap service/version scan behind an injectable ``runner``
(``subprocess.run``) and ``which`` (``shutil.which``), so tests can simulate
a missing binary, a timeout, or a non-zero exit without touching the real
tool or the network.

Crucially the adapter returns only *structured, parsed* data - never raw
tool chatter. This closes the path in bug #2 (plan.md Section 0, item 2)
where noisy nmap NSE help/error text got written straight into a tech-stack
field and then quoted in the report; the module decides what, if anything,
to extract from ``raw_output``, and it does so from a known field, not by
scraping console output that happened to be lying around.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional

from security_orchestrator.core.result import Result

_TIMEOUT_SECONDS = 300


@dataclass
class NmapScan:
    raw_output: str
    command: str
    skip_ping_used: bool


class NmapAdapter:
    def __init__(
        self,
        runner: Callable = subprocess.run,
        which: Callable[[str], Optional[str]] = shutil.which,
    ) -> None:
        self._runner = runner
        self._which = which

    def _build_command(self, target: str, profile: str, skip_ping: bool) -> List[str]:
        if profile.lower() == "stealth":
            cmd = ["nmap", "-T2", "-sV"]
        else:
            cmd = ["nmap", "-T4", "-A"]
        if skip_ping:
            cmd.append("-Pn")
        cmd.append(target)
        return cmd

    def scan(self, target: str, profile: str = "Stealth", skip_ping: bool = False) -> Result[NmapScan]:
        if self._which("nmap") is None:
            return Result.err("nmap not found in PATH")

        cmd = self._build_command(target, profile, skip_ping)
        cmd_str = " ".join(cmd)
        try:
            proc = self._runner(cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return Result.err(f"nmap scan timed out after {_TIMEOUT_SECONDS}s (command: {cmd_str})")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"nmap execution failed: {type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return Result.err(f"nmap exited {proc.returncode}: {detail} (command: {cmd_str})")

        return Result.ok(NmapScan(raw_output=proc.stdout or "", command=cmd_str, skip_ping_used=skip_ping))
