"""
modules
=======

Rebuilt business logic for the tool's five capabilities, sitting on top
of Phase 2's adapters and returning Phase 1's typed models. Distinct from
the legacy flat `modules/` package at the repo root, which stays in place
and keeps working until Phase 4's exit criterion passes (plan.md
Section 7, "Migration approach").

`log_analyzer.py` exposes one function taking an injected "log source"
dependency, instead of the legacy `analyze_logs` / `analyze_logs_from_ssh`
split (plan.md Section 0.1, item 8; Phase-3).

Populated in Phase 3. Empty in Phase 0.
"""

from security_orchestrator.modules.fuzzer import FuzzerModule, select_nuclei_tags
from security_orchestrator.modules.log_analyzer import (
    FileLogReader,
    LogModule,
    SshLogReader,
)
from security_orchestrator.modules.privesc import PrivescModule
from security_orchestrator.modules.recon import ReconModule

__all__ = [
    "ReconModule",
    "FuzzerModule",
    "select_nuclei_tags",
    "PrivescModule",
    "LogModule",
    "FileLogReader",
    "SshLogReader",
]
