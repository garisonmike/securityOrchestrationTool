"""
modules.log_analyzer
====================

Blue-team log correlation. The engine takes a *log reader* - any object with
``read(path) -> Result[str]`` - as an injected dependency, instead of reaching
into a live paramiko session directly. This is the structural fix for bug #7
(plan.md Section 0 item 7): the correlation logic no longer depends on the
privesc module having established SSH. Two readers ship:

  * :class:`FileLogReader` - reads a local file (no SSH, ever). This is the
    path that lets ``--log-source <path>`` run log correlation standalone
    (Phase 4 product decision).
  * :class:`SshLogReader` - cats a remote file over an existing SSH session
    handed in by the orchestrator.

Both feed the *same* :meth:`LogModule.analyze`, which normalizes everything
into one ``LogFindings.source`` field (bug #8 - no more log_file/target
split).
"""

from __future__ import annotations

import os
import re
from typing import Callable, List, Optional

from security_orchestrator.adapters.ssh import DEFAULT_REMOTE_LOG_PATHS
from security_orchestrator.core.models import (
    AnalyzedLog,
    LogFindings,
    LogMatch,
    ModuleStatus,
)
from security_orchestrator.core.result import Result

_SIGNATURES = {
    "nmap": re.compile(r"(?i)nmap\b"),
    "nuclei": re.compile(r"(?i)nuclei"),
    "polyglot": re.compile(
        r"(?i)(SLEEP\(\d+\)|<script>|<svg/onload|NCI_HACKATHON|UNION\s+SELECT|OR\s+1=1|/etc/passwd)"
    ),
}


class FileLogReader:
    """Reads a local log file. Injectable ``exists``/``opener`` for tests."""

    def __init__(
        self,
        exists: Callable[[str], bool] = os.path.exists,
        isfile: Callable[[str], bool] = os.path.isfile,
        opener: Callable = open,
    ) -> None:
        self._exists = exists
        self._isfile = isfile
        self._opener = opener

    def read(self, path: str) -> Result[str]:
        if not path or not self._exists(path):
            return Result.err(f"Log file not found at: {path}")
        if not self._isfile(path):
            return Result.err(f"Path is not a regular file: {path}")
        try:
            with self._opener(path, "r", encoding="utf-8", errors="replace") as handle:
                return Result.ok(handle.read())
        except PermissionError:
            return Result.err(f"Permission denied reading {path}. Try elevated privileges.")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"Error reading {path}: {exc}")


class SshLogReader:
    """Cats a remote log file over an existing SSH session."""

    def __init__(self, session) -> None:
        self._session = session

    def read(self, path: str) -> Result[str]:
        out = self._session.exec(f"cat {path}")
        if out.is_err:
            return Result.err(f"{path}: {out.error}")
        command = out.value
        stderr = command.stderr or ""
        if "No such file" in stderr or "Permission denied" in stderr:
            return Result.err(f"{path}: {stderr.strip()}")
        if not command.stdout:
            return Result.err(f"{path}: File is empty or unreadable")
        return Result.ok(command.stdout)


class LogModule:
    def analyze(self, reader, source: str, paths: List[str]) -> LogFindings:
        findings = LogFindings(status=ModuleStatus.SUCCESS, source=source)

        for path in paths:
            content = reader.read(path)
            if content.is_err:
                findings.errors.append(content.error)
                continue

            lines = content.value.splitlines()
            if not lines:
                findings.errors.append(f"{path}: File is empty or unreadable")
                continue

            matched = 0
            for line_num, raw_line in enumerate(lines, start=1):
                findings.total_lines_analyzed += 1
                line = raw_line.strip()
                for kind, pattern in _SIGNATURES.items():
                    if pattern.search(line):
                        bucket = getattr(findings.matches, kind)
                        bucket.append(LogMatch(file=path, line=line_num, content=line))
                        findings.detection_score += 1
                        matched += 1
            findings.logs_analyzed.append(AnalyzedLog(path=path, lines=len(lines), matches=matched))

        if not findings.logs_analyzed:
            findings.status = ModuleStatus.ERROR
            findings.errors.append("No logs could be analyzed")
        return findings

    def analyze_local_file(self, path: str, reader: Optional[FileLogReader] = None) -> LogFindings:
        reader = reader or FileLogReader()
        return self.analyze(reader, source=path, paths=[path])

    def analyze_remote(
        self,
        session,
        host: str,
        paths: Optional[List[str]] = None,
    ) -> LogFindings:
        reader = SshLogReader(session)
        return self.analyze(reader, source=host, paths=paths or list(DEFAULT_REMOTE_LOG_PATHS))
