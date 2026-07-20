"""
adapters.fakes
==============

Fake counterparts of every real adapter, used only by tests. They share the
real adapters' public method signatures and return ``Result`` values from
canned data, so a module test drives the full logic path without opening a
socket or spawning a subprocess (plan.md Phase-2 exit criterion). None of
these touch the network, the filesystem, or paramiko.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from security_orchestrator.adapters.gobuster import GobusterScan
from security_orchestrator.adapters.http import HttpResponse
from security_orchestrator.adapters.nmap import NmapScan
from security_orchestrator.adapters.nuclei import NucleiScan
from security_orchestrator.adapters.ssh import (
    CommandOutput,
    SshConnectResult,
    SshOutcome,
    SshSession,
)
from security_orchestrator.core.result import Result


class FakeHttpAdapter:
    """Serves canned HTTP responses.

    Provide either ``handler(url, headers, allow_redirects) -> Result`` for
    full control, or a ``responses`` dict keyed by exact URL (values may be
    an ``HttpResponse`` - auto-wrapped in ``Result.ok`` - or a ``Result``).
    Unmatched URLs return ``default``.
    """

    def __init__(
        self,
        responses: Optional[Dict[str, object]] = None,
        default: Optional[Result] = None,
        handler: Optional[Callable] = None,
    ) -> None:
        self._responses = responses or {}
        self._default = default or Result.err("no canned response")
        self._handler = handler
        self.calls: List[dict] = []

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: float = 5.0,
        verify: bool = False,
    ) -> Result[HttpResponse]:
        self.calls.append({"url": url, "headers": headers, "allow_redirects": allow_redirects})
        if self._handler is not None:
            return self._handler(url, headers, allow_redirects)
        if url in self._responses:
            val = self._responses[url]
            return val if isinstance(val, Result) else Result.ok(val)
        return self._default


class FakeNmapAdapter:
    def __init__(self, result: Optional[Result[NmapScan]] = None) -> None:
        self._result = result or Result.err("nmap not found in PATH")
        self.calls: List[dict] = []

    def scan(self, target: str, profile: str = "Stealth", skip_ping: bool = False) -> Result[NmapScan]:
        self.calls.append({"target": target, "profile": profile, "skip_ping": skip_ping})
        return self._result


class FakeGobusterAdapter:
    def __init__(self, result: Optional[Result[GobusterScan]] = None) -> None:
        self._result = result or Result.err("gobuster not found in PATH")
        self.calls: List[dict] = []

    def enumerate(self, url: str, wordlist: str = "") -> Result[GobusterScan]:
        self.calls.append({"url": url, "wordlist": wordlist})
        return self._result


class FakeNucleiAdapter:
    def __init__(self, result: Optional[Result[NucleiScan]] = None) -> None:
        self._result = result or Result.err("nuclei not found in PATH")
        self.calls: List[dict] = []

    def scan(
        self,
        url: str,
        tags: Optional[List[str]] = None,
        severity: str = "critical,high",
        cookie: Optional[str] = None,
        templates_path: Optional[str] = None,
    ) -> Result[NucleiScan]:
        self.calls.append({"url": url, "tags": tags, "severity": severity, "cookie": cookie})
        return self._result


class FakeSearchsploitAdapter:
    def __init__(
        self,
        results_by_query: Optional[Dict[str, List[Dict]]] = None,
        default: Optional[Result] = None,
    ) -> None:
        self._by_query = results_by_query or {}
        self._default = default or Result.ok([])
        self.calls: List[str] = []

    def search(self, query: str) -> Result[List[Dict]]:
        self.calls.append(query)
        if query in self._by_query:
            return Result.ok(self._by_query[query])
        return self._default


class FakeWkhtmltopdfAdapter:
    def __init__(self, result: Optional[Result[str]] = None) -> None:
        self._result = result or Result.err("wkhtmltopdf not found in PATH")
        self.calls: List[dict] = []

    def convert(self, html_path: str, pdf_path: str) -> Result[str]:
        self.calls.append({"html_path": html_path, "pdf_path": pdf_path})
        return self._result


class FakeSshSession(SshSession):
    """A session that returns canned command output by substring match."""

    def __init__(self, command_outputs: Optional[Dict[str, CommandOutput]] = None) -> None:
        self._outputs = command_outputs or {}
        self.closed = False
        self.commands_run: List[str] = []

    def exec(self, command: str, timeout: int = 15) -> Result[CommandOutput]:
        self.commands_run.append(command)
        for needle, output in self._outputs.items():
            if needle in command:
                return Result.ok(output)
        return Result.ok(CommandOutput(command=command, stdout="", exit_status=0))

    def close(self) -> None:
        self.closed = True


class FakeSshAdapter:
    """Simulates SSH port checks and connection outcomes deterministically.

    - ``port_open`` drives :meth:`check_port` (or set ``port_error`` to make
      it return ``Result.err``).
    - ``valid_credentials`` is a set of ``(username, password)`` tuples that
      yield ``SUCCESS`` (with a :class:`FakeSshSession`); any other pair
      yields ``AUTH_FAILED``.
    - ``connect_script`` (optional) overrides the above with an explicit list
      of :class:`SshOutcome` popped per call - used to simulate dropped
      connections / rate-limiting sequences.
    """

    def __init__(
        self,
        port_open: bool = True,
        port_error: Optional[str] = None,
        valid_credentials: Optional[set] = None,
        command_outputs: Optional[Dict[str, CommandOutput]] = None,
        connect_script: Optional[List[SshOutcome]] = None,
    ) -> None:
        self._port_open = port_open
        self._port_error = port_error
        self._valid = valid_credentials or set()
        self._command_outputs = command_outputs or {}
        self._script = list(connect_script) if connect_script is not None else None
        self.connect_calls: List[dict] = []
        self.last_session: Optional[FakeSshSession] = None

    def check_port(self, host: str, port: int = 22, timeout: int = 3) -> Result[bool]:
        if self._port_error is not None:
            return Result.err(self._port_error)
        return Result.ok(self._port_open)

    def connect(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 10,
    ) -> SshConnectResult:
        self.connect_calls.append({"host": host, "username": username, "password": password})

        if self._script is not None:
            outcome = self._script.pop(0) if self._script else SshOutcome.AUTH_FAILED
        elif (username, password) in self._valid:
            outcome = SshOutcome.SUCCESS
        else:
            outcome = SshOutcome.AUTH_FAILED

        if outcome is SshOutcome.SUCCESS:
            session = FakeSshSession(self._command_outputs)
            self.last_session = session
            return SshConnectResult(outcome=outcome, session=session)
        return SshConnectResult(outcome=outcome, message=outcome.value)


class FakeLogReader:
    """A fake 'way to fetch log content' for the log module.

    Maps a log path to its full text (or to a ``Result`` for error cases).
    Mirrors the real ``read(path) -> Result[str]`` contract, so the log
    module never needs a real file or SSH session in tests.
    """

    def __init__(self, contents: Optional[Dict[str, object]] = None) -> None:
        self._contents = contents or {}
        self.reads: List[str] = []

    def read(self, path: str) -> Result[str]:
        self.reads.append(path)
        if path not in self._contents:
            return Result.err(f"{path}: No such file")
        val = self._contents[path]
        return val if isinstance(val, Result) else Result.ok(val)
