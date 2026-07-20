"""
modules.privesc
===============

Privilege-escalation simulation on the SSH adapter. Produces a
``PrivescFindings`` in exactly one of its three explicit shapes
(plan.md Section 0.1 item 15):

  * SUCCESS - connected, ``findings`` populated with enumeration output.
  * ERROR   - an attempt was made but the connection failed; ``findings``
              is an empty dict (present, not absent).
  * SKIPPED - no attempt was made (no credentials / user opted out);
              ``findings`` is ``None``.

``run`` returns the findings *and* the still-open SSH session, so the
orchestrator can hand that session to log correlation before closing it -
this is what decouples log correlation's data source from privesc's private
state (bug #7), rather than the two modules sharing a global.

Timing-dependent logic (rate-limit detection, inter-attempt backoff) takes
injected ``clock`` and ``sleep`` callables so it is deterministic in tests.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from security_orchestrator.adapters.ssh import SshOutcome, SshSession
from security_orchestrator.core.models import (
    ModuleStatus,
    PrivescCommandResult,
    PrivescFindings,
    ScanConfig,
)

DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("root", "root"),
    ("root", "toor"),
    ("admin", "password"),
    ("pi", "raspberry"),
    ("user", "user"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
]

ENUM_COMMANDS: Dict[str, str] = {
    "sudo_privileges": "sudo -n -l 2>/dev/null",
    "suid_binaries": "find / -type f -perm -4000 2>/dev/null | grep -v 'snap\\|docker' | head -n 20",
    "shadow_writable": "ls -l /etc/shadow | awk '{print $1}'",
    "cron_jobs": "cat /etc/crontab 2>/dev/null",
    "os_release": "cat /etc/os-release | grep PRETTY_NAME",
}


def parse_hostname(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target.split(":")[0]


class PrivescModule:
    def __init__(
        self,
        ssh,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.ssh = ssh
        self._clock = clock
        self._sleep = sleep

    # -- rate-limit detection ---------------------------------------------
    def detect_rate_limiting(self, host: str, port: int = 22) -> Tuple[bool, str]:
        delays: List[float] = []
        drops = 0
        for attempt in range(3):
            start = self._clock()
            conn = self.ssh.connect(host, "__rate_limit_test__", "__invalid__", port=port)
            delays.append(self._clock() - start)
            if conn.session is not None:
                conn.session.close()
            if conn.outcome is SshOutcome.DROPPED:
                drops += 1
            elif conn.outcome in (SshOutcome.UNREACHABLE, SshOutcome.ERROR):
                return (False, f"Rate limit detection inconclusive: {conn.message}")
            if attempt < 2:
                self._sleep(0.1)

        if drops >= 2:
            return (True, f"SSH rate limiting detected: {drops}/3 connections dropped/reset")
        if len(delays) == 3 and delays[1] > delays[0] * 1.5 and delays[2] > delays[1] * 1.5:
            return (
                True,
                f"SSH rate limiting detected: exponential delay pattern "
                f"({delays[0]:.2f}s -> {delays[1]:.2f}s -> {delays[2]:.2f}s)",
            )
        if any(d > 5.0 for d in delays):
            return (True, f"SSH rate limiting detected: artificial delay (max {max(delays):.2f}s)")
        avg = sum(delays) / len(delays) if delays else 0.0
        return (False, f"No rate limiting detected (avg delay: {avg:.2f}s)")

    # -- default credential brute-force -----------------------------------
    def try_default_credentials(self, host: str, port: int = 22) -> Dict[str, Any]:
        port_check = self.ssh.check_port(host, port)
        if port_check.is_err:
            return self._brute_fail(0, f"[!] {port_check.error} - skipping SSH brute-force.")
        if not port_check.value:
            return self._brute_fail(0, f"[!] Port {port} closed/filtered - skipping SSH brute-force.")

        for idx, (username, password) in enumerate(DEFAULT_CREDENTIALS, start=1):
            conn = self.ssh.connect(host, username, password, port=port)
            if conn.outcome is SshOutcome.SUCCESS:
                if conn.session is not None:
                    conn.session.close()
                return {
                    "success": True,
                    "credentials": {"username": username, "password": password},
                    "attempts": idx,
                    "message": f"Default credentials found: {username}:{password}",
                }
            if conn.outcome is SshOutcome.DROPPED:
                return self._brute_fail(idx, f"[!] SSH connection dropped: {conn.message} - aborting.")
            if conn.outcome is SshOutcome.UNREACHABLE:
                return self._brute_fail(idx, f"[!] SSH unreachable: {conn.message}")
            if conn.outcome is SshOutcome.ERROR:
                return self._brute_fail(idx, f"[!] Unexpected SSH error: {conn.message}")
            # AUTH_FAILED -> try the next pair.
            self._sleep(0.5)

        return self._brute_fail(
            len(DEFAULT_CREDENTIALS),
            f"No default credentials found (tried {len(DEFAULT_CREDENTIALS)} combinations)",
        )

    @staticmethod
    def _brute_fail(attempts: int, message: str) -> Dict[str, Any]:
        return {"success": False, "credentials": None, "attempts": attempts, "message": message}

    # -- main entry point --------------------------------------------------
    def run(
        self,
        config: ScanConfig,
        ssh_creds: Optional[Dict[str, str]],
    ) -> Tuple[PrivescFindings, Optional[SshSession]]:
        host = parse_hostname(config.target)

        if not ssh_creds or not ssh_creds.get("username") or not ssh_creds.get("password"):
            return PrivescFindings.skipped(reason="No SSH credentials provided", target=host), None

        username = ssh_creds["username"]
        conn = self.ssh.connect(host, username, ssh_creds["password"])
        if conn.outcome is not SshOutcome.SUCCESS:
            reason = {
                SshOutcome.AUTH_FAILED: "Authentication failed. Invalid username or password.",
                SshOutcome.DROPPED: f"SSH connection dropped: {conn.message}",
                SshOutcome.UNREACHABLE: f"SSH unreachable: {conn.message}",
                SshOutcome.ERROR: f"Unexpected SSH error: {conn.message}",
            }.get(conn.outcome, conn.message)
            return PrivescFindings.error(reason=reason, target=host, auth_used=username), None

        session = conn.session
        assert session is not None
        results: Dict[str, PrivescCommandResult] = {}
        for key, command in ENUM_COMMANDS.items():
            out = session.exec(command)
            if out.is_ok:
                results[key] = PrivescCommandResult(
                    command=command,
                    stdout=out.value.stdout,
                    stderr=out.value.stderr,
                    exit_status=out.value.exit_status,
                )
            else:
                results[key] = PrivescCommandResult(command=command, error=out.error)

        findings = PrivescFindings(
            status=ModuleStatus.SUCCESS,
            target=host,
            auth_used=username,
            findings=results,
        )
        return findings, session
