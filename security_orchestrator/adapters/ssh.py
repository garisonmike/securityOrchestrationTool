"""
adapters.ssh
============

SSH access behind an injectable ``client_factory`` (paramiko.SSHClient) and
``socket_factory`` (socket.socket), so privesc/log tests never open a real
socket.

SSH has more than two outcomes that callers must distinguish - an auth
rejection (credential simply wrong, keep trying) is not the same event as a
connection being dropped/reset (a rate-limiting signal, stop trying). A flat
ok/err ``Result`` would collapse that distinction, so :meth:`connect`
returns a richer :class:`SshConnectResult` carrying an explicit
:class:`SshOutcome`. The simple port check still returns a plain ``Result``.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

from security_orchestrator.core.result import Result

# Imported at module load (not lazily inside connect) so the import happens
# during collection, before any test fixture monkeypatches socket.socket -
# paramiko's own import chain touches socket and breaks under that patch.
# Guarded so the module still loads in an environment without paramiko.
try:
    import paramiko as _paramiko
    from paramiko.ssh_exception import SSHException as _SSHException

    _AUTH_EXC: tuple = (_paramiko.AuthenticationException,)
    _SSH_EXC: tuple = (_SSHException,)
except Exception:  # pragma: no cover - paramiko is a declared dependency
    _paramiko = None
    _AUTH_EXC = ()
    _SSH_EXC = ()

_CONNECT_TIMEOUT = 10
_EXEC_TIMEOUT = 15


class SshOutcome(str, Enum):
    SUCCESS = "success"
    AUTH_FAILED = "auth_failed"
    DROPPED = "dropped"          # connection reset/EOF - rate-limiting signal
    UNREACHABLE = "unreachable"  # port closed, host unresolvable, socket error
    ERROR = "error"             # anything unexpected


@dataclass
class CommandOutput:
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_status: Optional[int] = None
    error: Optional[str] = None


class SshSession:
    """A connected SSH session. Wraps a paramiko client (or a fake)."""

    def __init__(self, client) -> None:
        self._client = client

    def exec(self, command: str, timeout: int = _EXEC_TIMEOUT) -> Result[CommandOutput]:
        try:
            _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            return Result.ok(
                CommandOutput(command=command, stdout=out, stderr=err, exit_status=exit_status)
            )
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"command {command!r} failed: {type(exc).__name__}: {exc}")

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 - close is best-effort
            pass


@dataclass
class SshConnectResult:
    outcome: SshOutcome
    session: Optional[SshSession] = None
    message: str = ""

    @property
    def is_success(self) -> bool:
        return self.outcome is SshOutcome.SUCCESS


def _default_client_factory():  # pragma: no cover - real paramiko
    client = _paramiko.SSHClient()
    client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
    return client


class SshAdapter:
    def __init__(
        self,
        client_factory: Callable = _default_client_factory,
        socket_factory: Callable = socket.socket,
    ) -> None:
        self._client_factory = client_factory
        self._socket_factory = socket_factory

    def check_port(self, host: str, port: int = 22, timeout: int = 3) -> Result[bool]:
        try:
            sock = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            sock.close()
        except socket.gaierror:
            return Result.err(f"hostname {host} could not be resolved")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"port check failed: {type(exc).__name__}: {exc}")
        return Result.ok(code == 0)

    def connect(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = _CONNECT_TIMEOUT,
    ) -> SshConnectResult:
        auth_exc = _AUTH_EXC
        ssh_exc = _SSH_EXC

        client = self._client_factory()
        try:
            client.connect(
                hostname=host,
                username=username,
                password=password,
                port=port,
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return SshConnectResult(outcome=SshOutcome.SUCCESS, session=SshSession(client))
        except auth_exc:  # type: ignore[misc]
            _safe_close(client)
            return SshConnectResult(outcome=SshOutcome.AUTH_FAILED, message="authentication failed")
        except ssh_exc as exc:  # type: ignore[misc]
            _safe_close(client)
            return SshConnectResult(outcome=SshOutcome.DROPPED, message=f"SSH error: {exc}")
        except EOFError:
            _safe_close(client)
            return SshConnectResult(outcome=SshOutcome.DROPPED, message="connection dropped (EOF)")
        except socket.error as exc:
            _safe_close(client)
            return SshConnectResult(outcome=SshOutcome.UNREACHABLE, message=f"network error: {exc}")
        except Exception as exc:  # noqa: BLE001 - boundary
            _safe_close(client)
            return SshConnectResult(
                outcome=SshOutcome.ERROR, message=f"{type(exc).__name__}: {exc}"
            )


def _safe_close(client) -> None:
    try:
        client.close()
    except Exception:  # noqa: BLE001
        pass


# Default remote log locations the SSH log path reads, kept next to the
# adapter so both the real path and fakes share one source of truth.
DEFAULT_REMOTE_LOG_PATHS: List[str] = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/auth.log",
    "/var/log/syslog",
]
