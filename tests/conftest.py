"""
Shared test safety net (plan.md Phase-2 exit criterion).

No test in this suite is allowed to open a real socket or spawn a real
subprocess: every adapter takes an injectable runner, and every module test
injects a Fake* adapter. To make an *accidental* live call a loud failure
instead of a silent real scan, this autouse fixture monkeypatches the low
-level primitives to raise. Code under test must go through an injected
runner - never these.

A test that genuinely needs to exercise a real primitive (there are none by
design) would have to opt out explicitly; nothing here does.
"""

import socket
import subprocess

import pytest


@pytest.fixture(autouse=True)
def _no_live_calls(monkeypatch):
    def _blocked_subprocess(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError(
            "A test triggered a real subprocess.run(). Tests must inject a fake "
            "runner into the adapter instead of calling the real tool."
        )

    def _blocked_socket(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError(
            "A test triggered a real socket(). Tests must inject a fake "
            "socket_factory into the SSH adapter instead of opening a socket."
        )

    monkeypatch.setattr(subprocess, "run", _blocked_subprocess)
    monkeypatch.setattr(socket, "socket", _blocked_socket)
    yield
