"""
Phase 2 adapter tests.

Mandatory matrix per adapter (plan.md Phase-2):
  - tool succeeds, output parses cleanly
  - tool binary missing (which -> None) -> Result.err
  - tool times out
  - tool returns non-zero exit / malformed output
  - (http only) realistic long-doctype regression for bug #3

Every adapter is driven through an injected fake runner; the autouse
conftest fixture guarantees no real subprocess/socket is ever touched.
"""

import subprocess
from types import SimpleNamespace

import pytest

from security_orchestrator.adapters.gobuster import GobusterAdapter
from security_orchestrator.adapters.http import HttpAdapter, body_looks_like_html
from security_orchestrator.adapters.nmap import NmapAdapter
from security_orchestrator.adapters.nuclei import NucleiAdapter
from security_orchestrator.adapters.searchsploit import SearchsploitAdapter
from security_orchestrator.adapters.ssh import SshAdapter, SshOutcome
from security_orchestrator.adapters.wkhtmltopdf import WkhtmltopdfAdapter


# --- fake subprocess helpers ----------------------------------------------
def proc(returncode=0, stdout="", stderr=""):
    """Build a fake CompletedProcess-like object."""
    def runner(cmd, capture_output=True, text=True, timeout=None):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    return runner


def timing_out(cmd, capture_output=True, text=True, timeout=None):
    raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)


def present(name):
    return f"/usr/bin/{name}"


def missing(name):
    return None


# --- HTTP ------------------------------------------------------------------
class FakeRequestsResponse:
    def __init__(self, status_code=200, text="", headers=None, url="", history=None, elapsed_s=0.1):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.history = history or []
        self.elapsed = SimpleNamespace(total_seconds=lambda: elapsed_s)


def test_http_success_parses_cleanly():
    resp = FakeRequestsResponse(
        status_code=200,
        text="<html><body>hi</body></html>",
        headers={"Server": "Apache", "Set-Cookie": "PHPSESSID=x"},
        url="http://t/",
    )
    adapter = HttpAdapter(runner=lambda *a, **k: resp)
    result = adapter.get("http://t/")
    assert result.is_ok
    assert result.value.status_code == 200
    assert result.value.headers["Server"] == "Apache"
    assert result.value.elapsed_seconds == pytest.approx(0.1)


def test_http_network_failure_is_err():
    def boom(*a, **k):
        raise ConnectionError("refused")
    result = HttpAdapter(runner=boom).get("http://t/")
    assert result.is_err
    assert "failed" in result.error


def test_http_timeout_is_err():
    def to(*a, **k):
        raise TimeoutError("timed out")
    result = HttpAdapter(runner=to).get("http://t/")
    assert result.is_err


def test_http_malformed_runner_return_is_err():
    # runner returns something without status_code
    result = HttpAdapter(runner=lambda *a, **k: object()).get("http://t/")
    assert result.is_err
    assert "could not be parsed" in result.error


# bug #3 regression: a realistic long doctype must still be recognised as HTML.
def test_body_looks_like_html_realistic_long_doctype():
    dvwa_doctype = (
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
        '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'
        '<html xmlns="http://www.w3.org/1999/xhtml">\n<head><title>DVWA</title></head>'
    )
    # The <html tag sits well past character 50 - the legacy 50-char window
    # would have missed it and misclassified the page as a downloadable file.
    assert "<html" not in dvwa_doctype[:50].lower()
    assert body_looks_like_html(dvwa_doctype) is True


def test_body_looks_like_html_negatives():
    assert body_looks_like_html("") is False
    assert body_looks_like_html("just some plaintext CHANGELOG contents") is False
    assert body_looks_like_html('{"name": "package"}') is False


def test_body_looks_like_html_short_doctype_still_html():
    assert body_looks_like_html("<!DOCTYPE html><html><body></body></html>") is True


# --- nmap ------------------------------------------------------------------
def test_nmap_success():
    adapter = NmapAdapter(runner=proc(0, stdout="Nmap scan report..."), which=present)
    result = adapter.scan("host", profile="Stealth", skip_ping=True)
    assert result.is_ok
    assert "Nmap scan report" in result.value.raw_output
    assert result.value.skip_ping_used is True
    assert "-Pn" in result.value.command


def test_nmap_missing_binary():
    result = NmapAdapter(runner=proc(0), which=missing).scan("host")
    assert result.is_err
    assert "not found" in result.error


def test_nmap_timeout():
    result = NmapAdapter(runner=timing_out, which=present).scan("host")
    assert result.is_err
    assert "timed out" in result.error


def test_nmap_nonzero_exit():
    result = NmapAdapter(runner=proc(1, stderr="bad flag"), which=present).scan("host")
    assert result.is_err
    assert "exited 1" in result.error


def test_nmap_stealth_vs_noisy_flags():
    stealth = NmapAdapter(runner=proc(0), which=present).scan("h", profile="Stealth")
    noisy = NmapAdapter(runner=proc(0), which=present).scan("h", profile="Noisy")
    assert "-sV" in stealth.value.command
    assert "-A" in noisy.value.command


# --- gobuster --------------------------------------------------------------
def test_gobuster_success_parses_paths():
    out = "/admin (Status: 200)\n/secret (Status: 301)\n/nope (Status: 404)\n"
    adapter = GobusterAdapter(runner=proc(0, stdout=out), which=present, exists=lambda p: True)
    result = adapter.enumerate("http://t/")
    assert result.is_ok
    assert len(result.value.discovered_paths) == 2


def test_gobuster_missing_binary():
    result = GobusterAdapter(which=missing, exists=lambda p: True).enumerate("http://t/")
    assert result.is_err and "not found" in result.error


def test_gobuster_missing_wordlist():
    result = GobusterAdapter(which=present, exists=lambda p: False).enumerate("http://t/")
    assert result.is_err and "wordlist not found" in result.error


def test_gobuster_timeout():
    result = GobusterAdapter(runner=timing_out, which=present, exists=lambda p: True).enumerate("http://t/")
    assert result.is_err and "timed out" in result.error


def test_gobuster_nonzero_exit():
    result = GobusterAdapter(runner=proc(2, stderr="x"), which=present, exists=lambda p: True).enumerate("http://t/")
    assert result.is_err and "exited 2" in result.error


# --- nuclei ----------------------------------------------------------------
def test_nuclei_success_parses_jsonl():
    out = '{"template-id":"a"}\n\nnot-json-banner\n{"template-id":"b"}\n'
    adapter = NucleiAdapter(runner=proc(0, stdout=out), which=present)
    result = adapter.scan("http://t/", tags=["cve"], severity="high")
    assert result.is_ok
    assert len(result.value.findings) == 2  # the non-JSON banner line is tolerated


def test_nuclei_missing_binary():
    result = NucleiAdapter(which=missing).scan("http://t/")
    assert result.is_err and "not found" in result.error


def test_nuclei_timeout():
    result = NucleiAdapter(runner=timing_out, which=present).scan("http://t/")
    assert result.is_err and "timed out" in result.error


def test_nuclei_nonzero_exit():
    result = NucleiAdapter(runner=proc(1, stderr="template err"), which=present).scan("http://t/")
    assert result.is_err and "exited 1" in result.error


# --- searchsploit ----------------------------------------------------------
def test_searchsploit_success():
    out = '{"RESULTS_EXPLOIT": [{"Title": "Apache RCE"}]}'
    result = SearchsploitAdapter(runner=proc(0, stdout=out), which=present).search("apache 2.4")
    assert result.is_ok
    assert result.value[0]["Title"] == "Apache RCE"


def test_searchsploit_missing_binary():
    result = SearchsploitAdapter(which=missing).search("q")
    assert result.is_err and "not found" in result.error


def test_searchsploit_malformed_json():
    result = SearchsploitAdapter(runner=proc(0, stdout="not json"), which=present).search("q")
    assert result.is_err and "malformed JSON" in result.error


def test_searchsploit_timeout():
    result = SearchsploitAdapter(runner=timing_out, which=present).search("q")
    assert result.is_err and "timed out" in result.error


# --- wkhtmltopdf -----------------------------------------------------------
def test_wkhtmltopdf_success():
    result = WkhtmltopdfAdapter(runner=proc(0), which=present).convert("in.html", "out.pdf")
    assert result.is_ok and result.value == "out.pdf"


def test_wkhtmltopdf_missing_binary():
    result = WkhtmltopdfAdapter(which=missing).convert("in.html", "out.pdf")
    assert result.is_err and "not found" in result.error


def test_wkhtmltopdf_nonzero_exit():
    result = WkhtmltopdfAdapter(runner=proc(1, stderr="boom"), which=present).convert("i", "o")
    assert result.is_err and "exited 1" in result.error


# --- ssh -------------------------------------------------------------------
class FakeSocket:
    def __init__(self, connect_code=0, raise_on_connect=None):
        self._code = connect_code
        self._raise = raise_on_connect

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        if self._raise:
            raise self._raise
        return self._code

    def close(self):
        pass


def test_ssh_check_port_open():
    adapter = SshAdapter(socket_factory=lambda *a, **k: FakeSocket(connect_code=0))
    result = adapter.check_port("host")
    assert result.is_ok and result.value is True


def test_ssh_check_port_closed():
    adapter = SshAdapter(socket_factory=lambda *a, **k: FakeSocket(connect_code=1))
    result = adapter.check_port("host")
    assert result.is_ok and result.value is False


def test_ssh_check_port_unresolvable():
    import socket as _socket

    adapter = SshAdapter(socket_factory=lambda *a, **k: FakeSocket(raise_on_connect=_socket.gaierror()))
    result = adapter.check_port("bad-host")
    assert result.is_err and "could not be resolved" in result.error


class FakeParamikoClient:
    """Fake paramiko.SSHClient covering connect outcomes and exec."""

    def __init__(self, on_connect=None, exec_map=None):
        self._on_connect = on_connect
        self._exec_map = exec_map or {}
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        if self._on_connect is not None:
            raise self._on_connect

    def exec_command(self, command, timeout=None):
        stdout_text = self._exec_map.get(command, "")

        class _Chan:
            def recv_exit_status(self_inner):
                return 0

        class _Std:
            def __init__(self_inner, data):
                self_inner._data = data.encode()
                self_inner.channel = _Chan()

            def read(self_inner):
                return self_inner._data

        return None, _Std(stdout_text), _Std("")

    def close(self):
        self.closed = True


def test_ssh_connect_success_and_exec():
    client = FakeParamikoClient(exec_map={"whoami": "root"})
    adapter = SshAdapter(client_factory=lambda: client)
    conn = adapter.connect("h", "root", "root")
    assert conn.outcome is SshOutcome.SUCCESS
    assert conn.session is not None
    out = conn.session.exec("whoami")
    assert out.is_ok and out.value.stdout == "root"
    conn.session.close()
    assert client.closed


def test_ssh_connect_auth_failed():
    import paramiko

    adapter = SshAdapter(
        client_factory=lambda: FakeParamikoClient(on_connect=paramiko.AuthenticationException())
    )
    conn = adapter.connect("h", "root", "wrong")
    assert conn.outcome is SshOutcome.AUTH_FAILED


def test_ssh_connect_dropped_signals_rate_limit():
    adapter = SshAdapter(client_factory=lambda: FakeParamikoClient(on_connect=EOFError()))
    conn = adapter.connect("h", "u", "p")
    assert conn.outcome is SshOutcome.DROPPED


def test_ssh_connect_unreachable():
    import socket as _socket

    adapter = SshAdapter(client_factory=lambda: FakeParamikoClient(on_connect=_socket.error("no route")))
    conn = adapter.connect("h", "u", "p")
    assert conn.outcome is SshOutcome.UNREACHABLE
