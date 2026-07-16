"""
adapters
========

One class per external tool/network call (http, nmap, gobuster, nuclei,
ssh, searchsploit, wkhtmltopdf). Each constructor takes an injectable
runner that defaults to the real subprocess/paramiko/requests call, and
each adapter exposes one public method that returns a `core.result.Result`.

`fakes.py` holds the Fake* counterparts used only by tests (never real
network/subprocess calls) - see plan.md Phase-2.

Populated in Phase 2. Empty in Phase 0.
"""

from security_orchestrator.adapters.gobuster import GobusterAdapter, GobusterScan
from security_orchestrator.adapters.http import HttpAdapter, HttpResponse, body_looks_like_html
from security_orchestrator.adapters.nmap import NmapAdapter, NmapScan
from security_orchestrator.adapters.nuclei import NucleiAdapter, NucleiScan
from security_orchestrator.adapters.searchsploit import SearchsploitAdapter
from security_orchestrator.adapters.ssh import (
    CommandOutput,
    SshAdapter,
    SshConnectResult,
    SshOutcome,
    SshSession,
)
from security_orchestrator.adapters.wkhtmltopdf import WkhtmltopdfAdapter

__all__ = [
    "HttpAdapter",
    "HttpResponse",
    "body_looks_like_html",
    "NmapAdapter",
    "NmapScan",
    "GobusterAdapter",
    "GobusterScan",
    "NucleiAdapter",
    "NucleiScan",
    "SearchsploitAdapter",
    "SshAdapter",
    "SshSession",
    "SshConnectResult",
    "SshOutcome",
    "CommandOutput",
    "WkhtmltopdfAdapter",
]
