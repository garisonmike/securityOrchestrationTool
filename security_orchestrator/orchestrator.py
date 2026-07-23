"""
orchestrator
============

Sequences the modules into a single ``Report`` and owns the gating rules as
explicit, named conditions - not as an implicit side effect of call order
(plan.md Phase-4).

Two product decisions from the plan are made concrete here:

  * Log correlation independent of PrivEsc (Section 0 item 7). The rule is:
    prefer a live SSH session handed over by privesc; otherwise, if the user
    supplied ``--log-source <path>``, read that local file (``analyze_logs``
    never needed SSH); otherwise skip with an explicit, recorded reason.
    Log correlation is therefore reachable without privesc, deliberately.

  * Non-interactive missing-tool policy (Section 0.1 item 14). There is no
    prompting anywhere in ``run`` - a scan runs to completion from the
    ``ScanConfig`` alone. A tool that is absent surfaces as ``Result.err``
    from its adapter, which each module records as a SKIPPED/ERROR status on
    its own findings model. So a missing tool degrades that one capability
    and is written into the ``Report``; it never blocks the run or waits on
    a tty. This is what makes the CLI's non-interactive exit criterion
    meaningful in CI.

The orchestrator collects *all* input from the ``ScanConfig`` up front, so
the interactive CLI and a scripted ``--target ...`` invocation drive the
exact same entry point and cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from security_orchestrator.core.models import (
    LogFindings,
    Module,
    ModuleStatus,
    Profile,
    Report,
    ScanConfig,
)
from security_orchestrator.modules.fuzzer import FuzzerModule
from security_orchestrator.modules.log_analyzer import LogModule
from security_orchestrator.modules.privesc import PrivescModule, parse_hostname
from security_orchestrator.modules.recon import ReconModule


@dataclass
class Adapters:
    """Bundle of the seven adapters, so callers inject one object.

    Tests build this from ``adapters.fakes``; production uses
    :func:`default_adapters`.
    """

    http: object
    nmap: object
    gobuster: object
    nuclei: object
    ssh: object
    searchsploit: object
    wkhtmltopdf: object


def default_adapters() -> Adapters:  # pragma: no cover - wires real I/O adapters
    from security_orchestrator.adapters.gobuster import GobusterAdapter
    from security_orchestrator.adapters.http import HttpAdapter
    from security_orchestrator.adapters.nmap import NmapAdapter
    from security_orchestrator.adapters.nuclei import NucleiAdapter
    from security_orchestrator.adapters.searchsploit import SearchsploitAdapter
    from security_orchestrator.adapters.ssh import SshAdapter
    from security_orchestrator.adapters.wkhtmltopdf import WkhtmltopdfAdapter

    return Adapters(
        http=HttpAdapter(),
        nmap=NmapAdapter(),
        gobuster=GobusterAdapter(),
        nuclei=NucleiAdapter(),
        ssh=SshAdapter(),
        searchsploit=SearchsploitAdapter(),
        wkhtmltopdf=WkhtmltopdfAdapter(),
    )


class Orchestrator:
    def __init__(self, adapters: Optional[Adapters] = None) -> None:
        self.adapters = adapters or default_adapters()

    def run(self, config: ScanConfig) -> Report:
        report = Report(target=config.target, config=config)
        selected = set(config.modules)

        tech_stack = None
        if Module.RECON in selected:
            recon = ReconModule(
                self.adapters.http,
                self.adapters.nmap,
                self.adapters.gobuster,
                self.adapters.searchsploit,
            )
            report.recon = recon.run(config)
            if report.recon.status is ModuleStatus.SUCCESS:
                tech_stack = report.recon.hierarchical_stack

        if Module.FUZZER in selected:
            fuzzer = FuzzerModule(self.adapters.http, self.adapters.nuclei)
            report.fuzzer = fuzzer.run(config, tech_stack)

        session = None
        if Module.PRIVESC in selected:
            privesc = PrivescModule(self.adapters.ssh)
            creds = self._resolve_ssh_credentials(config, privesc)
            report.privesc, session = privesc.run(config, creds)

        if Module.LOGS in selected:
            report.log_analysis = self._run_log_correlation(config, session)

        if session is not None:
            session.close()
        return report

    # -- gating helpers ----------------------------------------------------
    def _resolve_ssh_credentials(
        self, config: ScanConfig, privesc: PrivescModule
    ) -> Optional[Dict[str, str]]:
        """Explicit rule: user-supplied creds win; otherwise a noisy-profile
        scan may try rate-limit-aware default credentials; a stealth scan
        with no creds simply skips privesc (no attempt)."""
        if config.ssh_username and config.ssh_password:
            return {"username": config.ssh_username, "password": config.ssh_password}

        if config.profile is Profile.NOISY:
            host = parse_hostname(config.target)
            limited, _msg = privesc.detect_rate_limiting(host)
            if limited:
                return None
            brute = privesc.try_default_credentials(host)
            if brute["success"]:
                return brute["credentials"]
        return None

    def _run_log_correlation(
        self, config: ScanConfig, session
    ) -> LogFindings:
        """Explicit gating (Section 0 item 7):
        1. a live SSH session from privesc -> analyze remote logs;
        2. else a --log-source local file -> analyze it (no SSH needed);
        3. else skip, recording why."""
        log = LogModule()
        host = parse_hostname(config.target)
        if session is not None:
            return log.analyze_remote(session, host)
        if config.log_source:
            return log.analyze_local_file(config.log_source)
        return LogFindings.skipped(
            source=host,
            reason="No SSH session established and no --log-source provided",
        )
