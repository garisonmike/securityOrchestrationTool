"""Phase 4 tests for the orchestrator: sequencing, gating, policy."""

from security_orchestrator.adapters.fakes import (
    FakeGobusterAdapter,
    FakeHttpAdapter,
    FakeNmapAdapter,
    FakeNucleiAdapter,
    FakeSearchsploitAdapter,
    FakeSshAdapter,
    FakeWkhtmltopdfAdapter,
)
from security_orchestrator.adapters.http import HttpResponse
from security_orchestrator.adapters.nmap import NmapScan
from security_orchestrator.adapters.ssh import CommandOutput
from security_orchestrator.core.models import (
    Module,
    ModuleStatus,
    Profile,
    ScanConfig,
)
from security_orchestrator.core.result import Result
from security_orchestrator.orchestrator import Adapters, Orchestrator

SAMPLE_LOG = 'GET / nmap\nGET /?q=UNION SELECT 1 HTTP\nnuclei ua\n'


def _adapters(**overrides):
    online = HttpResponse(status_code=200, text="<html></html>", headers={"Server": "Apache"}, url="http://localhost:8080")
    base = dict(
        http=FakeHttpAdapter(default=Result.ok(online)),
        nmap=FakeNmapAdapter(Result.ok(NmapScan(raw_output="scan", command="nmap", skip_ping_used=True))),
        gobuster=FakeGobusterAdapter(),
        nuclei=FakeNucleiAdapter(Result.err("nuclei not found in PATH")),
        ssh=FakeSshAdapter(),
        searchsploit=FakeSearchsploitAdapter(),
        wkhtmltopdf=FakeWkhtmltopdfAdapter(),
    )
    base.update(overrides)
    return Adapters(**base)


def test_only_selected_modules_appear_in_report():
    config = ScanConfig(target="localhost:8080", modules=[Module.RECON])
    report = Orchestrator(_adapters()).run(config)
    assert report.recon is not None
    assert report.fuzzer is None
    assert report.privesc is None
    assert report.log_analysis is None  # not selected -> None, not a fake skip


def test_fuzzer_receives_recon_tech_stack():
    config = ScanConfig(target="localhost:8080", modules=[Module.RECON, Module.FUZZER])
    report = Orchestrator(_adapters()).run(config)
    assert report.recon is not None
    assert report.fuzzer is not None


def test_privesc_skipped_without_credentials_in_stealth():
    config = ScanConfig(target="localhost:8080", modules=[Module.PRIVESC])
    report = Orchestrator(_adapters()).run(config)
    assert report.privesc.status is ModuleStatus.SKIPPED
    assert report.privesc.findings is None


def test_privesc_uses_supplied_credentials():
    ssh = FakeSshAdapter(
        valid_credentials={("root", "root")},
        command_outputs={"os-release": CommandOutput(command="c", stdout="Ubuntu")},
    )
    config = ScanConfig(
        target="localhost:8080",
        modules=[Module.PRIVESC],
        ssh_username="root",
        ssh_password="root",
    )
    report = Orchestrator(_adapters(ssh=ssh)).run(config)
    assert report.privesc.status is ModuleStatus.SUCCESS


def test_log_correlation_gating_no_session_no_source_is_skipped():
    config = ScanConfig(target="localhost:8080", modules=[Module.LOGS])
    report = Orchestrator(_adapters()).run(config)
    assert report.log_analysis.status is ModuleStatus.SKIPPED
    assert "no ssh session" in report.log_analysis.reason.lower()


def test_log_correlation_runs_independently_via_log_source(tmp_path):
    # Section 0 item 7: logs reachable without privesc, via --log-source.
    log_file = tmp_path / "access.log"
    log_file.write_text(SAMPLE_LOG)
    config = ScanConfig(
        target="localhost:8080",
        modules=[Module.LOGS],
        log_source=str(log_file),
    )
    report = Orchestrator(_adapters()).run(config)
    assert report.log_analysis.status is ModuleStatus.SUCCESS
    assert report.log_analysis.detection_score >= 3


def test_log_correlation_uses_privesc_session_when_available():
    ssh = FakeSshAdapter(
        valid_credentials={("root", "root")},
        command_outputs={"cat": CommandOutput(command="c", stdout=SAMPLE_LOG)},
    )
    config = ScanConfig(
        target="localhost:8080",
        modules=[Module.PRIVESC, Module.LOGS],
        ssh_username="root",
        ssh_password="root",
    )
    report = Orchestrator(_adapters(ssh=ssh)).run(config)
    assert report.privesc.status is ModuleStatus.SUCCESS
    assert report.log_analysis.status is ModuleStatus.SUCCESS
    assert report.log_analysis.source  # hostname
    # session was closed by the orchestrator after log correlation
    assert ssh.last_session.closed is True


def test_missing_tool_degrades_module_not_the_run():
    # nuclei absent: fuzzer still produces findings, marked skipped - no crash,
    # no prompt (non-interactive missing-tool policy, Section 0.1 item 14).
    config = ScanConfig(target="localhost:8080", modules=[Module.FUZZER])
    report = Orchestrator(_adapters(nuclei=FakeNucleiAdapter(Result.err("nuclei not found in PATH")))).run(config)
    assert report.fuzzer is not None
    assert report.fuzzer.nuclei_scan.status is ModuleStatus.SKIPPED
