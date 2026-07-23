"""Phase 4 tests for the CLI: argument parsing + end-to-end run on fakes."""

import pytest

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
from security_orchestrator.cli import build_config, build_parser, main
from security_orchestrator.core.exceptions import ConfigError
from security_orchestrator.core.models import Module, OpsecLevel, Profile, ReportFormat
from security_orchestrator.core.result import Result
from security_orchestrator.orchestrator import Adapters


def _args(argv):
    return build_parser().parse_args(argv)


# --- argument parsing ------------------------------------------------------
def test_build_config_maps_all_flags():
    config = build_config(_args([
        "--target", "localhost:8080",
        "--modules", "recon,fuzzer",
        "--profile", "noisy",
        "--opsec", "noisy",
        "--output-format", "html",
        "--cookie", "PHPSESSID=x",
    ]))
    assert config.target == "localhost:8080"
    assert config.modules == [Module.RECON, Module.FUZZER]
    assert config.profile is Profile.NOISY
    assert config.opsec_level is OpsecLevel.NOISY
    assert config.report_format is ReportFormat.HTML
    assert config.cookie == "PHPSESSID=x"


def test_module_aliases_and_dedup():
    config = build_config(_args(["--target", "t", "--modules", "log,logs,fuzz,fuzzer"]))
    assert config.modules == [Module.LOGS, Module.FUZZER]


def test_unknown_module_raises_config_error():
    with pytest.raises(ConfigError):
        build_config(_args(["--target", "t", "--modules", "recon,bogus"]))


def test_missing_modules_raises_config_error():
    with pytest.raises(ConfigError):
        build_config(_args(["--target", "t"]))


def test_empty_target_raises_config_error():
    with pytest.raises(ConfigError):
        build_config(_args(["--target", "   ", "--modules", "recon"]))


# --- end-to-end (exit criterion) ------------------------------------------
def _fake_adapters():
    online = HttpResponse(status_code=200, text="<html></html>", headers={"Server": "Apache"}, url="http://localhost:8080")
    return Adapters(
        http=FakeHttpAdapter(default=Result.ok(online)),
        nmap=FakeNmapAdapter(Result.ok(NmapScan(raw_output="scan", command="nmap", skip_ping_used=True))),
        gobuster=FakeGobusterAdapter(),
        nuclei=FakeNucleiAdapter(Result.err("nuclei not found in PATH")),
        ssh=FakeSshAdapter(),
        searchsploit=FakeSearchsploitAdapter(),
        wkhtmltopdf=FakeWkhtmltopdfAdapter(),
    )


def test_main_runs_non_interactively_and_writes_report(tmp_path, capsys):
    # plan.md Phase-4 exit: runs non-interactively, in CI, no real network,
    # no hang on a missing-tool prompt.
    code = main(
        [
            "--target", "localhost:8080",
            "--modules", "recon,fuzzer",
            "--output-format", "markdown",
            "--output-dir", str(tmp_path),
        ],
        adapters=_fake_adapters(),
    )
    assert code == 0
    reports = list(tmp_path.glob("report_*.md"))
    assert len(reports) == 1
    out = capsys.readouterr().out
    assert "Report written to" in out


def test_main_bad_config_returns_exit_code_2(capsys):
    code = main(["--target", "t", "--modules", "nonsense"], adapters=_fake_adapters())
    assert code == 2
