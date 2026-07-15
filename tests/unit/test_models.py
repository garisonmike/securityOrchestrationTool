"""Phase 1 tests for the six typed models.

Exit criteria (plan.md Phase-1):
  - every model round-trips through model_dump() / model_validate()
  - valid input constructs; missing required fields raise ValidationError
  - skipped/error variants are representable without inventing data
"""

import pytest
from pydantic import ValidationError

from security_orchestrator.core.models import (
    FuzzerFindings,
    LogFindings,
    Module,
    ModuleStatus,
    OpsecLevel,
    PrivescFindings,
    Profile,
    ReconFindings,
    Report,
    ReportFormat,
    ScanConfig,
    SearchsploitResult,
)


# --- ScanConfig ------------------------------------------------------------
def test_scanconfig_minimal_valid():
    cfg = ScanConfig(target="localhost:8080", modules=[Module.RECON])
    assert cfg.target == "localhost:8080"
    assert cfg.profile is Profile.STEALTH
    assert cfg.opsec_level is OpsecLevel.STEALTH
    assert cfg.report_format is ReportFormat.MARKDOWN


def test_scanconfig_empty_target_rejected():
    with pytest.raises(ValidationError):
        ScanConfig(target="   ", modules=[Module.RECON])


def test_scanconfig_requires_a_module():
    with pytest.raises(ValidationError):
        ScanConfig(target="x", modules=[])


def test_scanconfig_dedupes_modules_preserving_order():
    cfg = ScanConfig(target="x", modules=[Module.FUZZER, Module.RECON, Module.FUZZER])
    assert cfg.modules == [Module.FUZZER, Module.RECON]


def test_scanconfig_rejects_unknown_field():
    with pytest.raises(ValidationError):
        ScanConfig(target="x", modules=[Module.RECON], bogus=1)


def test_scanconfig_rejects_unknown_module_value():
    with pytest.raises(ValidationError):
        ScanConfig(target="x", modules=["not-a-module"])


# --- variant constructors --------------------------------------------------
def test_recon_skipped_variant_has_no_invented_data():
    r = ReconFindings.skipped(target="x", reason="not selected")
    assert r.status is ModuleStatus.SKIPPED
    assert r.reason == "not selected"
    assert r.web_headers is None
    assert r.nmap_scan is None
    # buckets always exist (empty), never absent
    assert r.hierarchical_stack.frontend == []


def test_privesc_three_distinct_shapes():
    # user-skipped: no attempt -> findings is None
    skipped = PrivescFindings.skipped(reason="User chose to skip")
    assert skipped.status is ModuleStatus.SKIPPED
    assert skipped.findings is None

    # connection-error: attempt made -> findings present-but-empty
    errored = PrivescFindings.error(reason="Authentication failed", target="h")
    assert errored.status is ModuleStatus.ERROR
    assert errored.findings == {}

    # success: populated findings
    ok = PrivescFindings(
        status=ModuleStatus.SUCCESS,
        target="h",
        auth_used="root",
        findings={"os_release": {"command": "cat", "stdout": "Ubuntu"}},
    )
    assert ok.findings is not None
    assert ok.findings["os_release"].stdout == "Ubuntu"


def test_log_findings_uses_single_source_field():
    # both the file-path path and the ssh path populate one field: source.
    from_file = LogFindings(status=ModuleStatus.SUCCESS, source="/var/log/auth.log")
    from_ssh = LogFindings(status=ModuleStatus.SUCCESS, source="10.0.0.5")
    assert from_file.source == "/var/log/auth.log"
    assert from_ssh.source == "10.0.0.5"
    # matches buckets always exist
    assert from_file.matches.nmap == []


def test_searchsploit_result_accepts_searchsploit_json_aliases():
    raw = {"Title": "Apache 2.4 RCE", "EDB-ID": "12345", "Path": "/x", "Date_Published": "2023-01-01"}
    s = SearchsploitResult.model_validate(raw)
    assert s.title == "Apache 2.4 RCE"
    assert s.edb_id == "12345"


# --- round-trip ------------------------------------------------------------
def test_full_report_round_trips():
    cfg = ScanConfig(target="localhost:8080", modules=[Module.RECON, Module.PRIVESC])
    report = Report(
        target="localhost:8080",
        config=cfg,
        recon=ReconFindings(status=ModuleStatus.SUCCESS, target="localhost:8080"),
        privesc=PrivescFindings.skipped(reason="User chose to skip"),
        fuzzer=FuzzerFindings.skipped(target="localhost:8080", reason="not selected"),
    )
    dumped = report.model_dump()
    restored = Report.model_validate(dumped)
    assert restored == report
    # log_analysis was never part of the run -> None, not a fake skipped dict
    assert restored.log_analysis is None


def test_report_requires_target_and_config():
    with pytest.raises(ValidationError):
        Report()  # type: ignore[call-arg]
