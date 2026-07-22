"""
Phase 5 tests for report rendering.

Direct regression coverage for the exact crash in the pasted run (plan.md
Section 0 item 1) - rendered as TWO independent cases, since either alone
raised UndefinedError in the legacy templates:
  (a) privesc user-skipped, log correlation absent;
  (b) privesc absent, log correlation skipped (the more common trigger).
Plus the redaction regression (Section 0.1 item 9): a rendered report must
never contain a raw session cookie value.
"""

from security_orchestrator.core.models import (
    CustomFuzzerResult,
    FuzzerFindings,
    GobusterResult,
    LogFindings,
    Module,
    ModuleStatus,
    NmapResult,
    NucleiMeta,
    NucleiResult,
    PrivescCommandResult,
    PrivescFindings,
    ReconFindings,
    Report,
    ReportFormat,
    ScanConfig,
    SearchsploitResult,
    TechStack,
    WebHeaders,
)
from security_orchestrator.report.generator import generate_report, render


def _config(fmt=ReportFormat.MARKDOWN, cookie=None):
    return ScanConfig(
        target="localhost:8080",
        modules=[Module.RECON, Module.PRIVESC, Module.LOGS],
        cookie=cookie,
        report_format=fmt,
    )


def _full_recon():
    return ReconFindings(
        status=ModuleStatus.SUCCESS,
        target="localhost:8080",
        hierarchical_stack=TechStack(web_server=["Apache/2.4.41"], backend=["PHP"]),
        searchsploit_results={"Apache 2.4.41": [SearchsploitResult(Title="Apache RCE", **{"EDB-ID": "1"})]},
        nmap_scan=NmapResult(status=ModuleStatus.SUCCESS, raw_output="scan"),
        gobuster_scan=GobusterResult(status=ModuleStatus.SUCCESS, discovered_paths=["/admin"]),
        web_headers=WebHeaders(url="http://localhost:8080", is_online=True),
    )


# --- fully successful report renders ---------------------------------------
def test_full_success_report_renders_markdown():
    report = Report(
        target="localhost:8080",
        config=_config(),
        recon=_full_recon(),
        fuzzer=FuzzerFindings(
            status=ModuleStatus.SUCCESS,
            target="localhost:8080",
            nuclei_scan=NucleiResult(status=ModuleStatus.SUCCESS, findings=[{"id": "x"}], meta=NucleiMeta()),
            custom_fuzzer=CustomFuzzerResult(xss=["one"]),
        ),
        privesc=PrivescFindings(
            status=ModuleStatus.SUCCESS,
            target="localhost:8080",
            auth_used="root",
            findings={"os_release": PrivescCommandResult(command="cat", stdout="Ubuntu 22.04")},
        ),
        log_analysis=LogFindings(status=ModuleStatus.SUCCESS, source="10.0.0.5", detection_score=4, total_lines_analyzed=100),
    )
    out = render(report)
    assert "Apache/2.4.41" in out
    assert "Ubuntu 22.04" in out
    assert "Detection Score:" in out


# --- REGRESSION (a): privesc user-skipped, log correlation absent ----------
def test_render_privesc_skipped_log_absent_does_not_raise():
    report = Report(
        target="localhost:8080",
        config=_config(),
        recon=_full_recon(),
        privesc=PrivescFindings.skipped(reason="User chose to skip"),
        log_analysis=None,
    )
    out = render(report)  # must not raise UndefinedError
    assert "User chose to skip" in out
    assert "PrivEsc" in out


# --- REGRESSION (b): privesc absent, log correlation skipped ---------------
def test_render_privesc_absent_log_skipped_does_not_raise():
    report = Report(
        target="localhost:8080",
        config=_config(),
        recon=_full_recon(),
        privesc=None,
        log_analysis=LogFindings.skipped(source="localhost", reason="No shell access obtained"),
    )
    out = render(report)  # the more common trigger - must not raise
    assert "No shell access obtained" in out
    assert "Privilege Escalation Simulation was not executed" in out


# --- fully skipped/empty report --------------------------------------------
def test_render_all_modules_skipped():
    report = Report(
        target="localhost:8080",
        config=ScanConfig(target="localhost:8080", modules=[Module.RECON]),
        recon=ReconFindings.skipped(target="localhost:8080", reason="offline"),
        privesc=PrivescFindings.skipped(reason="skip"),
        log_analysis=LogFindings.skipped(source="localhost", reason="skip"),
        fuzzer=FuzzerFindings.skipped(target="localhost:8080", reason="skip"),
    )
    out = render(report)
    assert "localhost:8080" in out


def test_html_variant_renders():
    report = Report(
        target="localhost:8080",
        config=_config(fmt=ReportFormat.HTML),
        recon=_full_recon(),
        privesc=PrivescFindings.skipped(reason="skip"),
        log_analysis=LogFindings.skipped(source="localhost", reason="skip"),
    )
    out = render(report)
    assert "<html" in out.lower()
    assert "PrivEsc" in out


# --- redaction regression (Section 0.1 item 9) -----------------------------
def test_rendered_report_never_contains_raw_cookie():
    secret = "abcdef0123456789deadbeef"
    cookie = f"PHPSESSID={secret}"
    recon = _full_recon()
    recon.web_headers = WebHeaders(
        url="http://localhost:8080",
        is_online=True,
        headers={"Server": "Apache", "Set-Cookie": f"{cookie}; path=/; HttpOnly"},
    )
    report = Report(
        target="localhost:8080",
        config=_config(cookie=cookie),
        recon=recon,
        privesc=PrivescFindings.skipped(reason="skip"),
        log_analysis=LogFindings.skipped(source="localhost", reason="skip"),
    )
    out = render(report)
    assert secret not in out


def test_generate_report_writes_file(tmp_path):
    report = Report(
        target="localhost:8080",
        config=_config(),
        recon=_full_recon(),
        privesc=PrivescFindings.skipped(reason="skip"),
        log_analysis=LogFindings.skipped(source="localhost", reason="skip"),
    )
    path = generate_report(report, output_dir=str(tmp_path))
    assert path.endswith(".md")
    assert (tmp_path / "report_localhost_8080.md").exists()
