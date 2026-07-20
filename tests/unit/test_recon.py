"""Phase 3 tests for the recon module."""

from datetime import datetime

from security_orchestrator.adapters.fakes import (
    FakeGobusterAdapter,
    FakeHttpAdapter,
    FakeNmapAdapter,
    FakeSearchsploitAdapter,
)
from security_orchestrator.adapters.http import HttpResponse
from security_orchestrator.adapters.nmap import NmapScan
from security_orchestrator.core.models import (
    Module,
    ModuleStatus,
    OpsecLevel,
    ScanConfig,
    TechStack,
)
from security_orchestrator.core.result import Result
from security_orchestrator.modules.recon import (
    ReconModule,
    clean_target_for_nmap,
    detect_dvwa_level_from_cookie,
    extract_searchsploit_queries,
    filter_searchsploit_results,
    format_target_for_web,
    parse_error_body_backend,
    parse_stealth_stack,
)

DVWA_DOCTYPE = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'
    '<html xmlns="http://www.w3.org/1999/xhtml"><head><title>DVWA</title></head><body>x</body></html>'
)


# --- pure helpers ----------------------------------------------------------
def test_target_cleaners():
    assert clean_target_for_nmap("http://localhost:8080/") == "localhost:8080"
    assert format_target_for_web("localhost:8080") == "http://localhost:8080"
    assert format_target_for_web("https://x") == "https://x"


def test_extract_searchsploit_queries():
    stack = TechStack(web_server=["Apache/2.4.41 (Ubuntu)"], backend=["PHP"])
    queries = extract_searchsploit_queries(stack)
    assert "Apache 2.4.41" in queries
    assert "PHP" in queries


def test_filter_searchsploit_recency_and_dedup():
    now = datetime(2026, 1, 1)
    results = [
        {"Title": "Old exploit CVE-2010-1111", "Date_Published": "2010-01-01"},
        {"Title": "Recent CVE-2025-2222", "Date_Published": "2025-06-01"},
        {"Title": "Dup CVE-2025-2222", "Date_Published": "2025-07-01"},
    ]
    filtered = filter_searchsploit_results(results, "apache 2.4", now=now)
    titles = [r["Title"] for r in filtered]
    assert "Old exploit CVE-2010-1111" not in titles  # older than 5 years
    assert titles.count("Recent CVE-2025-2222") == 1   # dedup by CVE
    assert "Dup CVE-2025-2222" not in titles


def test_filter_searchsploit_does_not_mutate_input():
    records = [{"Title": "x", "Date_Published": "2025-01-01"}]
    filter_searchsploit_results(records, "q", now=datetime(2026, 1, 1))
    assert "_priority" not in records[0]


def test_detect_dvwa_level_from_cookie():
    assert detect_dvwa_level_from_cookie("PHPSESSID=x; security=low").level == "low"
    assert detect_dvwa_level_from_cookie("PHPSESSID=x").detected is False
    assert detect_dvwa_level_from_cookie(None).detected is False


def test_parse_stealth_stack_reads_headers_and_meta():
    stack = parse_stealth_stack(
        {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"},
        '<meta name="generator" content="WordPress 6.0"> _next/static data-reactroot',
    )
    assert "Apache/2.4.41" in stack.web_server
    assert "PHP/7.4" in stack.backend
    assert "WordPress 6.0" in stack.frontend
    assert "Next.js" in stack.frontend
    assert "React" in stack.frontend


def test_parse_error_body_backend_is_structured_only():
    # Only known frameworks are extracted - never arbitrary tool chatter.
    found = parse_error_body_backend("... Apache Tomcat/9.0.1 ... Django ...")
    assert "Apache Tomcat 9.0.1" in found
    assert "Django" in found
    assert parse_error_body_backend("Couldn't determine the underlying framework") == []


# --- module.run: helpers ---------------------------------------------------
def _http_for(pages):
    """pages: dict url -> HttpResponse. Missing urls -> connection error."""
    return FakeHttpAdapter(
        handler=lambda url, headers, allow_redirects: (
            Result.ok(pages[url]) if url in pages else Result.err("connection refused")
        )
    )


def _config(opsec=OpsecLevel.STEALTH, cookie=None):
    return ScanConfig(
        target="localhost:8080",
        modules=[Module.RECON],
        opsec_level=opsec,
        cookie=cookie,
    )


def test_run_offline_target_is_error_status():
    http = FakeHttpAdapter(handler=lambda u, h, a: Result.err("host down"))
    module = ReconModule(http, FakeNmapAdapter(), FakeGobusterAdapter(), FakeSearchsploitAdapter())
    findings = module.run(_config())
    assert findings.status is ModuleStatus.ERROR
    assert findings.web_headers.is_online is False


def test_run_stealth_success_skips_gobuster():
    page = HttpResponse(status_code=200, text="<html></html>", headers={"Server": "Apache/2.4.41"}, url="http://localhost:8080")
    http = _http_for({"http://localhost:8080": page})
    module = ReconModule(
        http,
        FakeNmapAdapter(Result.ok(NmapScan(raw_output="scan", command="nmap ...", skip_ping_used=True))),
        FakeGobusterAdapter(),
        FakeSearchsploitAdapter(),
    )
    findings = module.run(_config(OpsecLevel.STEALTH))
    assert findings.status is ModuleStatus.SUCCESS
    assert findings.gobuster_scan.status is ModuleStatus.SKIPPED
    assert findings.nmap_scan.status is ModuleStatus.SUCCESS


def test_bug2_nmap_raw_text_never_enters_tech_stack():
    # nmap returns noisy NSE chatter; it must stay in nmap_scan.raw_output only.
    noise = "Couldn't determine the underlying framework Werkzeug Django nmap junk"
    page = HttpResponse(status_code=200, text="<html></html>", headers={"Server": "Apache"}, url="http://localhost:8080")
    err_page = HttpResponse(status_code=404, text="not found", headers={}, url="x")
    http = _http_for({
        "http://localhost:8080": page,
        "http://localhost:8080/invalid_path_for_error_123_%ff": err_page,
    })
    module = ReconModule(
        http,
        FakeNmapAdapter(Result.ok(NmapScan(raw_output=noise, command="nmap", skip_ping_used=True))),
        FakeGobusterAdapter(),
        FakeSearchsploitAdapter(),
    )
    findings = module.run(_config(OpsecLevel.NOISY))
    stack = findings.hierarchical_stack
    joined = " ".join(stack.frontend + stack.web_server + stack.backend + stack.database + stack.active_probes)
    assert "Couldn't determine" not in joined
    assert noise in (findings.nmap_scan.raw_output or "")


def test_bug3_html_page_at_probe_path_is_not_reported_as_file():
    # Every probed file path returns the app's normal (long-doctype) HTML page.
    base = "http://localhost:8080"
    pages = {base: HttpResponse(status_code=200, text=DVWA_DOCTYPE, headers={"Server": "Apache"}, url=base)}
    for fname in ("CHANGELOG.md", "README.txt", "package.json", ".env"):
        pages[f"{base}/{fname}"] = HttpResponse(status_code=200, text=DVWA_DOCTYPE, headers={}, url=base)
    pages[f"{base}/invalid_path_for_error_123_%ff"] = HttpResponse(status_code=404, text="nope", headers={}, url=base)
    http = _http_for(pages)
    module = ReconModule(http, FakeNmapAdapter(Result.err("nmap not found in PATH")), FakeGobusterAdapter(), FakeSearchsploitAdapter())
    findings = module.run(_config(OpsecLevel.NOISY))
    # None of the probe files should be reported found - they were all the HTML page.
    assert findings.hierarchical_stack.active_probes == []


def test_run_populates_searchsploit_from_stack():
    base = "http://localhost:8080"
    page = HttpResponse(status_code=200, text="<html></html>", headers={"Server": "Apache/2.4.41"}, url=base)
    http = _http_for({base: page})
    sploit = FakeSearchsploitAdapter(
        results_by_query={"Apache 2.4.41": [{"Title": "Apache RCE CVE-2025-1", "Date_Published": "2025-01-01"}]}
    )
    module = ReconModule(http, FakeNmapAdapter(Result.err("nmap not found in PATH")), FakeGobusterAdapter(), sploit)
    findings = module.run(_config(OpsecLevel.STEALTH))
    assert "Apache 2.4.41" in findings.searchsploit_results
