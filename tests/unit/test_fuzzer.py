"""Phase 3 tests for the fuzzer module."""

from security_orchestrator.adapters.fakes import FakeHttpAdapter, FakeNucleiAdapter
from security_orchestrator.adapters.http import HttpResponse
from security_orchestrator.adapters.nuclei import NucleiScan
from security_orchestrator.core.models import (
    Module,
    ModuleStatus,
    Profile,
    ScanConfig,
    TechStack,
)
from security_orchestrator.core.result import Result
from security_orchestrator.modules.fuzzer import (
    FuzzerModule,
    select_nuclei_tags,
    validate_cookie_format,
)


# --- tag selection: one assertion per keyword branch -----------------------
def test_tags_empty_stack_defaults():
    assert select_nuclei_tags(None, Profile.STEALTH) == ["cve", "exposure", "misconfig"]
    assert select_nuclei_tags(TechStack(), Profile.STEALTH) == ["cve", "exposure", "misconfig"]


def test_tags_apache_branch():
    tags = select_nuclei_tags(TechStack(web_server=["Apache/2.4.41"]), Profile.STEALTH)
    assert {"apache", "httpd", "cve"} <= set(tags)


def test_tags_php_branch():
    tags = select_nuclei_tags(TechStack(backend=["PHP/7.4"]), Profile.STEALTH)
    assert {"php", "sqli", "xss", "rce"} <= set(tags)


def test_tags_nginx_branch():
    assert "nginx" in select_nuclei_tags(TechStack(web_server=["nginx"]), Profile.STEALTH)


def test_tags_database_branch():
    tags = select_nuclei_tags(TechStack(database=["MySQL"]), Profile.STEALTH)
    assert {"sqli", "db"} <= set(tags)


def test_tags_wordpress_branch():
    tags = select_nuclei_tags(TechStack(frontend=["WordPress 6.0"]), Profile.STEALTH)
    assert {"wordpress", "wp-plugin"} <= set(tags)


def test_tags_js_framework_branch():
    tags = select_nuclei_tags(TechStack(frontend=["React"]), Profile.STEALTH)
    assert {"js", "xss"} <= set(tags)


def test_tags_are_sorted_and_deterministic():
    stack = TechStack(web_server=["Apache"], backend=["PHP"])
    assert select_nuclei_tags(stack, Profile.STEALTH) == sorted(select_nuclei_tags(stack, Profile.STEALTH))


def test_validate_cookie_format():
    assert validate_cookie_format("PHPSESSID=abc123; security=low")
    assert not validate_cookie_format("not a cookie!!")


# --- run ------------------------------------------------------------------
def _cfg(cookie=None, profile=Profile.STEALTH):
    return ScanConfig(target="localhost:8080", modules=[Module.FUZZER], cookie=cookie, profile=profile)


def test_run_nuclei_missing_is_skipped_not_error():
    http = FakeHttpAdapter(default=Result.ok(HttpResponse(status_code=200, text="ok")))
    module = FuzzerModule(http, FakeNucleiAdapter(Result.err("nuclei not found in PATH")))
    findings = module.run(_cfg())
    assert findings.nuclei_scan.status is ModuleStatus.SKIPPED


def test_run_nuclei_success_sets_severity_by_profile():
    http = FakeHttpAdapter(default=Result.ok(HttpResponse(status_code=200, text="ok")))
    nuclei = FakeNucleiAdapter(Result.ok(NucleiScan(findings=[{"template-id": "x"}])))
    module = FuzzerModule(http, nuclei)
    findings = module.run(_cfg(profile=Profile.NOISY))
    assert findings.nuclei_scan.status is ModuleStatus.SUCCESS
    assert findings.nuclei_scan.meta.severity_filter == "critical,high,medium"
    assert findings.nuclei_scan.meta.templates_matched == 1


def test_run_invalid_cookie_is_recorded_and_dropped():
    http = FakeHttpAdapter(default=Result.ok(HttpResponse(status_code=200, text="ok")))
    module = FuzzerModule(http, FakeNucleiAdapter(Result.ok(NucleiScan())))
    findings = module.run(_cfg(cookie="totally invalid!!"))
    assert any("Invalid cookie" in e for e in findings.errors)


def test_custom_fuzzer_detects_error_based_sqli_and_xss():
    marker = "NCI_HACKATHON"
    reflected = f"<svg/onload=alert('{marker}')> SQL syntax error near MySQL"
    http = FakeHttpAdapter(default=Result.ok(HttpResponse(status_code=200, text=reflected)))
    module = FuzzerModule(http, FakeNucleiAdapter(Result.err("nuclei not found in PATH")))
    result = module.custom_fuzzer("localhost:8080", cookie=None)
    assert result.xss
    assert result.sqli_error


def test_custom_fuzzer_detects_time_based_sqli():
    # Baseline fast, attack slow (>4.5s over baseline) -> time-based signal.
    def handler(url, headers, allow_redirects):
        if "SLEEP" in url or "pg_sleep" in url:
            return Result.ok(HttpResponse(status_code=200, text="", elapsed_seconds=5.2))
        return Result.ok(HttpResponse(status_code=200, text="", elapsed_seconds=0.1))

    http = FakeHttpAdapter(handler=handler)
    module = FuzzerModule(http, FakeNucleiAdapter(Result.err("nuclei not found in PATH")))
    result = module.custom_fuzzer("localhost:8080", cookie=None)
    assert result.sqli_time


def test_custom_fuzzer_stops_on_login_redirect():
    def handler(url, headers, allow_redirects):
        return Result.ok(HttpResponse(status_code=302, text="", headers={"Location": "/login.php"}))

    # give the redirect a Location the response object exposes
    def handler2(url, headers, allow_redirects):
        r = HttpResponse(status_code=302, text="", headers={"Location": "/login.php"})
        r.redirect_location = "/login.php"
        return Result.ok(r)

    http = FakeHttpAdapter(handler=handler2)
    module = FuzzerModule(http, FakeNucleiAdapter(Result.err("nuclei not found in PATH")))
    result = module.custom_fuzzer("localhost:8080", cookie=None)
    assert result.warnings
    assert not result.xss and not result.sqli_error
