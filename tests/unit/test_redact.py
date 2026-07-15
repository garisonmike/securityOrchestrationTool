"""Phase 1 tests for the redaction pass.

Regression target: plan.md Section 0.1 item 9 - a live PHPSESSID cookie
was committed unredacted in this repo's own reports/ folder. A Report built
from a fixture carrying a real-shaped Set-Cookie header must never expose
that cookie value after redact().
"""

from security_orchestrator.core.models import (
    ModuleStatus,
    Module,
    ReconFindings,
    Report,
    ScanConfig,
    WebHeaders,
)
from security_orchestrator.core.redact import REDACTED, redact


def _report_with_cookie(cookie_value="PHPSESSID=abcdef0123456789deadbeef"):
    headers = {
        "Server": "Apache/2.4.41",
        "Set-Cookie": f"{cookie_value}; path=/; HttpOnly",
    }
    cfg = ScanConfig(
        target="localhost:8080",
        modules=[Module.RECON],
        cookie=cookie_value,
    )
    return Report(
        target="localhost:8080",
        config=cfg,
        recon=ReconFindings(
            status=ModuleStatus.SUCCESS,
            target="localhost:8080",
            web_headers=WebHeaders(
                url="http://localhost:8080",
                is_online=True,
                headers=headers,
            ),
        ),
    ), cookie_value


def test_set_cookie_header_value_is_removed():
    report, cookie_value = _report_with_cookie()
    raw_secret = cookie_value.split("=", 1)[1]  # abcdef0123456789deadbeef

    dumped = report.model_dump()
    # sanity: the secret really is present before redaction
    assert raw_secret in str(dumped)

    cleaned = redact(dumped)
    assert raw_secret not in str(cleaned)
    assert cleaned["recon"]["web_headers"]["headers"]["Set-Cookie"] == REDACTED


def test_config_cookie_field_is_redacted():
    report, cookie_value = _report_with_cookie()
    raw_secret = cookie_value.split("=", 1)[1]
    cleaned = redact(report.model_dump())
    assert raw_secret not in str(cleaned["config"])


def test_embedded_session_id_in_free_text_is_scrubbed():
    text = "GET /login.php HTTP/1.1 Cookie header PHPSESSID=SUPERSECRETVALUE served"
    scrubbed = redact(text)
    assert "SUPERSECRETVALUE" not in scrubbed
    assert "PHPSESSID=" + REDACTED in scrubbed


def test_password_assignment_in_text_is_scrubbed():
    scrubbed = redact({"message": "found default credentials root:hunter2", "password": "hunter2"})
    # whole-value key redaction
    assert scrubbed["password"] == REDACTED
    # embedded assignment form
    scrubbed2 = redact("connecting with password=hunter2 now")
    assert "hunter2" not in scrubbed2


def test_redact_does_not_mutate_input():
    original = {"Set-Cookie": "PHPSESSID=keepme"}
    _ = redact(original)
    assert original["Set-Cookie"] == "PHPSESSID=keepme"


def test_non_sensitive_data_survives():
    data = {"Server": "Apache/2.4.41", "status_code": 200, "paths": ["/a", "/b"]}
    assert redact(data) == data
