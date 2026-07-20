"""
modules.fuzzer
==============

Web vulnerability fuzzing rebuilt on the http + nuclei adapters.

Nuclei tag selection - previously observable only by reading console output -
is the pure function :func:`select_nuclei_tags`, with one test per tech-stack
keyword branch. The custom polyglot/SQLi fuzzer drives the http adapter, so
its error-based, reflected-XSS and time-based detections are all testable
against canned responses (including a slow response for the time-based path)
without a live target.
"""

from __future__ import annotations

import re
from typing import List, Optional

from security_orchestrator.core.models import (
    CustomFuzzerResult,
    FuzzerFindings,
    ModuleStatus,
    NucleiMeta,
    NucleiResult,
    Profile,
    ScanConfig,
    TechStack,
)

_DB_ERROR_REGEXES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PostgreSQL query failed",
    r"ORA-[0-9]{4}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver",
    r"Syntax error in string in query expression",
]

_XSS_MARKER = "NCI_HACKATHON"
_TIME_PAYLOADS = ["1' OR SLEEP(5)--", "1' OR pg_sleep(5)--"]
_TIME_THRESHOLD_SECONDS = 4.5


def format_target_for_web(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def validate_cookie_format(cookie: str) -> bool:
    return bool(re.match(r"^([a-zA-Z0-9_]+=[^;]+)(;[ ]?[a-zA-Z0-9_]+=[^;]+)*$", cookie))


def select_nuclei_tags(tech_stack: Optional[TechStack], profile: Profile) -> List[str]:
    """Auto-select nuclei template tags from the detected tech stack.

    Deterministic and order-stable (returns a sorted list) so tests can
    assert on exact membership per keyword branch (legacy Issues #35/#31).
    """
    components: List[str] = []
    if tech_stack is not None:
        for items in (
            tech_stack.frontend,
            tech_stack.web_server,
            tech_stack.backend,
            tech_stack.database,
            tech_stack.active_probes,
        ):
            components.extend(item.lower() for item in items)
    tech_string = " ".join(components)

    if not tech_string.strip():
        return ["cve", "exposure", "misconfig"]

    tags: set = {"exposure", "misconfig"}

    if "apache" in tech_string:
        tags.update(["apache", "httpd", "cve"])
    if "php" in tech_string:
        tags.update(["php", "sqli", "xss", "rce"])
    if "nginx" in tech_string:
        tags.add("nginx")
    if any(db in tech_string for db in ("mysql", "mariadb", "postgres", "mongodb")):
        tags.update(["sqli", "db"])
    if "wordpress" in tech_string or "wp-" in tech_string:
        tags.update(["wordpress", "wp-plugin"])
    if "joomla" in tech_string:
        tags.add("joomla")
    if "drupal" in tech_string:
        tags.add("drupal")
    if any(js in tech_string for js in ("react", "vue", "angular", "next")):
        tags.update(["js", "xss"])

    if tags == {"exposure", "misconfig"}:
        tags.update(["cve", "generic"])

    return sorted(tags)


class FuzzerModule:
    def __init__(self, http, nuclei) -> None:
        self.http = http
        self.nuclei = nuclei

    def run(
        self,
        config: ScanConfig,
        tech_stack: Optional[TechStack] = None,
    ) -> FuzzerFindings:
        target = config.target
        cookie = config.cookie
        findings = FuzzerFindings(status=ModuleStatus.SUCCESS, target=target)

        if cookie and not validate_cookie_format(cookie):
            findings.errors.append("Invalid cookie format detected. Cookie injection skipped.")
            cookie = None

        findings.nuclei_scan = self._run_nuclei(target, config.profile, tech_stack, cookie)
        findings.custom_fuzzer = self.custom_fuzzer(target, cookie)
        findings.dependencies = {
            "nuclei": findings.nuclei_scan.status is not ModuleStatus.SKIPPED
        }
        return findings

    def _run_nuclei(
        self,
        target: str,
        profile: Profile,
        tech_stack: Optional[TechStack],
        cookie: Optional[str],
    ) -> NucleiResult:
        web_target = format_target_for_web(target)
        tags = select_nuclei_tags(tech_stack, profile)
        severity = "critical,high,medium" if profile is Profile.NOISY else "critical,high"

        result = self.nuclei.scan(web_target, tags=tags, severity=severity, cookie=cookie)
        if result.is_err:
            # A missing binary is a skip; any other execution failure is an error.
            status = ModuleStatus.SKIPPED if "not found" in result.error else ModuleStatus.ERROR
            return NucleiResult(status=status, reason=result.error)

        scan = result.value
        meta = NucleiMeta(
            tags_used=tags,
            tags_string=",".join(tags) if tags else "none",
            templates_matched=len(scan.findings),
            severity_filter=severity,
            tech_stack_received=tech_stack is not None
            and any((tech_stack.frontend, tech_stack.web_server, tech_stack.backend, tech_stack.database)),
            tech_stack_keys=["frontend", "web_server", "backend", "database"]
            if tech_stack is not None
            else [],
        )
        nuclei_result = NucleiResult(
            status=ModuleStatus.SUCCESS, findings=scan.findings, meta=meta
        )
        if not scan.findings:
            nuclei_result.warning = (
                f"Nuclei returned 0 findings (tags: {meta.tags_string}). "
                "Templates may be unavailable or the target has no matching vulnerabilities."
            )
        return nuclei_result

    def custom_fuzzer(self, target: str, cookie: Optional[str]) -> CustomFuzzerResult:
        web_target = format_target_for_web(target)
        findings = CustomFuzzerResult()
        headers = {"Cookie": cookie} if cookie else {}
        test_url = web_target if "?" in web_target else f"{web_target}?q="

        # Bail out early if the target redirects unauthenticated traffic to login.
        probe = self.http.get(test_url, headers=headers, allow_redirects=False, timeout=10)
        if probe.is_ok and probe.value.status_code in (301, 302, 303, 307, 308):
            loc = (probe.value.redirect_location or "").lower()
            if any(p in loc for p in ("/login", "/signin", "/auth")):
                findings.warnings.append(
                    f"Target requires authentication (redirect to {probe.value.redirect_location}). "
                    "Provide a session cookie for full coverage."
                )
                return findings
        elif probe.is_err:
            findings.errors.append(f"Authentication check request failed: {probe.error}")

        self._detect_error_based(findings, test_url, headers)
        self._detect_time_based(findings, test_url, headers)
        return findings

    def _detect_error_based(self, findings: CustomFuzzerResult, test_url: str, headers: dict) -> None:
        payload = f"'\"><svg/onload=alert('{_XSS_MARKER}')> OR 1=1; --"
        resp = self.http.get(f"{test_url}{payload}", headers=headers, timeout=10)
        if resp.is_err:
            findings.errors.append(f"Polyglot fuzzing request failed: {resp.error}")
            return
        body = resp.value.text
        if _XSS_MARKER in body and re.search(rf"alert\('{_XSS_MARKER}'\)", body):
            findings.xss.append(f"Highly likely XSS: unmodified payload reflection at {test_url}")
        for db_err in _DB_ERROR_REGEXES:
            if re.search(db_err, body, re.IGNORECASE):
                findings.sqli_error.append(f"Database error leaked matching '{db_err}' structure.")
                break

    def _detect_time_based(self, findings: CustomFuzzerResult, test_url: str, headers: dict) -> None:
        for payload in _TIME_PAYLOADS:
            baseline = self.http.get(f"{test_url}1", headers=headers, timeout=10)
            if baseline.is_err:
                findings.errors.append(f"Time-based baseline request failed: {baseline.error}")
                continue
            baseline_time = baseline.value.elapsed_seconds

            attack = self.http.get(f"{test_url}{payload}", headers=headers, timeout=15)
            if attack.is_err:
                # A timeout here is itself a weak time-based SQLi signal.
                findings.sqli_time.append(
                    f"Request failed/timed out with payload '{payload}'. Potential time-based SQLi."
                )
                continue
            attack_time = attack.value.elapsed_seconds
            if attack_time >= _TIME_THRESHOLD_SECONDS and attack_time >= baseline_time + _TIME_THRESHOLD_SECONDS:
                findings.sqli_time.append(
                    f"Potential time-based SQLi: payload '{payload}' delayed response by {attack_time:.1f}s."
                )
