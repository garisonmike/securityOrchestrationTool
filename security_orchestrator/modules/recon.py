"""
modules.recon
=============

Reconnaissance rebuilt on Phase-2 adapters. Every external call goes through
an injected adapter that returns structured data, so:

  * bug #2 (plan.md Section 0 item 2) is closed by construction - raw nmap
    stdout is only ever stored in ``NmapResult.raw_output``; it is never
    scraped into a tech-stack field. Framework detection now comes from the
    forced-error HTTP response body (structured extraction), not from
    quoting nmap's NSE help text.
  * bug #3 (plan.md Section 0 item 3) is closed by using
    ``adapters.http.body_looks_like_html`` - which scans a generous window,
    not a fixed 50 chars - to decide whether an active-probe hit is a real
    file or just the app's normal HTML page.

The pure decision logic (query extraction, searchsploit filtering, DVWA
level parsing, fingerprint parsing) lives in module-level functions so each
can be unit-tested without any adapter at all.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from security_orchestrator.adapters.http import body_looks_like_html
from security_orchestrator.core.models import (
    DvwaSecurityLevel,
    GobusterResult,
    ModuleStatus,
    NmapResult,
    OpsecLevel,
    Profile,
    ReconFindings,
    ScanConfig,
    SearchsploitResult,
    TechStack,
    WebHeaders,
)

_LOGIN_REDIRECT_PATTERNS = ["/login", "/signin", "/auth", "?redirect=", "/accounts/login"]
_SESSION_COOKIE_HINTS = ["phpsessid", "sessionid", "jsessionid", "session"]
_COMMON_PROBE_FILES = ["CHANGELOG.md", "README.txt", "package.json", ".env"]
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


# ---------------------------------------------------------------------------
# Pure helpers (no adapters).
# ---------------------------------------------------------------------------
def clean_target_for_nmap(target: str) -> str:
    return re.sub(r"^https?://", "", target).rstrip("/")


def format_target_for_web(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def extract_searchsploit_queries(stack: TechStack) -> List[str]:
    """Build searchsploit query strings from detected components."""
    queries: set = set()
    for items in (stack.frontend, stack.web_server, stack.backend, stack.database):
        for item in items:
            parts = item.replace("/", " ").replace("(", "").replace(")", "").split()
            if len(parts) >= 2:
                queries.add(f"{parts[0]} {parts[1]}")
            elif parts:
                queries.add(parts[0])
    return sorted(queries)


def filter_searchsploit_results(
    results: List[Dict],
    query: str,
    now: Optional[datetime] = None,
    max_age_years: int = 5,
    limit: int = 5,
) -> List[Dict]:
    """Keep recent, de-duplicated, relevance-tagged exploits (legacy Issue #28).

    ``now`` is injectable so the recency window is deterministic in tests.
    """
    now = now or datetime.now()
    cutoff = now - timedelta(days=365 * max_age_years)

    filtered: List[Dict] = []
    seen_cves: set = set()

    for result in results:
        result = dict(result)  # never mutate caller's records
        date_str = result.get("Date_Published", "")
        if date_str:
            exploit_date = _parse_exploit_date(date_str, cutoff)
            if exploit_date < cutoff:
                continue

        title = result.get("Title", "")
        cve_match = re.search(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

        verified = result.get("Verified", "0") == "1"
        result["verified"] = verified
        result["_priority"] = 1 if verified else 2

        q_versions = re.findall(r"\d+\.\d+", query.lower())
        t_versions = re.findall(r"\d+\.\d+", title.lower())
        if q_versions and t_versions and not any(qv in t_versions for qv in q_versions):
            result["version_mismatch"] = True

        filtered.append(result)

    filtered.sort(key=lambda r: (r.get("_priority", 2), _sort_date_key(r)))
    return filtered[:limit]


def _parse_exploit_date(date_str: str, cutoff: datetime) -> datetime:
    try:
        if len(date_str) == 10 and "-" in date_str:
            return datetime.strptime(date_str, "%Y-%m-%d")
        if len(date_str) == 8:
            return datetime.strptime(date_str, "%Y%m%d")
    except ValueError:
        pass
    # Unknown/unparseable format: don't let it fail the recency filter.
    return cutoff + timedelta(days=1)


def _sort_date_key(result: Dict) -> float:
    date_str = result.get("Date_Published", "")
    if date_str and len(date_str) == 10:
        try:
            return -datetime.strptime(date_str, "%Y-%m-%d").timestamp()
        except ValueError:
            return 0.0
    return 0.0


def detect_dvwa_level_from_cookie(cookie: Optional[str]) -> DvwaSecurityLevel:
    """Parse a DVWA ``security=<level>`` cookie value (legacy Issue #23)."""
    result = DvwaSecurityLevel()
    if not cookie:
        return result
    match = re.search(r"security=(\w+)", cookie, re.IGNORECASE)
    if match:
        level = match.group(1).lower()
        if level in ("low", "medium", "high", "impossible"):
            return DvwaSecurityLevel(
                detected=True,
                level=level,
                method="cookie",
                note=f"DVWA security level detected: {level} - certain vulnerability "
                f"classes may be filtered at this level.",
            )
    return result


def parse_stealth_stack(headers: Dict[str, str], html: str) -> TechStack:
    """Passive fingerprint from response headers + HTML (no active probing)."""
    stack = TechStack()
    if headers.get("Server"):
        stack.web_server.append(headers["Server"])
    if headers.get("X-Powered-By"):
        stack.backend.append(headers["X-Powered-By"])

    generator = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.I
    )
    if generator:
        stack.frontend.append(generator.group(1))
    if "_next/static" in html:
        stack.frontend.append("Next.js")
    if "data-reactroot" in html:
        stack.frontend.append("React")
    return stack


def parse_error_body_backend(body: str) -> List[str]:
    """Structured backend detection from a forced-error response body.

    This replaces the legacy path that dumped raw nmap NSE output into the
    backend field (bug #2). Only known, matched frameworks are returned.
    """
    found: List[str] = []
    tomcat = re.search(r"Apache Tomcat/([0-9.]+)", body)
    if tomcat:
        found.append(f"Apache Tomcat {tomcat.group(1)}")
    if "Werkzeug" in body or "Flask" in body:
        found.append("Werkzeug/Flask")
    if "Django" in body:
        found.append("Django")
    return found


def _dedupe_stack(stack: TechStack) -> TechStack:
    for name in ("frontend", "web_server", "backend", "database", "active_probes"):
        values = getattr(stack, name)
        seen: set = set()
        deduped = [v for v in values if not (v in seen or seen.add(v))]
        setattr(stack, name, deduped)
    return stack


# ---------------------------------------------------------------------------
# ReconModule - orchestrates the adapters into a ReconFindings.
# ---------------------------------------------------------------------------
class ReconModule:
    def __init__(self, http, nmap, gobuster, searchsploit) -> None:
        self.http = http
        self.nmap = nmap
        self.gobuster = gobuster
        self.searchsploit = searchsploit

    def grab_headers(self, target: str) -> WebHeaders:
        web = format_target_for_web(target)
        wh = WebHeaders(url=web)

        no_redirect = self.http.get(web, allow_redirects=False)
        if no_redirect.is_ok:
            resp = no_redirect.value
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = (resp.redirect_location or "").lower()
                if any(p in loc for p in _LOGIN_REDIRECT_PATTERNS):
                    wh.requires_auth = True
                    wh.auth_detection = {
                        "redirect_to": resp.redirect_location or "",
                        "status_code": str(resp.status_code),
                        "message": "Target redirects to login page - authentication required",
                    }

        full = self.http.get(web, allow_redirects=True)
        if full.is_err:
            wh.error = full.error
            return wh
        resp = full.value
        wh.is_online = True
        wh.status_code = resp.status_code
        wh.headers = resp.headers
        if resp.headers.get("Set-Cookie") and not wh.requires_auth:
            cookie_header = resp.headers["Set-Cookie"].lower()
            if any(h in cookie_header for h in _SESSION_COOKIE_HINTS) and resp.history_len > 0:
                wh.requires_auth = True
                wh.auth_detection = {
                    "session_cookie_detected": "true",
                    "redirects": str(resp.history_len),
                    "message": "Session cookie set with redirects - likely requires authentication",
                }
        return wh

    def _stealth_fingerprint(self, web_target: str) -> TechStack:
        resp = self.http.get(web_target)
        if resp.is_err:
            return TechStack(error=resp.error)
        return parse_stealth_stack(resp.value.headers, resp.value.text)

    def _noisy_fingerprint(self, web_target: str) -> TechStack:
        stack = TechStack()
        base = web_target.rstrip("/")

        for filename in _COMMON_PROBE_FILES:
            probe = self.http.get(f"{base}/{filename}", timeout=3)
            if probe.is_err:
                continue
            resp = probe.value
            # bug #3 fix: a 200 that is really the app's HTML page is NOT a file.
            if resp.status_code == 200 and resp.text and not body_looks_like_html(resp.text):
                stack.active_probes.append(f"Found {filename}: {resp.text[:100].strip()}...")

        error_probe = self.http.get(f"{base}/invalid_path_for_error_123_%ff")
        if error_probe.is_ok:
            resp = error_probe.value
            if resp.headers.get("Server"):
                stack.web_server.append(resp.headers["Server"])
            stack.backend.extend(parse_error_body_backend(resp.text))
        return stack

    def run(self, config: ScanConfig) -> ReconFindings:
        target = config.target
        web_target = format_target_for_web(target)
        nmap_target = clean_target_for_nmap(target)

        findings = ReconFindings(
            status=ModuleStatus.SUCCESS,
            target=target,
            profile=config.profile,
            opsec_level=config.opsec_level,
        )

        wh = self.grab_headers(target)
        findings.web_headers = wh
        if not wh.is_online:
            findings.status = ModuleStatus.ERROR
            findings.reason = wh.error or "Target appears offline or unreachable via HTTP"
            return findings

        if config.cookie:
            findings.dvwa_security_level = detect_dvwa_level_from_cookie(config.cookie)

        if config.opsec_level is OpsecLevel.STEALTH:
            stack = self._stealth_fingerprint(web_target)
        else:
            stack = self._noisy_fingerprint(web_target)
        findings.hierarchical_stack = _dedupe_stack(stack)

        findings.searchsploit_results = self._run_searchsploit(findings.hierarchical_stack)

        skip_ping = wh.is_online or nmap_target in _LOCAL_HOSTS
        findings.nmap_scan = self._to_nmap_result(
            self.nmap.scan(nmap_target, config.profile.value, skip_ping=skip_ping)
        )

        if config.opsec_level is OpsecLevel.STEALTH:
            findings.gobuster_scan = GobusterResult(
                status=ModuleStatus.SKIPPED,
                reason="Gobuster skipped in stealth mode to avoid noisy logs",
            )
        else:
            findings.gobuster_scan = self._to_gobuster_result(self.gobuster.enumerate(web_target))

        findings.dependencies = {
            "nmap": findings.nmap_scan.status is not ModuleStatus.ERROR
            or "not found" not in (findings.nmap_scan.reason or ""),
            "gobuster": findings.gobuster_scan.status is not ModuleStatus.ERROR
            or "not found" not in (findings.gobuster_scan.reason or ""),
        }
        return findings

    def _run_searchsploit(self, stack: TechStack) -> Dict[str, List[SearchsploitResult]]:
        out: Dict[str, List[SearchsploitResult]] = {}
        for query in extract_searchsploit_queries(stack):
            result = self.searchsploit.search(query)
            if result.is_err or not result.value:
                continue
            filtered = filter_searchsploit_results(result.value, query)
            if filtered:
                out[query] = [SearchsploitResult.model_validate(r) for r in filtered]
        return out

    @staticmethod
    def _to_nmap_result(result) -> NmapResult:
        if result.is_err:
            return NmapResult(status=ModuleStatus.ERROR, reason=result.error)
        scan = result.value
        return NmapResult(
            status=ModuleStatus.SUCCESS,
            raw_output=scan.raw_output,
            command_executed=scan.command,
            skip_ping_used=scan.skip_ping_used,
        )

    @staticmethod
    def _to_gobuster_result(result) -> GobusterResult:
        if result.is_err:
            return GobusterResult(status=ModuleStatus.ERROR, reason=result.error)
        scan = result.value
        return GobusterResult(
            status=ModuleStatus.SUCCESS,
            discovered_paths=scan.discovered_paths,
            raw_output=scan.raw_output,
        )
