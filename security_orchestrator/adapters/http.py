"""
adapters.http
=============

Thin wrapper around an HTTP GET. Like every adapter here it takes an
injectable ``runner`` (defaulting to the real ``requests.get``) and returns
a ``Result`` - a routine network failure (host down, timeout) is an
``err``, not an exception the caller must catch.

This module also owns :func:`body_looks_like_html`, the fix for bug #3
(plan.md Section 0, item 3). The legacy active-probe filter decided whether
a 200 response was a "real file" by checking ``'<html' not in
resp.text[:50].lower()``. A realistic app - DVWA serves a long XHTML 1.0
Transitional doctype - pushes the actual ``<html`` tag past character 50,
so the page was misclassified as a downloadable file and the tool reported
finding CHANGELOG.md / README.txt / .env that were really just the app's
normal page. The fix scans a generous window, not a fixed 50 chars.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from security_orchestrator.core.result import Result

# Characters of the body to inspect when deciding "is this an HTML page?".
# Comfortably larger than any real doctype+head, unlike the legacy 50.
_HTML_SCAN_WINDOW = 2048


@dataclass
class HttpResponse:
    """Normalized view of an HTTP response, independent of requests."""

    status_code: int
    text: str
    headers: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    elapsed_seconds: float = 0.0
    history_len: int = 0
    redirect_location: Optional[str] = None


def body_looks_like_html(text: str) -> bool:
    """True if ``text`` appears to be an HTML document.

    Scans a generous leading window for an ``<html`` tag or an HTML doctype,
    so a long doctype declaration can't hide the ``<html`` tag out of view
    the way the legacy fixed-50-char check allowed (bug #3).
    """

    if not text:
        return False
    window = text[:_HTML_SCAN_WINDOW].lower()
    return "<html" in window or "<!doctype html" in window


def _default_runner(url, headers, allow_redirects, timeout, verify):  # pragma: no cover - real network
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return requests.get(
        url,
        headers=headers,
        allow_redirects=allow_redirects,
        timeout=timeout,
        verify=verify,
    )


def _to_response(raw, requested_url: str) -> HttpResponse:
    history = getattr(raw, "history", []) or []
    elapsed = getattr(raw, "elapsed", None)
    elapsed_seconds = elapsed.total_seconds() if elapsed is not None and hasattr(elapsed, "total_seconds") else float(getattr(raw, "elapsed_seconds", 0.0) or 0.0)
    headers = dict(getattr(raw, "headers", {}) or {})
    return HttpResponse(
        status_code=int(getattr(raw, "status_code")),
        text=getattr(raw, "text", "") or "",
        headers=headers,
        url=getattr(raw, "url", requested_url) or requested_url,
        elapsed_seconds=elapsed_seconds,
        history_len=len(history),
        redirect_location=headers.get("Location"),
    )


class HttpAdapter:
    """Performs HTTP GETs, translating network failures into ``Result.err``."""

    def __init__(self, runner: Optional[Callable] = None) -> None:
        self._runner = runner or _default_runner

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: float = 5.0,
        verify: bool = False,
    ) -> Result[HttpResponse]:
        try:
            raw = self._runner(
                url,
                headers=headers or {},
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=verify,
            )
        except Exception as exc:  # noqa: BLE001 - boundary: any I/O failure is a routine err
            return Result.err(f"HTTP request to {url} failed: {type(exc).__name__}: {exc}")
        try:
            return Result.ok(_to_response(raw, url))
        except Exception as exc:  # noqa: BLE001 - malformed/unexpected runner return
            return Result.err(f"HTTP response from {url} could not be parsed: {exc}")
