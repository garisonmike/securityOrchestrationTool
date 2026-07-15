"""
core.redact
===========

The redaction pass that runs over a ``Report`` before it reaches the render
layer. This replaces the orphaned ``main.py:redact_sensitive_data`` that was
written for exactly this purpose (its own comment cites "Issue #29") and
then wired up nowhere - while an unredacted live ``PHPSESSID`` cookie sat in
this repo's own committed report,
``reports/report_localhost_8080_dvwa_vulnerabilities_sqli_.md`` (plan.md
Section 0.1 item 9).

Redaction here is not the render layer's afterthought; it is a mandatory
step the generator calls on the dumped report *before* handing it to a
template. It works on the ``model_dump()`` dict (a plain nested structure of
dicts / lists / scalars) rather than on the typed model, so it can scrub
values wherever they appear - a ``Set-Cookie`` response header, a ``Cookie``
request header echoed into findings, a password in a credential string -
without needing to know which model field they came from.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"

# Header/field names whose entire value is sensitive and gets replaced wholesale.
_SENSITIVE_KEYS = {
    "set-cookie",
    "cookie",
    "password",
    "passwd",
    "pwd",
    "ssh_password",
    "authorization",
    "x-auth-token",
}

# Session-id assignments embedded inside a larger string (e.g. a header value
# or a log line): "PHPSESSID=abc123" -> "PHPSESSID=***REDACTED***".
_SESSION_ID_RE = re.compile(
    r"(?i)\b(PHPSESSID|JSESSIONID|SESSIONID|SESSION|SID|ASP\.NET_SessionId|security)="
    r"[^;\s\"']+"
)

# password/secret assignments embedded in free text.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)"
    r"(\s*[:=]\s*)"
    r"[^\s,;}\]\"']+"
)


def _scrub_string(value: str) -> str:
    value = _SESSION_ID_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
    value = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    return value


def redact(data: Any) -> Any:
    """Return a redacted deep copy of a JSON-like structure.

    - Any dict entry whose key names a sensitive field has its value replaced
      wholesale (matched case-insensitively, so ``Set-Cookie`` and
      ``set-cookie`` both hit).
    - Every remaining string is scrubbed for embedded session ids and
      secret assignments.
    - Lists and nested dicts are walked recursively.
    The input is never mutated.
    """

    if isinstance(data, dict):
        out = {}
        for key, val in data.items():
            if isinstance(key, str) and key.lower() in _SENSITIVE_KEYS and val is not None:
                out[key] = REDACTED
            else:
                out[key] = redact(val)
        return out
    if isinstance(data, list):
        return [redact(item) for item in data]
    if isinstance(data, str):
        return _scrub_string(data)
    return data
