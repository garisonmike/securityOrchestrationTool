"""
report.generator
================

Renders a typed ``Report`` to Markdown or HTML. Two invariants make this the
place the plan's crash and leak bugs die:

  * It renders against ``report.model_dump(mode="json")`` - a plain,
    JSON-safe nested structure whose every key the models guarantee exists in
    every variant. The template never touches a "sometimes absent" key, so
    the ``UndefinedError`` from the pasted run (privesc skipped, or log
    correlation skipped) cannot happen (plan.md Section 0 item 1 / Phase-5).

  * Redaction is a *mandatory step in this function*, run over the dumped
    report before it ever reaches a template (plan.md Section 0.1 item 9).
    There is no code path that renders un-redacted data.

Optional PDF conversion is delegated to an injected wkhtmltopdf adapter; a
missing binary just means "no PDF", never a failure.
"""

from __future__ import annotations

import os
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from security_orchestrator.core.models import Report, ReportFormat
from security_orchestrator.core.redact import redact

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def _clean_target(target: str) -> str:
    cleaned = target.replace("http://", "").replace("https://", "")
    for ch in (":", "/", "?", "&", "=", " "):
        cleaned = cleaned.replace(ch, "_")
    return cleaned.strip("_") or "target"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(report: Report) -> str:
    """Return the rendered report body as a string (redacted, no file I/O)."""
    # mode="json" serializes enums to their string values, so template
    # comparisons like status == "success" work and output reads cleanly.
    data = redact(report.model_dump(mode="json"))
    fmt = report.config.report_format
    template_name = "report.html.j2" if fmt is ReportFormat.HTML else "report.md.j2"
    template = _environment().get_template(template_name)
    return template.render(report=data)


def generate_report(
    report: Report,
    output_dir: str = "reports",
    wkhtmltopdf=None,
) -> str:
    """Render ``report`` to a file under ``output_dir`` and return its path.

    If the format is HTML and a wkhtmltopdf adapter is provided and succeeds,
    the PDF path is returned instead; otherwise the HTML/Markdown path is.
    """
    os.makedirs(output_dir, exist_ok=True)
    fmt = report.config.report_format
    ext = ".html" if fmt is ReportFormat.HTML else ".md"

    body = render(report)
    filename = f"report_{_clean_target(report.target)}{ext}"
    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(body)

    if fmt is ReportFormat.HTML and wkhtmltopdf is not None:
        pdf_path = os.path.join(output_dir, f"report_{_clean_target(report.target)}.pdf")
        result = wkhtmltopdf.convert(output_path, pdf_path)
        if result.is_ok and os.path.exists(result.value):
            return result.value

    return output_path
