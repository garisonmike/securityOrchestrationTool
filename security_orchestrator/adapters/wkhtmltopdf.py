"""
adapters.wkhtmltopdf
====================

Optional HTML->PDF conversion. Injectable ``runner`` / ``which``. A missing
binary is a routine ``err`` (PDF is a nice-to-have, the HTML report already
exists), not a crash - the report generator treats an ``err`` here as
"skip the PDF".
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Callable, Optional

from security_orchestrator.core.result import Result

_TIMEOUT_SECONDS = 120


class WkhtmltopdfAdapter:
    def __init__(
        self,
        runner: Callable = subprocess.run,
        which: Callable[[str], Optional[str]] = shutil.which,
    ) -> None:
        self._runner = runner
        self._which = which

    def convert(self, html_path: str, pdf_path: str) -> Result[str]:
        binary = self._which("wkhtmltopdf")
        if binary is None:
            return Result.err("wkhtmltopdf not found in PATH")

        cmd = [binary, "--quiet", html_path, pdf_path]
        try:
            proc = self._runner(cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return Result.err(f"wkhtmltopdf timed out after {_TIMEOUT_SECONDS}s")
        except Exception as exc:  # noqa: BLE001 - boundary
            return Result.err(f"wkhtmltopdf execution failed: {type(exc).__name__}: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            return Result.err(f"wkhtmltopdf exited {proc.returncode}: {detail}")

        return Result.ok(pdf_path)
