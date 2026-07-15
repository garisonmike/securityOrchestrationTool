"""
security_orchestrator
=====================

Typed, tested rewrite of the flat `modules/`-based security orchestration
tool (see /plan.md for the full rewrite plan).

This package is being built up phase by phase alongside the legacy
`main.py` / `modules/` tree, which remains the working, runnable tool until
Phase 4's exit criterion passes end-to-end (see plan.md, Section 7,
"Migration approach"). Nothing in this package is wired up to the legacy
tool yet.

Phase status:
    Phase 0 (this phase): project scaffolding only. No behavior lives here.
    Phase 1: core/ contracts  (Result[T], exceptions, six pydantic models, redaction)
    Phase 2: adapters/        (http, nmap, gobuster, nuclei, ssh, searchsploit, wkhtmltopdf)
    Phase 3: modules/         (recon, fuzzer, privesc, log_analyzer)
    Phase 4: orchestrator.py, cli.py
    Phase 5: report/          (templates rendered from typed Report models)
"""

__version__ = "0.1.0"
