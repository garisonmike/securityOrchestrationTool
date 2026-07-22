"""
report
======

Report rendering layer. `generator.py` will call `core.redact` before
`template.render()`, and `templates/` will hold the existing `.j2` files
once they are rendered against `model_dump()` of a typed `Report` instead
of raw findings dicts (plan.md Phase-5).

Populated in Phase 5. Empty in Phase 0.
"""

from security_orchestrator.report.generator import generate_report, render

__all__ = ["generate_report", "render"]
