"""
Phase 0 smoke tests.

These are the only tests that exist at this phase. Their sole purpose is
to prove the harness itself works end to end - the package installs, every
sub-package imports cleanly, and `pytest` can find and run tests - so
Phase 0's exit criterion ("pytest is green in CI on a fresh clone, zero
manual setup steps") is something CI actually checks, not an assumption.

Real behavioral tests start in Phase 1 (tests/unit/test_models.py,
tests/unit/test_result.py, ...) once core/ has something to test.
"""

import importlib

import security_orchestrator


def test_package_version_is_set():
    assert isinstance(security_orchestrator.__version__, str)
    assert security_orchestrator.__version__


SUBMODULES = [
    "security_orchestrator.core",
    "security_orchestrator.core.models",
    "security_orchestrator.core.result",
    "security_orchestrator.core.exceptions",
    "security_orchestrator.core.redact",
    "security_orchestrator.adapters",
    "security_orchestrator.adapters.http",
    "security_orchestrator.adapters.nmap",
    "security_orchestrator.adapters.gobuster",
    "security_orchestrator.adapters.nuclei",
    "security_orchestrator.adapters.ssh",
    "security_orchestrator.adapters.searchsploit",
    "security_orchestrator.adapters.wkhtmltopdf",
    "security_orchestrator.adapters.fakes",
    "security_orchestrator.modules",
    "security_orchestrator.modules.recon",
    "security_orchestrator.modules.fuzzer",
    "security_orchestrator.modules.privesc",
    "security_orchestrator.modules.log_analyzer",
    "security_orchestrator.report",
    "security_orchestrator.report.generator",
    "security_orchestrator.orchestrator",
    "security_orchestrator.cli",
]


def test_every_scaffolded_submodule_imports_cleanly():
    for name in SUBMODULES:
        importlib.import_module(name)
