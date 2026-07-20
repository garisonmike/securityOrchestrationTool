"""Phase 3 tests for the privesc module.

Covers the three distinct PrivescFindings shapes (plan.md 0.1 item 15),
rate-limit detection (dropped-connection and exponential-delay paths), and
the default-credential brute-force outcomes - all against a fake SSH
adapter, no real socket.
"""

from security_orchestrator.adapters.fakes import FakeSshAdapter
from security_orchestrator.adapters.ssh import CommandOutput, SshOutcome
from security_orchestrator.core.models import Module, ModuleStatus, ScanConfig
from security_orchestrator.modules.privesc import DEFAULT_CREDENTIALS, PrivescModule


def _cfg():
    return ScanConfig(target="localhost:8080", modules=[Module.PRIVESC])


def _no_sleep(_):
    return None


# --- three shapes ----------------------------------------------------------
def test_run_success_populates_findings_and_returns_session():
    ssh = FakeSshAdapter(
        valid_credentials={("root", "root")},
        command_outputs={"os-release": CommandOutput(command="c", stdout="Ubuntu")},
    )
    module = PrivescModule(ssh, sleep=_no_sleep)
    findings, session = module.run(_cfg(), {"username": "root", "password": "root"})
    assert findings.status is ModuleStatus.SUCCESS
    assert findings.findings is not None
    assert set(findings.findings.keys()) >= {"sudo_privileges", "os_release"}
    assert session is not None  # handed to log correlation


def test_run_auth_failure_is_error_with_empty_findings():
    ssh = FakeSshAdapter(valid_credentials=set())  # nothing valid
    module = PrivescModule(ssh, sleep=_no_sleep)
    findings, session = module.run(_cfg(), {"username": "root", "password": "wrong"})
    assert findings.status is ModuleStatus.ERROR
    assert findings.findings == {}  # attempt made -> present-but-empty, not None
    assert session is None


def test_run_no_credentials_is_skipped_with_none_findings():
    module = PrivescModule(FakeSshAdapter(), sleep=_no_sleep)
    findings, session = module.run(_cfg(), None)
    assert findings.status is ModuleStatus.SKIPPED
    assert findings.findings is None  # no attempt made
    assert session is None


# --- rate-limit detection --------------------------------------------------
def test_rate_limit_dropped_connections():
    ssh = FakeSshAdapter(connect_script=[SshOutcome.DROPPED, SshOutcome.DROPPED, SshOutcome.DROPPED])
    module = PrivescModule(ssh, sleep=_no_sleep)
    limited, message = module.detect_rate_limiting("host")
    assert limited is True
    assert "dropped" in message.lower()


def test_rate_limit_exponential_delay():
    # AUTH_FAILED each probe (no drops), but delays grow >1.5x each step.
    clock_values = iter([0.0, 0.1, 0.1, 0.6, 0.6, 2.6])
    module = PrivescModule(
        FakeSshAdapter(valid_credentials=set()),
        clock=lambda: next(clock_values),
        sleep=_no_sleep,
    )
    limited, message = module.detect_rate_limiting("host")
    assert limited is True
    assert "exponential" in message.lower()


def test_rate_limit_none_detected():
    clock_values = iter([0.0, 0.1, 0.1, 0.2, 0.2, 0.3])
    module = PrivescModule(
        FakeSshAdapter(valid_credentials=set()),
        clock=lambda: next(clock_values),
        sleep=_no_sleep,
    )
    limited, _ = module.detect_rate_limiting("host")
    assert limited is False


# --- default credential brute-force ---------------------------------------
def test_brute_force_finds_valid_pair():
    # (root, root) is the 2nd pair in DEFAULT_CREDENTIALS.
    ssh = FakeSshAdapter(valid_credentials={("root", "root")})
    module = PrivescModule(ssh, sleep=_no_sleep)
    result = module.try_default_credentials("host")
    assert result["success"] is True
    assert result["credentials"] == {"username": "root", "password": "root"}
    assert result["attempts"] == 2


def test_brute_force_exhausts_all_eight_when_none_valid():
    ssh = FakeSshAdapter(valid_credentials=set())
    module = PrivescModule(ssh, sleep=_no_sleep)
    result = module.try_default_credentials("host")
    assert result["success"] is False
    assert result["attempts"] == len(DEFAULT_CREDENTIALS) == 8


def test_brute_force_skips_when_port_closed():
    ssh = FakeSshAdapter(port_open=False)
    module = PrivescModule(ssh, sleep=_no_sleep)
    result = module.try_default_credentials("host")
    assert result["success"] is False
    assert result["attempts"] == 0
    assert "closed" in result["message"].lower()


def test_brute_force_aborts_on_dropped_connection():
    ssh = FakeSshAdapter(connect_script=[SshOutcome.DROPPED])
    module = PrivescModule(ssh, sleep=_no_sleep)
    result = module.try_default_credentials("host")
    assert result["success"] is False
    assert "dropped" in result["message"].lower()
