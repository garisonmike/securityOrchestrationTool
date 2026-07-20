"""Phase 3 tests for the log correlation module."""

from security_orchestrator.adapters.fakes import FakeLogReader, FakeSshSession
from security_orchestrator.adapters.ssh import CommandOutput
from security_orchestrator.core.models import ModuleStatus
from security_orchestrator.core.result import Result
from security_orchestrator.modules.log_analyzer import (
    FileLogReader,
    LogModule,
    SshLogReader,
)

SAMPLE_LOG = """
10.0.0.1 - - "GET / HTTP/1.1" 200 nmap scripting engine
10.0.0.2 - - "GET /?q=UNION SELECT 1,2,3 HTTP/1.1" 500
10.0.0.3 - - user-agent: nuclei/2.9
10.0.0.4 - - normal traffic here
""".strip()


def test_analyze_scores_each_signature():
    reader = FakeLogReader({"/var/log/access.log": SAMPLE_LOG})
    findings = LogModule().analyze(reader, source="/var/log/access.log", paths=["/var/log/access.log"])
    assert findings.status is ModuleStatus.SUCCESS
    assert len(findings.matches.nmap) == 1
    assert len(findings.matches.nuclei) == 1
    assert len(findings.matches.polyglot) == 1
    assert findings.detection_score == 3
    assert findings.source == "/var/log/access.log"


def test_analyze_all_reads_fail_is_error():
    reader = FakeLogReader({})  # nothing readable
    findings = LogModule().analyze(reader, source="host", paths=["/a", "/b"])
    assert findings.status is ModuleStatus.ERROR
    assert findings.logs_analyzed == []
    assert findings.errors


def test_analyze_records_per_file_errors_but_still_succeeds():
    reader = FakeLogReader(
        {"/good.log": SAMPLE_LOG, "/bad.log": Result.err("/bad.log: Permission denied")}
    )
    findings = LogModule().analyze(reader, source="host", paths=["/good.log", "/bad.log"])
    assert findings.status is ModuleStatus.SUCCESS
    assert len(findings.logs_analyzed) == 1
    assert any("Permission denied" in e for e in findings.errors)


def test_single_source_field_for_both_paths():
    # File path -> source is the file; SSH path -> source is the host.
    file_findings = LogModule().analyze_local_file(
        "/var/log/auth.log",
        reader=FakeLogReader({"/var/log/auth.log": SAMPLE_LOG}),
    )
    assert file_findings.source == "/var/log/auth.log"

    session = FakeSshSession({"cat /var/log/auth.log": CommandOutput(command="c", stdout=SAMPLE_LOG)})
    ssh_findings = LogModule().analyze_remote(session, host="10.0.0.5", paths=["/var/log/auth.log"])
    assert ssh_findings.source == "10.0.0.5"
    assert ssh_findings.detection_score == 3


def test_ssh_log_reader_reports_missing_file():
    session = FakeSshSession({})  # every cat returns empty stdout
    reader = SshLogReader(session)
    result = reader.read("/var/log/missing.log")
    assert result.is_err


def test_file_log_reader_missing_file():
    reader = FileLogReader(exists=lambda p: False)
    assert reader.read("/nope.log").is_err


def test_file_log_reader_reads_content():
    reader = FileLogReader(
        exists=lambda p: True,
        isfile=lambda p: True,
        opener=lambda *a, **k: _FakeFile(SAMPLE_LOG),
    )
    result = reader.read("/var/log/x.log")
    assert result.is_ok
    assert "nmap" in result.value


class _FakeFile:
    def __init__(self, content):
        self._content = content

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._content
