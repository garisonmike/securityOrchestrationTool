"""
core.models
===========

The typed contract every module speaks. This is the heart of the rewrite:
the legacy tool crashed (and leaked data) because every consumer - the
nuclei tag selector, the report template, the console printer - made its
own private guess about a dict's shape, and those guesses silently diverged
the moment a code path other than "everything succeeded" ran (plan.md
Section 0, root cause).

Here, a module's output is a pydantic model whose *every* variant -
success, skipped, error - is spelled out. A field that only exists in one
variant is an explicit ``Optional[...] = None``, never a key that is
"sometimes just absent" (plan.md Section 0.1 items 8 and 15). If you can
read the model you know every field that can exist in every state, without
opening the module that produced it.

Six models, per plan.md Section 4 / Section 0.1 item 12:
    ScanConfig, ReconFindings, FuzzerFindings, PrivescFindings,
    LogFindings, Report
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ModuleStatus(str, Enum):
    """The three states any module's findings can be in.

    ``SUCCESS`` - the module ran and produced data.
    ``SKIPPED`` - the module was deliberately not run (not selected, gated
                  off, a required tool absent, the user opted out). No
                  attempt was made, so variant-specific data fields are
                  ``None``, and ``reason`` explains why.
    ``ERROR``   - the module attempted its work and failed (target offline,
                  auth rejected). An attempt *was* made; data fields may be
                  present-but-empty, and ``reason`` carries the message.
    """

    SUCCESS = "success"
    SKIPPED = "skipped"
    ERROR = "error"


class Module(str, Enum):
    """Canonical short module identifiers used by the CLI and orchestrator.

    The legacy tool keyed off long human strings ("Reconnaissance &
    Enumeration"); those are display labels, not identifiers. These short
    slugs are what ``--modules recon,fuzzer`` accepts (plan.md Goals: the
    CLI is scriptable).
    """

    RECON = "recon"
    FUZZER = "fuzzer"
    PRIVESC = "privesc"
    LOGS = "logs"

    @property
    def label(self) -> str:
        return {
            Module.RECON: "Reconnaissance & Enumeration",
            Module.FUZZER: "Web Vulnerability Fuzzer",
            Module.PRIVESC: "Privilege Escalation Simulator",
            Module.LOGS: "Blue Team Log Correlation Engine",
        }[self]


class Profile(str, Enum):
    STEALTH = "Stealth"
    NOISY = "Noisy"


class OpsecLevel(str, Enum):
    STEALTH = "stealth"
    NOISY = "noisy"


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"


# ---------------------------------------------------------------------------
# ScanConfig - user/CLI input, validated once at the boundary.
# ---------------------------------------------------------------------------
class ScanConfig(BaseModel):
    """Everything needed to run a scan, validated on construction.

    Replaces the free-form ``config`` dict that legacy ``main.py`` grew keys
    on mid-run (``config['cookie']``, ``config['hierarchical_stack']``). Here
    it is immutable input; data discovered mid-run lives in the findings
    models, not back-written onto the config.
    """

    model_config = ConfigDict(extra="forbid")

    target: str
    modules: List[Module] = Field(default_factory=list)
    profile: Profile = Profile.STEALTH
    opsec_level: OpsecLevel = OpsecLevel.STEALTH
    report_format: ReportFormat = ReportFormat.MARKDOWN
    cookie: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    # Section 0 item 7 / Phase 4 product decision: log correlation can run
    # independently of PrivEsc when given a local log file to read, since
    # analyze_logs() never needed SSH. None means "only via an SSH session".
    log_source: Optional[str] = None

    @field_validator("target")
    @classmethod
    def _target_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target cannot be empty")
        return v.strip()

    @field_validator("modules")
    @classmethod
    def _at_least_one_module(cls, v: List[Module]) -> List[Module]:
        if not v:
            raise ValueError("at least one module must be selected")
        # De-duplicate while preserving order.
        seen: set = set()
        ordered: List[Module] = []
        for m in v:
            if m not in seen:
                seen.add(m)
                ordered.append(m)
        return ordered


# ---------------------------------------------------------------------------
# Shared / nested sub-models.
# ---------------------------------------------------------------------------
class WebHeaders(BaseModel):
    """Result of the initial HTTP reachability + header probe."""

    url: str
    is_online: bool = False
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    requires_auth: bool = False
    auth_detection: Dict[str, str] = Field(default_factory=dict)
    error: Optional[str] = None


class TechStack(BaseModel):
    """Detected technology components, bucketed by tier.

    Every bucket is a list that always exists (empty, never absent), so the
    report template can iterate unconditionally - closing the "sometimes the
    key isn't there" template crash class (plan.md Section 0 item 1).
    """

    frontend: List[str] = Field(default_factory=list)
    web_server: List[str] = Field(default_factory=list)
    backend: List[str] = Field(default_factory=list)
    database: List[str] = Field(default_factory=list)
    active_probes: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class SearchsploitResult(BaseModel):
    """One searchsploit hit. Extra JSON keys from searchsploit are kept."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    title: str = Field(alias="Title", default="Unknown")
    edb_id: Optional[str] = Field(alias="EDB-ID", default=None)
    path: Optional[str] = Field(alias="Path", default=None)
    date_published: Optional[str] = Field(alias="Date_Published", default=None)
    verified: bool = False
    version_mismatch: bool = False


class NmapResult(BaseModel):
    status: ModuleStatus
    raw_output: Optional[str] = None
    command_executed: Optional[str] = None
    skip_ping_used: Optional[bool] = None
    reason: Optional[str] = None


class GobusterResult(BaseModel):
    status: ModuleStatus
    discovered_paths: List[str] = Field(default_factory=list)
    raw_output: Optional[str] = None
    reason: Optional[str] = None


class DvwaSecurityLevel(BaseModel):
    detected: bool = False
    level: Optional[str] = None
    method: Optional[str] = None
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# ReconFindings
# ---------------------------------------------------------------------------
class ReconFindings(BaseModel):
    """Output of the recon module in all three of its states."""

    status: ModuleStatus
    target: str
    profile: Profile = Profile.STEALTH
    opsec_level: OpsecLevel = OpsecLevel.STEALTH
    reason: Optional[str] = None

    dependencies: Dict[str, bool] = Field(default_factory=dict)
    web_headers: Optional[WebHeaders] = None
    hierarchical_stack: TechStack = Field(default_factory=TechStack)
    searchsploit_results: Dict[str, List[SearchsploitResult]] = Field(default_factory=dict)
    nmap_scan: Optional[NmapResult] = None
    gobuster_scan: Optional[GobusterResult] = None
    dvwa_security_level: Optional[DvwaSecurityLevel] = None

    @classmethod
    def skipped(cls, target: str, reason: str) -> "ReconFindings":
        return cls(status=ModuleStatus.SKIPPED, target=target, reason=reason)


# ---------------------------------------------------------------------------
# FuzzerFindings
# ---------------------------------------------------------------------------
class NucleiMeta(BaseModel):
    tags_used: List[str] = Field(default_factory=list)
    tags_string: str = "none"
    templates_matched: int = 0
    severity_filter: str = ""
    tech_stack_received: bool = False
    tech_stack_keys: List[str] = Field(default_factory=list)


class NucleiResult(BaseModel):
    status: ModuleStatus
    findings: List[Dict] = Field(default_factory=list)
    meta: Optional[NucleiMeta] = None
    warning: Optional[str] = None
    reason: Optional[str] = None
    raw_output: Optional[str] = None


class CustomFuzzerResult(BaseModel):
    xss: List[str] = Field(default_factory=list)
    sqli_error: List[str] = Field(default_factory=list)
    sqli_time: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class FuzzerFindings(BaseModel):
    status: ModuleStatus
    target: str
    reason: Optional[str] = None
    dependencies: Dict[str, bool] = Field(default_factory=dict)
    nuclei_scan: Optional[NucleiResult] = None
    custom_fuzzer: Optional[CustomFuzzerResult] = None
    errors: List[str] = Field(default_factory=list)

    @classmethod
    def skipped(cls, target: str, reason: str) -> "FuzzerFindings":
        return cls(status=ModuleStatus.SKIPPED, target=target, reason=reason)


# ---------------------------------------------------------------------------
# PrivescFindings - three genuinely distinct shapes (plan.md 0.1 item 15).
# ---------------------------------------------------------------------------
class PrivescCommandResult(BaseModel):
    command: str
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    exit_status: Optional[int] = None
    error: Optional[str] = None


class PrivescFindings(BaseModel):
    """PrivEsc output. Its ``findings`` field is the load-bearing example of
    this rewrite's thesis: it is an explicit ``Optional`` that is ``None``
    only in the user-skipped state (no attempt made), an empty dict in the
    connection-error state (attempt made, nothing enumerated), and populated
    on success - never a key that is simply absent (plan.md 0.1 item 15).
    """

    status: ModuleStatus
    target: Optional[str] = None
    auth_used: Optional[str] = None
    reason: Optional[str] = None
    findings: Optional[Dict[str, PrivescCommandResult]] = None

    @classmethod
    def skipped(cls, reason: str, target: Optional[str] = None) -> "PrivescFindings":
        # user-skipped: no attempt, so findings stays None.
        return cls(status=ModuleStatus.SKIPPED, target=target, reason=reason, findings=None)

    @classmethod
    def error(cls, reason: str, target: Optional[str] = None, auth_used: Optional[str] = None) -> "PrivescFindings":
        # connection-error: attempt made, findings present-but-empty.
        return cls(
            status=ModuleStatus.ERROR,
            target=target,
            auth_used=auth_used,
            reason=reason,
            findings={},
        )


# ---------------------------------------------------------------------------
# LogFindings - one normalized source field (plan.md 0.1 item 8).
# ---------------------------------------------------------------------------
class LogMatch(BaseModel):
    file: Optional[str] = None
    line: int
    content: str


class LogMatches(BaseModel):
    nmap: List[LogMatch] = Field(default_factory=list)
    nuclei: List[LogMatch] = Field(default_factory=list)
    polyglot: List[LogMatch] = Field(default_factory=list)


class AnalyzedLog(BaseModel):
    path: str
    lines: int
    matches: int


class LogFindings(BaseModel):
    """Blue-team log correlation output.

    The legacy code had two entry points that disagreed on a field name -
    ``analyze_logs`` returned ``log_file``, ``analyze_logs_from_ssh``
    returned ``target`` - and both templates read ``log_file``, so the SSH
    path (the only one actually wired up) always rendered blank (plan.md 0.1
    item 8). Here there is exactly one field, ``source``, whichever path
    produced the data.
    """

    status: ModuleStatus
    source: str
    reason: Optional[str] = None
    logs_analyzed: List[AnalyzedLog] = Field(default_factory=list)
    total_lines_analyzed: int = 0
    detection_score: int = 0
    matches: LogMatches = Field(default_factory=LogMatches)
    errors: List[str] = Field(default_factory=list)

    @classmethod
    def skipped(cls, source: str, reason: str) -> "LogFindings":
        return cls(status=ModuleStatus.SKIPPED, source=source, reason=reason)


# ---------------------------------------------------------------------------
# Report - the top-level object the renderer consumes.
# ---------------------------------------------------------------------------
class Report(BaseModel):
    """The full session result. Each module slot is ``None`` if that module
    was never part of the run, or a findings model (in any of its states)
    if it was. The renderer treats ``None`` as "not executed" and a
    ``SKIPPED`` findings model as "executed-but-skipped, here's why".
    """

    target: str
    config: ScanConfig
    recon: Optional[ReconFindings] = None
    fuzzer: Optional[FuzzerFindings] = None
    privesc: Optional[PrivescFindings] = None
    log_analysis: Optional[LogFindings] = None
