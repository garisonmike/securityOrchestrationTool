"""
core
====

Framework-free contracts shared by every other package: the six typed
findings/config/report models, the `Result[T]` type for expected failures,
the small programmer-error exception hierarchy, and the redaction pass.

Populated in Phase 1 (plan.md, Phase-1). Empty in Phase 0.
"""

from security_orchestrator.core.exceptions import (
    ConfigError,
    OrchestratorError,
    ToolNotFoundError,
)
from security_orchestrator.core.models import (
    AnalyzedLog,
    CustomFuzzerResult,
    DvwaSecurityLevel,
    FuzzerFindings,
    GobusterResult,
    LogFindings,
    LogMatch,
    LogMatches,
    Module,
    ModuleStatus,
    NmapResult,
    NucleiMeta,
    NucleiResult,
    OpsecLevel,
    PrivescCommandResult,
    PrivescFindings,
    Profile,
    ReconFindings,
    Report,
    ReportFormat,
    ScanConfig,
    SearchsploitResult,
    TechStack,
    WebHeaders,
)
from security_orchestrator.core.redact import redact
from security_orchestrator.core.result import Result

__all__ = [
    "ConfigError",
    "OrchestratorError",
    "ToolNotFoundError",
    "Result",
    "redact",
    "Module",
    "ModuleStatus",
    "Profile",
    "OpsecLevel",
    "ReportFormat",
    "ScanConfig",
    "WebHeaders",
    "TechStack",
    "SearchsploitResult",
    "NmapResult",
    "GobusterResult",
    "DvwaSecurityLevel",
    "ReconFindings",
    "NucleiMeta",
    "NucleiResult",
    "CustomFuzzerResult",
    "FuzzerFindings",
    "PrivescCommandResult",
    "PrivescFindings",
    "LogMatch",
    "LogMatches",
    "AnalyzedLog",
    "LogFindings",
    "Report",
]
