"""
cli
===

argparse wiring for every flag the README already promised (``--target``,
``--modules``, ``--output-format`` and friends) plus a thin interactive
questionary flow. Both paths build the *same* ``ScanConfig`` and call the
*same* ``Orchestrator.run`` - so the scriptable and interactive experiences
cannot drift (plan.md Goals / Phase-4).

``build_config`` is a pure ``args -> ScanConfig`` function (no I/O), so
argument handling is unit-tested without spawning anything. ``main`` accepts
an injected ``Adapters`` bundle purely so the end-to-end test can run the
whole pipeline against fakes, touching no real network.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from security_orchestrator.core.exceptions import ConfigError
from security_orchestrator.core.models import (
    Module,
    OpsecLevel,
    Profile,
    ReportFormat,
    ScanConfig,
)
from security_orchestrator.orchestrator import Adapters, Orchestrator

_MODULE_ALIASES = {
    "recon": Module.RECON,
    "fuzzer": Module.FUZZER,
    "fuzz": Module.FUZZER,
    "privesc": Module.PRIVESC,
    "logs": Module.LOGS,
    "log": Module.LOGS,
    "log-correlation": Module.LOGS,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_orchestrator",
        description="Automated security orchestration and correlation engine.",
    )
    parser.add_argument("--target", help="Target URL or IP. If omitted, runs interactively.")
    parser.add_argument(
        "--modules",
        help="Comma-separated modules to run: recon,fuzzer,privesc,logs",
    )
    parser.add_argument(
        "--profile",
        choices=["stealth", "noisy"],
        default="stealth",
        help="General aggressiveness profile (default: stealth).",
    )
    parser.add_argument(
        "--opsec",
        choices=["stealth", "noisy"],
        default="stealth",
        help="Fingerprinting OPSEC level (default: stealth).",
    )
    parser.add_argument(
        "--output-format",
        choices=["markdown", "html"],
        default="markdown",
        help="Report format (default: markdown).",
    )
    parser.add_argument("--output-dir", default="reports", help="Where to write the report.")
    parser.add_argument("--cookie", help="Session cookie header value for authenticated scanning.")
    parser.add_argument("--ssh-user", help="SSH username for the privesc module.")
    parser.add_argument("--ssh-pass", help="SSH password for the privesc module.")
    parser.add_argument(
        "--log-source",
        help="Local log file path, enabling log correlation independently of privesc.",
    )
    return parser


def parse_modules(raw: Optional[str]) -> List[Module]:
    if not raw:
        raise ConfigError("--modules is required in non-interactive mode")
    modules: List[Module] = []
    for token in raw.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token not in _MODULE_ALIASES:
            raise ConfigError(
                f"unknown module {token!r}; valid: recon, fuzzer, privesc, logs"
            )
        module = _MODULE_ALIASES[token]
        if module not in modules:
            modules.append(module)
    if not modules:
        raise ConfigError("no valid modules selected")
    return modules


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Pure args -> ScanConfig. Raises ConfigError on bad input."""
    try:
        return ScanConfig(
            target=args.target,
            modules=parse_modules(args.modules),
            profile=Profile.NOISY if args.profile == "noisy" else Profile.STEALTH,
            opsec_level=OpsecLevel.NOISY if args.opsec == "noisy" else OpsecLevel.STEALTH,
            report_format=ReportFormat.HTML if args.output_format == "html" else ReportFormat.MARKDOWN,
            cookie=args.cookie,
            ssh_username=args.ssh_user,
            ssh_password=args.ssh_pass,
            log_source=args.log_source,
        )
    except ConfigError:
        raise
    except Exception as exc:  # pydantic ValidationError -> ConfigError
        raise ConfigError(str(exc)) from exc


def interactive_config() -> Optional[ScanConfig]:  # pragma: no cover - needs a tty
    """Thin questionary wrapper that builds the same ScanConfig."""
    import questionary

    target = questionary.text(
        "Enter the Target URL/IP:",
        validate=lambda t: True if t.strip() else "Target cannot be empty",
    ).ask()
    if not target:
        return None

    opsec = questionary.select(
        "Fingerprinting OPSEC level:", choices=["stealth", "noisy"]
    ).ask()
    if opsec is None:
        return None

    profile = questionary.select("Scan profile:", choices=["stealth", "noisy"]).ask()
    if profile is None:
        return None

    chosen = questionary.checkbox(
        "Select modules to run:",
        choices=[m.value for m in Module],
        validate=lambda a: True if a else "Select at least one module.",
    ).ask()
    if not chosen:
        return None

    fmt = questionary.select("Report format:", choices=["markdown", "html"]).ask()
    if fmt is None:
        return None

    cookie = questionary.text("Session cookie (blank for none):").ask() or None

    return ScanConfig(
        target=target.strip(),
        modules=[Module(m) for m in chosen],
        profile=Profile.NOISY if profile == "noisy" else Profile.STEALTH,
        opsec_level=OpsecLevel.NOISY if opsec == "noisy" else OpsecLevel.STEALTH,
        report_format=ReportFormat.HTML if fmt == "html" else ReportFormat.MARKDOWN,
        cookie=cookie,
    )


def summarize(report) -> str:
    lines = [f"Scan complete for {report.target}."]
    for name in ("recon", "fuzzer", "privesc", "log_analysis"):
        section = getattr(report, name)
        if section is not None:
            lines.append(f"  {name}: {section.status.value}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None, adapters: Optional[Adapters] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.target:
            config = build_config(args)
        else:
            config = interactive_config()
            if config is None:
                print("Configuration aborted.")
                return 0
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    report = Orchestrator(adapters).run(config)

    from security_orchestrator.report.generator import generate_report

    path = generate_report(report, output_dir=args.output_dir)
    print(summarize(report))
    print(f"Report written to: {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
