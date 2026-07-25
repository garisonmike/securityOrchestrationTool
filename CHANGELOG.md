# Changelog

All notable changes to the Automated Security Orchestration Engine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed - Typed, tested rewrite (`security_orchestrator/` package)
- **Full architecture rewrite** onto a typed contract: every module now
  returns a validated pydantic findings model with explicit
  success/skipped/error variants, instead of free-form dicts whose shape
  diverged between producers and consumers. The legacy flat `main.py` /
  `modules/` tree is superseded by the `security_orchestrator/` package.
- **Scriptable CLI**: `python -m security_orchestrator --target ... --modules
  recon,fuzzer,privesc,logs --output-format markdown|html` runs
  non-interactively; the interactive prompt flow is a thin wrapper over the
  same `Orchestrator.run` entry point.
- **Injectable adapters** wrap every external tool/call (http, nmap,
  gobuster, nuclei, ssh, searchsploit, wkhtmltopdf); the full test suite runs
  with zero real network or subprocess calls, enforced by a conftest safety
  net and a CI coverage gate.

### Fixed
- Report generation no longer crashes with `UndefinedError` when PrivEsc or
  Log Correlation is skipped - templates render against a typed `Report`
  whose keys are guaranteed in every variant.
- Active-probe HTML detection scans a generous window instead of a fixed 50
  characters, so a realistic long doctype (e.g. DVWA's XHTML declaration) is
  no longer misclassified as a downloadable file.
- Raw nmap output can no longer leak into tech-stack fields (or the report);
  adapters return only structured, parsed data.
- Log correlation is decoupled from the PrivEsc SSH session and can run
  standalone via `--log-source <path>`; its output uses one normalized
  `source` field (previously a `log_file`/`target` split that rendered blank).

### Security
- **Redaction is now wired up and mandatory**: session cookies and
  credentials are stripped from a `Report` before it reaches the renderer,
  with a direct regression test. (Previously a `redact_sensitive_data`
  function existed but was called nowhere, and a live `PHPSESSID` cookie had
  been committed in `reports/`.)

### Planned
- API integration for popular security tools
- Cloud security assessment modules
- Machine learning-based anomaly detection
- Real-time dashboard and monitoring
- Plugin architecture for custom modules
- Container and Kubernetes security testing

## [1.0.0] - 2024-03-28

### Added
- **Core Orchestration Framework**: Interactive CLI for security assessment workflow management
- **Reconnaissance Module**: Automated nmap, gobuster, and whatweb integration for attack surface mapping
- **Web Vulnerability Assessment**: Nuclei integration and custom polyglot fuzzer for web application testing
- **Privilege Escalation Simulation**: SSH-based post-exploitation testing with paramiko
- **Blue Team Log Correlation**: Real-time detection score calculation and IOC analysis
- **Multi-Format Reporting**: Jinja2-based report generation in Markdown, HTML, and PDF formats
- **Professional Documentation**: Comprehensive README, contributing guidelines, and security disclaimers
- **Security-First Design**: Input validation, command injection prevention, and safe testing practices
- **Modular Architecture**: Extensible plugin system for custom security modules

### Security
- Added a non-empty-target input check
- Added command injection prevention measures
- Added a `redact_sensitive_data` helper _(note: in 1.0.0 this helper was
  never actually invoked; redaction was wired up and made mandatory in the
  Unreleased rewrite above)_
- Established secure credential handling practices
- Added authorization verification framework

### Documentation
- Created comprehensive README with installation and usage instructions
- Established contributing guidelines for open-source collaboration
- Added security considerations and responsible disclosure processes
- Included troubleshooting guides and common issue solutions
- Provided architectural documentation and module descriptions

### Infrastructure
- Configured .gitignore for security-sensitive files
- Established professional repository structure
- Removed development artifacts and test files
- Implemented clean, production-ready codebase

## Version History

### Pre-1.0.0 Development
- Initial proof-of-concept development
- CTF challenge integration and testing
- Module development and integration
- Security testing and validation
- Code cleanup and professionalization

---

## Contributing to Changelog

When contributing changes, please update this changelog following these guidelines:

### Categories
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes and security improvements

### Format
```markdown
## [Version] - YYYY-MM-DD

### Added
- New feature description

### Fixed
- Bug fix description

### Security
- Security improvement description
```

### Guidelines
- Keep entries concise but descriptive
- Group similar changes together
- Include issue numbers when applicable
- Highlight breaking changes clearly
- Maintain reverse chronological order