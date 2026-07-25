# Automated Security Orchestration Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

A comprehensive, Python-based DevSecOps command-line tool designed to orchestrate security assessments, simulate vulnerability exploitation, and correlate blue team detection capabilities. This engine provides a unified platform for both offensive security testing and defensive analysis.

---

## **CRITICAL LEGAL DISCLAIMER**

**READ THIS BEFORE USING THE SOFTWARE**

**THIS SOFTWARE IS INTENDED EXCLUSIVELY FOR:**
- Educational and research purposes
- Authorized penetration testing with explicit written permission
- Security assessments on systems you own or have legal authorization to test
- CTF (Capture The Flag) competitions and controlled lab environments

**UNAUTHORIZED USE IS STRICTLY PROHIBITED AND MAY BE ILLEGAL.**

By using this software, you acknowledge and agree that:

1. **You have explicit, documented authorization** to test the target systems
2. **You are solely responsible** for compliance with all applicable laws and regulations
3. **The authors and contributors disclaim all liability** for misuse, damage, or illegal activities
4. **You will not use this tool** against systems without proper authorization
5. **You understand the legal implications** of security testing in your jurisdiction

**If you do not agree to these terms or lack proper authorization, DO NOT USE THIS SOFTWARE.**

The developers of this tool are not responsible for any misuse or damage caused by its use. Always ensure you have proper legal authorization before conducting any security testing.

---

## Features

### **Reconnaissance & Enumeration**
- Automated `nmap` port scanning with customizable profiles (stealthy/aggressive)
- Directory and file discovery using `gobuster`
- Web technology fingerprinting with `whatweb`
- HTTP header analysis and service detection
- Intelligent target identification and attack surface mapping

### **Web Vulnerability Assessment**
- Integration with `nuclei` for comprehensive vulnerability scanning
- Custom polyglot fuzzer for parameter injection testing
- Detection capabilities for:
  - SQL Injection (Time-based and Error-based)
  - Cross-Site Scripting (XSS)
  - Server-Side Request Forgery (SSRF)
  - Path traversal vulnerabilities
  - Configuration misconfigurations

### **Privilege Escalation Simulation**
- Secure SSH-based post-exploitation testing via `paramiko`
- SUID binary enumeration and analysis
- PATH manipulation vulnerability detection
- Sudo privilege escalation pathway identification
- Safe testing methodology to prevent system instability

### **Blue Team Log Correlation**
- Real-time detection score calculation
- Log analysis for tool artifacts and IOCs (Indicators of Compromise)
- Correlation of offensive activities with defensive telemetry
- SOC team validation capabilities
- Custom log parsing and pattern matching

### **Comprehensive Reporting**
- Dynamic report generation using `Jinja2` templates
- Multiple output formats: Markdown, HTML, and PDF
- Professional presentation-ready documentation
- Executive summary and technical details
- Remediation recommendations and risk scoring

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu/Debian recommended), macOS, or Windows with WSL
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM (4GB+ recommended for large scans)
- **Storage**: At least 1GB free space for dependencies and reports

### Required Dependencies

Install the following system-level tools before running the orchestration engine:

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y nmap gobuster whatweb nuclei wkhtmltopdf python3-pip python3-venv git
```

#### CentOS/RHEL/Fedora:
```bash
sudo dnf install -y nmap gobuster whatweb nuclei wkhtmltopdf python3-pip python3-venv git
# or for older versions: sudo yum install ...
```

#### macOS (with Homebrew):
```bash
brew install nmap gobuster whatweb nuclei wkhtmltopdf python3 git
```

#### Arch Linux:
```bash
sudo pacman -S nmap gobuster whatweb nuclei wkhtmltopdf python python-pip git
```

### Tool Verification
Verify all dependencies are correctly installed:
```bash
nmap --version && gobuster version && whatweb --version && nuclei -version && wkhtmltopdf --version
```

## Installation

### Option 1: Git Clone (Recommended)
```bash
# Clone the repository
git clone https://github.com/garisonmike/securityOrchestrationTool.git
cd securityOrchestrationTool

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package (pulls in all Python dependencies)
pip install --upgrade pip
pip install -e .

# Verify installation
python -m security_orchestrator --help
```

### Option 2: Download Release
```bash
# Download the latest release
wget https://github.com/garisonmike/securityOrchestrationTool/archive/main.zip
unzip main.zip
cd securityOrchestrationTool-main

# Follow the same virtual environment setup as above
```

### Development Installation
For contributors or advanced users:
```bash
git clone https://github.com/garisonmike/securityOrchestrationTool.git
cd securityOrchestrationTool

# Install in editable/development mode with the test toolchain
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the test suite
pytest
```

## Usage

### Quick Start
1. **Activate the virtual environment** (critical step):
   ```bash
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

2. **Run the orchestration engine interactively** (omit `--target` to be prompted):
   ```bash
   python -m security_orchestrator
   ```

3. **Follow the interactive prompts** to configure:
   - Target IP address or URL
   - Fingerprinting OPSEC level and scan profile
   - Module selection (recon, fuzzer, privesc, logs)
   - Report format preferences

### Advanced Usage

#### Command Line Options

Passing `--target` runs non-interactively (scriptable, CI-friendly); the
interactive prompts above are a thin wrapper over this same entry point, so
the two cannot drift.

```bash
python -m security_orchestrator [OPTIONS]

Options:
  --target TEXT           Target URL or IP. If omitted, runs interactively.
  --modules TEXT          Comma-separated modules: recon,fuzzer,privesc,logs
  --profile {stealth,noisy}        General aggressiveness (default: stealth)
  --opsec {stealth,noisy}          Fingerprinting OPSEC level (default: stealth)
  --output-format {markdown,html}  Report format (default: markdown)
  --output-dir TEXT       Directory to write the report to (default: reports)
  --cookie TEXT           Session cookie header value for authenticated scans
  --ssh-user TEXT         SSH username for the privesc module
  --ssh-pass TEXT         SSH password for the privesc module
  --log-source TEXT       Local log file, enabling log correlation without privesc
  --help                  Show help message and exit
```

> An HTML report is additionally converted to PDF when `wkhtmltopdf` is
> installed; a missing binary simply means no PDF, never a failure. There is
> no `--output-format pdf` value.

#### Example Commands
```bash
# Basic recon scan
python -m security_orchestrator --target 192.168.1.100 --modules recon

# Comprehensive noisy scan with all modules, HTML report
python -m security_orchestrator --target https://example.com \
    --profile noisy --opsec noisy \
    --modules recon,fuzzer,privesc,logs --output-format html

# Run log correlation standalone against a local log file (no SSH needed)
python -m security_orchestrator --target 10.0.0.1 \
    --modules logs --log-source /var/log/apache2/access.log
```

> Configuration is supplied entirely via CLI flags (or the interactive
> prompts). A `config.yaml` file is **not** supported.

## Architecture

### Project Structure
```
securityOrchestrationTool/
├── security_orchestrator/         # The application package
│   ├── __main__.py                # `python -m security_orchestrator`
│   ├── cli.py                     # argparse + interactive entry points
│   ├── orchestrator.py            # Sequences modules; owns gating rules
│   ├── core/                      # Typed contracts (framework-free)
│   │   ├── models.py              # ScanConfig, *Findings, Report (pydantic)
│   │   ├── result.py              # Result[T] for expected failures
│   │   ├── exceptions.py          # Programmer/setup-error hierarchy
│   │   └── redact.py              # Redaction pass over a Report
│   ├── adapters/                  # One class per external tool/call
│   │   ├── http.py  nmap.py  gobuster.py  nuclei.py
│   │   ├── ssh.py   searchsploit.py   wkhtmltopdf.py
│   │   └── fakes.py               # Test-only Fake* counterparts
│   ├── modules/                   # Business logic on top of adapters
│   │   ├── recon.py  fuzzer.py  privesc.py  log_analyzer.py
│   └── report/
│       ├── generator.py           # Redacts, then renders a typed Report
│       └── templates/             # report.md.j2 / report.html.j2
├── tests/                         # pytest unit tests + conftest safety net
├── pyproject.toml                 # Packaging, deps, pytest/coverage config
├── .github/workflows/ci.yml       # CI: pytest on push
├── LICENSE  README.md  CONTRIBUTING.md  CHANGELOG.md
```

### Module Architecture

Every module is built on injectable adapters and returns a typed findings
model, so each capability's success/skipped/error states are explicit and
independently testable (no live network or subprocess in tests).

#### Reconnaissance Module (`security_orchestrator/modules/recon.py`)
- HTTP header/reachability probing and passive/active fingerprinting
- Service/version scanning (nmap) and directory enumeration (gobuster)
- Technology-stack detection and searchsploit mapping (recency-filtered)

#### Web Fuzzer Module (`security_orchestrator/modules/fuzzer.py`)
- Tech-stack-aware nuclei template tag selection
- Custom error-based, reflected-XSS and time-based SQLi polyglot fuzzing

#### Privilege Escalation Module (`security_orchestrator/modules/privesc.py`)
- SSH port pre-check and rate-limit detection
- Rate-limit-aware default-credential testing and post-access enumeration

#### Log Analyzer Module (`security_orchestrator/modules/log_analyzer.py`)
- Tool-artifact signature correlation over a local file or a remote session
- Detection-score calculation, decoupled from the privesc SSH session

#### Report Generator (`security_orchestrator/report/generator.py`)
- Renders a typed `Report` to Markdown/HTML (optional PDF via wkhtmltopdf)
- Mandatory redaction of session cookies/credentials before rendering

## Contributing

We welcome contributions from the security community! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:

- Code style and standards
- Pull request process
- Issue reporting
- Security vulnerability disclosure
- Development environment setup

### Quick Contribution Guide
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

### Safe Testing Practices
- Always use isolated lab environments for initial testing
- Verify target authorization before conducting assessments
- Implement proper network segmentation during testing
- Maintain detailed logs of all testing activities

### Responsible Disclosure
If you discover security vulnerabilities in this tool:
1. **Do not** create public issues for security vulnerabilities
2. Create a private security advisory via GitHub's security tab
3. Provide detailed information about the vulnerability
4. Allow reasonable time for fixes before public disclosure
5. Follow coordinated vulnerability disclosure principles

## Troubleshooting

### Common Issues

#### "Command not found" errors
**Problem**: Missing system dependencies
**Solution**: Install required tools using your system's package manager

#### Permission denied errors
**Problem**: Insufficient privileges for network scanning
**Solution**: Run with appropriate privileges or adjust scan parameters

#### "No module named" errors
**Problem**: Python dependencies not installed or virtual environment not activated
**Solution**: Activate virtual environment and reinstall requirements

#### Large memory usage
**Problem**: Resource-intensive scanning operations
**Solution**: Reduce scan scope, increase system memory, or use stealth profiles

### Getting Help
- Check the [Issues](https://github.com/garisonmike/securityOrchestrationTool/issues) page for known problems
- Review the [Wiki](https://github.com/garisonmike/securityOrchestrationTool/wiki) for detailed documentation
- Join our [Discussions](https://github.com/garisonmike/securityOrchestrationTool/discussions) for community support

## Changelog

### Version 1.0.0 (Current)
- Initial release with core orchestration capabilities
- Comprehensive reconnaissance and enumeration
- Web vulnerability assessment framework
- Privilege escalation simulation
- Blue team log correlation
- Multi-format reporting system

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## Roadmap

### Planned Features
- [ ] API integration for popular security tools
- [ ] Cloud security assessment modules
- [ ] Machine learning-based anomaly detection
- [ ] Real-time dashboard and monitoring
- [ ] Plugin architecture for custom modules
- [ ] Container and Kubernetes security testing

## Citations and References

This project incorporates methodologies and techniques from:
- OWASP Testing Guide
- NIST Cybersecurity Framework
- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK Framework

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for complete details.

```
MIT License

Copyright (c) 2024 Security Orchestration Tool Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```

## Acknowledgments

- **OWASP** for web application security methodologies
- **Nuclei** project for vulnerability templates
- **Nmap** project for network discovery capabilities
- The broader **cybersecurity community** for tools and techniques
- **CTF community** for inspiration and testing methodologies

---

**Made with care by the security community, for the security community.**

**Remember: Use responsibly, test ethically, secure the world.**