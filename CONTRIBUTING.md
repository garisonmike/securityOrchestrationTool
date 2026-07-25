# Contributing to Automated Security Orchestration Engine

Thank you for your interest in contributing to the Automated Security Orchestration Engine! This document provides guidelines and information for contributors to ensure a smooth collaboration process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Issue Reporting](#issue-reporting)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Community](#community)

## Code of Conduct

### Our Commitment

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of background, experience level, or identity. This project follows ethical security research principles and responsible disclosure practices.

### Expected Behavior

- **Be respectful** and professional in all interactions
- **Follow ethical guidelines** for security research and testing
- **Provide constructive feedback** and accept criticism gracefully
- **Help maintain a safe environment** for learning and collaboration
- **Respect intellectual property** and attribution requirements

### Unacceptable Behavior

- Harassment, discrimination, or personal attacks
- Sharing of exploits for malicious purposes
- Unauthorized testing on systems without permission
- Disclosure of vulnerabilities without following responsible disclosure
- Spamming, trolling, or disruptive behavior

### Enforcement

Code of conduct violations should be reported by creating a private issue or contacting repository maintainers directly through GitHub. All reports will be investigated promptly and confidentially.

## Getting Started

### Prerequisites

Before contributing, ensure you have:

1. **Fundamental security knowledge** - Understanding of penetration testing, vulnerability assessment, and security concepts
2. **Python proficiency** - Comfortable with Python 3.8+ and common libraries
3. **Linux/Unix experience** - Familiarity with command-line tools and system administration
4. **Git knowledge** - Basic understanding of version control workflows

### First Steps

1. **Read the documentation** - Thoroughly review README.md and existing code
2. **Set up development environment** - Follow the setup instructions below
3. **Explore the codebase** - Understand the architecture and module structure
4. **Check open issues** - Look for beginner-friendly issues labeled `good first issue`
5. **Join the community** - Participate in discussions and introduce yourself

## Development Environment

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Python**: 3.8 or higher
- **Memory**: 4GB+ RAM for development and testing
- **Storage**: 2GB+ free space for dependencies and test environments

### Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/garisonmike/securityOrchestrationTool.git
   cd securityOrchestrationTool
   git remote add upstream https://github.com/garisonmike/securityOrchestrationTool.git
   ```

2. **Install system dependencies** (Ubuntu/Debian):
   ```bash
   sudo apt update
   sudo apt install -y nmap gobuster whatweb nuclei wkhtmltopdf python3-pip python3-venv git
   ```

3. **Set up the Python environment and install the package with its test
   toolchain**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

4. **Verify installation**:
   ```bash
   python -m security_orchestrator --help
   pytest
   ```

### Development Tools

The dev toolchain is deliberately lean: **pytest** + **pytest-cov** + the
stdlib `unittest.mock`, all declared in `pyproject.toml`'s `[project.optional
-dependencies].dev`. No linters or security scanners (black/flake8/mypy/
bandit/safety) are bundled or required to contribute; if you use them
locally, that's fine, but CI only runs the test suite.

#### Testing Tools
- **pytest**: the unit test suite under `tests/`
- **pytest-cov**: coverage measurement, with a fail-under gate configured in
  `pyproject.toml` (`[tool.pytest.ini_options].addopts`)

## Contributing Process

### Contribution Types

We welcome various types of contributions:

#### Bug Fixes
- Fix existing functionality issues
- Resolve security vulnerabilities
- Improve error handling and edge cases

#### New Features
- Add new security testing modules
- Enhance existing functionality
- Implement new reporting capabilities

#### Documentation
- Improve README and guides
- Add code comments and docstrings
- Create tutorials and examples

#### Testing
- Write unit and integration tests
- Develop test environments and scenarios
- Improve test coverage

#### Infrastructure
- CI/CD pipeline improvements
- Build and packaging enhancements
- Development tooling

### Contribution Workflow

1. **Plan your contribution**:
   - Check existing issues and discussions
   - Create an issue for significant changes
   - Discuss approach with maintainers

2. **Development**:
   - Create a feature branch from `main`
   - Make focused, atomic commits
   - Follow coding standards and guidelines
   - Write/update tests and documentation

3. **Quality assurance**:
   - Run all tests locally
   - Verify code quality tools pass
   - Test in multiple environments
   - Validate security considerations

4. **Submit contribution**:
   - Create a detailed pull request
   - Respond to review feedback
   - Make requested changes
   - Ensure CI/CD pipeline passes

## Coding Standards

### General Principles

- **Security first** - Always consider security implications
- **Clarity over cleverness** - Write readable, maintainable code
- **Fail safely** - Handle errors gracefully and securely
- **Document everything** - Code should be self-documenting

### Python Style Guide

Follow [PEP 8](https://pep8.org/) with these specific requirements:

#### Code Formatting
```python
# Use Black for automatic formatting
# Line length: 88 characters
# Use double quotes for strings
# 4 spaces for indentation
```

#### Naming Conventions
```python
# Variables and functions: snake_case
target_ip = "192.168.1.1"

# Classes: PascalCase
class SecurityModule:
    pass

# Constants: UPPER_SNAKE_CASE
DEFAULT_TIMEOUT = 30

# Private methods: _leading_underscore
def _internal_method(self):
    pass
```

#### Type Hints
```python
from typing import Dict, List, Optional, Any

def scan_target(target: str, ports: List[int]) -> Dict[str, Any]:
    """Scan target with specified ports.
    
    Args:
        target: Target IP address or hostname
        ports: List of ports to scan
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        ValueError: If target is invalid
        ConnectionError: If target is unreachable
    """
    pass
```

#### Error Handling
```python
import logging
from typing import Optional

def safe_operation(target: str) -> Optional[Dict]:
    """Perform operation with proper error handling."""
    try:
        # Risky operation here
        return perform_scan(target)
    except ConnectionError as e:
        logging.error(f"Connection failed for {target}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Invalid target {target}: {e}")
        raise  # Re-raise validation errors
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        return None
```

### Security Coding Standards

#### Input Validation
```python
import re
import ipaddress

def validate_target(target: str) -> bool:
    """Validate target IP or hostname."""
    try:
        # Try parsing as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Validate as hostname
        hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
        return re.match(hostname_pattern, target) is not None
```

#### Command Injection Prevention
```python
import subprocess
import shlex

def safe_command_execution(command_args: List[str]) -> str:
    """Execute command safely without shell injection."""
    # Never use shell=True with user input
    # Always validate and sanitize arguments
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise TimeoutError("Command execution timed out")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {e}")
```

#### Sensitive Data Handling
```python
def redact_sensitive_data(output: str) -> str:
    """Remove sensitive information from output."""
    patterns = [
        r'(password|passwd|pwd)["\s:=]+([^\s,}\]]+)',
        r'(token|key|secret)["\s:=]+([^\s,}\]]+)',
        r'(cookie)["\s:=]+([^\s,}\]]+)',
    ]
    
    redacted = output
    for pattern in patterns:
        redacted = re.sub(pattern, r'\1: [REDACTED]', redacted, flags=re.IGNORECASE)
    
    return redacted
```

## Testing Guidelines

### Test Structure

```
tests/
├── conftest.py             # Autouse safety net: blocks real socket/subprocess
├── unit/                   # One file per adapter / module / layer
│   ├── test_result.py  test_models.py  test_redact.py
│   ├── test_adapters.py
│   ├── test_recon.py  test_fuzzer.py  test_privesc.py  test_log_analyzer.py
│   ├── test_orchestrator.py  test_cli.py  test_report.py
│   └── test_scaffold.py    # Package-imports smoke test
└── fixtures/               # Canned tool outputs (as needed)
```

### Writing Tests

The core rule: **no test touches a real network or spawns a real
subprocess.** Adapters take an injectable runner (a fake `subprocess.run` /
`requests.get` / paramiko client), and module/orchestrator tests inject the
`Fake*` adapters from `security_orchestrator.adapters.fakes`. The autouse
fixture in `tests/conftest.py` monkeypatches `subprocess.run` and
`socket.socket` to raise, so an accidental live call fails loudly.

#### Adapter test (inject a fake runner)
```python
from types import SimpleNamespace
from security_orchestrator.adapters.nmap import NmapAdapter

def test_nmap_success():
    runner = lambda *a, **k: SimpleNamespace(returncode=0, stdout="Nmap scan report...", stderr="")
    result = NmapAdapter(runner=runner, which=lambda name: "/usr/bin/nmap").scan("host")
    assert result.is_ok
    assert "Nmap scan report" in result.value.raw_output
```

#### Module test (inject Fake* adapters)
```python
from security_orchestrator.adapters.fakes import FakeSshAdapter
from security_orchestrator.core.models import ModuleStatus, ScanConfig, Module
from security_orchestrator.modules.privesc import PrivescModule

def test_privesc_skipped_without_credentials():
    module = PrivescModule(FakeSshAdapter(), sleep=lambda _: None)
    config = ScanConfig(target="localhost:8080", modules=[Module.PRIVESC])
    findings, session = module.run(config, ssh_creds=None)
    assert findings.status is ModuleStatus.SKIPPED
    assert findings.findings is None   # no attempt made -> None, not {}
    assert session is None
```

### Running Tests

```bash
# Run all tests (coverage + the fail-under gate are configured in pyproject.toml)
pytest

# HTML coverage report
pytest --cov=security_orchestrator --cov-report=html

# Run a single file or test
pytest tests/unit/test_recon.py
pytest tests/unit/test_privesc.py::test_run_success_populates_findings_and_returns_session

# Verbose output
pytest -v
```

## Security Considerations

### Responsible Development

#### Authorization Verification
- Always verify explicit authorization before testing
- Implement target validation and whitelisting
- Log all testing activities for audit trails
- Provide clear warnings about unauthorized use

#### Safe Testing Practices
```python
def verify_authorization(target: str) -> bool:
    """Verify explicit authorization for target testing."""
    authorized_ranges = load_authorized_targets()
    
    for authorized_range in authorized_ranges:
        if target_in_range(target, authorized_range):
            logging.info(f"Authorization verified for {target}")
            return True
    
    logging.warning(f"No authorization found for {target}")
    return False
```

#### Vulnerability Disclosure

If you discover security vulnerabilities:

1. **Create a private security advisory** - Use GitHub's security advisory feature
2. **Provide detailed information** - Include steps to reproduce
3. **Allow time for fixes** - Give 90 days before public disclosure
4. **Follow coordinated disclosure** - Work with maintainers on timeline

### Code Security Reviews

All contributions undergo security review focusing on:

- Input validation and sanitization
- Command injection prevention
- Privilege escalation risks
- Data exposure and logging
- Authorization and authentication

## Documentation

### Documentation Standards

#### Code Comments
```python
def complex_security_function(target: str, options: Dict) -> Results:
    """
    Perform complex security operation on target.
    
    This function implements advanced security testing methodologies
    including reconnaissance, vulnerability assessment, and exploitation
    simulation in a controlled manner.
    
    Args:
        target (str): Target IP address or hostname (must be authorized)
        options (Dict): Configuration options including:
            - aggressive (bool): Use aggressive scanning techniques
            - modules (List[str]): Specific modules to execute
            - timeout (int): Maximum execution time in seconds
            
    Returns:
        Results: Object containing scan results, vulnerabilities found,
                and recommended remediation steps
                
    Raises:
        UnauthorizedTargetError: If target is not in authorized list
        InvalidConfigurationError: If options are invalid
        ToolNotFoundError: If required external tools are missing
        
    Example:
        >>> scanner = SecurityScanner()
        >>> results = scanner.complex_security_function(
        ...     "192.168.1.100",
        ...     {"aggressive": False, "modules": ["recon", "web_fuzzer"]}
        ... )
        >>> print(results.summary)
        
    Note:
        This function requires explicit authorization for the target.
        Always verify proper authorization before use.
    """
    # Implementation with detailed comments
    pass
```

#### README Updates
When adding new features, update the README.md:
- Add feature description to Features section
- Update usage examples
- Add any new prerequisites
- Update architecture diagrams if needed

#### Wiki Documentation
For complex features, create wiki pages covering:
- Detailed usage instructions
- Configuration options
- Troubleshooting guides
- Best practices

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Bug Description**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. Configure with '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python version: [e.g., 3.9.7]
- Tool version: [e.g., 1.0.0]

**Additional Context**
Any other relevant information.
```

### Feature Requests

Use the feature request template:

```markdown
**Feature Description**
A clear description of the proposed feature.

**Problem Statement**
What problem does this solve?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other solutions you've considered.

**Security Considerations**
How does this impact security?
```

### Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Use GitHub's security advisory feature
2. Include detailed vulnerability information
3. Provide proof of concept if safe
4. Suggest remediation approaches

## Pull Request Process

### PR Requirements

Before submitting a pull request:

- [ ] Code follows style guidelines
- [ ] Tests are written and passing
- [ ] Documentation is updated
- [ ] Security review is completed
- [ ] Breaking changes are documented
- [ ] Commit messages are descriptive

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature  
- [ ] Documentation update
- [ ] Security fix
- [ ] Breaking change

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Security testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No security issues introduced
```

### Review Process

1. **Automated checks** - CI/CD pipeline validates code quality
2. **Security review** - Maintainers review security implications
3. **Code review** - Technical review of implementation
4. **Testing verification** - Ensure comprehensive test coverage
5. **Final approval** - Maintainer approval for merge

### Merge Criteria

Pull requests are merged when:
- All automated checks pass
- At least one maintainer approves
- Security review is completed
- Documentation is adequate
- No unresolved conversations remain

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **Major** (X.0.0): Breaking changes
- **Minor** (X.Y.0): New features, backwards compatible
- **Patch** (X.Y.Z): Bug fixes, backwards compatible

### Release Schedule

- **Patch releases**: Monthly or as needed for critical fixes
- **Minor releases**: Quarterly for new features
- **Major releases**: Yearly or for significant changes

### Release Notes

Each release includes:
- New features and improvements
- Bug fixes and security updates
- Breaking changes and migration guides
- Known issues and workarounds

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community interaction
- **GitHub Security Advisories**: Private security vulnerability reports
- **Pull Request Reviews**: Code collaboration and technical discussions

### Recognition

We recognize contributors through:
- Contributors list in README
- Release notes acknowledgments
- GitHub contributor statistics
- Special recognition for significant contributions

### Mentorship

New contributors can:
- Look for `good first issue` labels
- Ask questions in discussions
- Request mentorship for complex features
- Participate in code reviews

## Questions?

If you have questions about contributing:

1. Check existing documentation and issues
2. Search previous discussions
3. Create a new discussion topic
4. Contact maintainers directly for sensitive topics

Thank you for contributing to making the security community stronger and more collaborative!

---

**Remember**: All contributions should follow ethical security practices and responsible disclosure principles. Together, we can build tools that make the digital world more secure.