# Security Orchestration Tool - Development Report

## Issue #1: Project Initialization and Interactive CLI Skeleton
- **Status**: Code Generated (Pending User Testing & Approval)
- **Work Completed**:
  - Validated and acknowledged strict Agile working rules.
  - Set up `requirements.txt` containing dependencies for rich, questionary, paramiko, requests, and jinja2.
  - Implemented `main.py` acting as the main entry point with clean typography using `rich` panels and interactive menus handled by `questionary`.
  - Gathered required configuration from users: Target URL/IP, Scan Profile (Stealth/Noisy), Modules to Execute, and Report Format. Added input validations.
  - Created modular architecture with `/modules` directory, implementing placeholders for `recon.py`, `web_fuzzer.py`, `privesc.py`, `log_analyzer.py`, and `report_gen.py`. Include type hints and robust error/interrupt handling.

## Issue #2: Reconnaissance & Enumeration Module
- **Status**: Code Generated (Pending User Testing & Approval)
- **Work Completed**:
  - Implemented `run_recon` as the main orchestrator in `modules/recon.py`.
  - Added dependency checks using `shutil.which` for native tools (`nmap` and `gobuster`).
  - Added HTTP Header capture with `requests` (using strict `5` second timeouts and graceful error handling on connectivity failures).
  - Wrote robust parameter-stripping helper functions: `gobuster` correctly gets the URL with schema (`http(s)://`), whereas `nmap` receives a clean IP or Domain. 
  - Wrote native OS tool wrappers for Nmap and Gobuster with aggressive vs stealth flag logic based on user input. 
  - Wrapped `subprocess.run` executions with `check=True` and specific handles for `subprocess.TimeoutExpired` and `subprocess.CalledProcessError` so Python cleanly logs failures rather than crashing. 

## Issue #3: Web Vulnerability Fuzzer Module
- **Status**: Planning
- **Goal**: Implement Nuclei wrapper and custom polyglot fuzzing logic using Python `requests`.
