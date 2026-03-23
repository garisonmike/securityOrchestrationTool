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

- **Implemented Solution**:
  - Validated Nuclei environment with `shutil.which`.
  - Configured Nuclei wrapper `subprocess.run` to use `-tags cve,xss,sqli,misconfig -jsonl -silent` for heavily targeted fast scans. Handled Nuclei stdout dynamically using `json.loads` to cleanly format back to a Python dictionary.
  - Implemented custom `requests.get()` fuzzer targeting dummy parameters.
  - Wrote regex iterations scanning `response.text` for common DB tracebacks (MySQL, Oracle, PostgreSQL, etc) when a polyglot is injected.
  - Used `response.elapsed.total_seconds()` wrapped around baseline requests versus `SLEEP(5)` / `pg_sleep(5)` payloads to confidently log time-based injections without risking false positives.
  - Required exact, unmodified reflection matching of `alert('NCI_HACKATHON')` before declaring an XSS capability.

- **Critical Fix Applied**: Addressed Nuclei v3 architecture issues wherein it installs its template library to `.local/nuclei-templates` instead of `~/nuclei-templates` or the system binary directory. Mapped the `run_nuclei` custom python method to force the `.local` absolute file path via `-t` flag, resolving the `[FTL] no templates provided` subprocess panic. 

## Issue #4: Privilege Escalation Simulator
- **Status**: Planning
- **Goal**: Implement paramiko-based SSH post-exploitation enumeration. Handle credentials inputs seamlessly. Catch authentication errors. Validate sudo configuration, SUID binaries, and global configurations parsing the POSIX OS stdout streams safely.

## Issue #5: Blue Team Log Correlation Engine
- **Status**: Planning / In Progress
- **Goal**: Implement `log_analyzer.py` to parse server access/auth logs, matching against known attack signatures (Nmap, Nuclei, custom polyglots) and calculating a Detection Score.
