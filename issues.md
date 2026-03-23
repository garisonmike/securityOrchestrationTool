Security Orchestration Tool - Development Tracker

This file tracks the Agile development process of the Automated Security Orchestration and Correlation Engine.
The AI assistant must complete these issues sequentially, updating the status only upon user verification.

Issue #1: Project Initialization and Interactive CLI Skeleton

Status: [x] Closed
Description: Set up the core application architecture, including the interactive terminal menu using InquirerPy or Questionary, and stylized console output using Rich.
Tasks:

[ ] Create requirements.txt with necessary libraries (rich, questionary, paramiko, requests, jinja2).

[ ] Create main.py that acts as the entry point.

[ ] Implement an interactive menu asking the user for: Target URL/IP, Scan Profile (Stealth/Noisy), Modules to Execute, and Report Format.

[ ] Create placeholder directories and files for the modules (recon.py, web_fuzzer.py, privesc.py, log_analyzer.py, report_gen.py).
Acceptance Criteria:

Running python main.py launches a beautiful, bug-free interactive menu.

The user's selections are stored in a configuration dictionary/object to be passed to modules.

Issue #2: Reconnaissance & Enumeration Module

Status: [x] Closed
Description: Build the recon.py module to grab server banners and run directory/subdomain fuzzing using native OS tools.
Tasks:

[ ] Implement a function to verify the target is online and grab HTTP response headers to identify the tech stack.

[ ] Implement an environment check using shutil.which to ensure nmap and gobuster are installed.

[ ] Write a subprocess wrapper to execute an Nmap scan (Stealth vs. Noisy based on user config).

[ ] Write a subprocess wrapper to execute a gobuster dir scan.
Acceptance Criteria:

The module successfully parses HTTP headers.

The module runs Nmap/Gobuster without hanging, catches subprocess.CalledProcessError, and returns parsed output as a Python dictionary.

Issue #3: Web Vulnerability Fuzzer Module

Status: [x] Closed
Description: Build the web_fuzzer.py module to test for SQLi, XSS, and SSRF using polyglot payloads and Nuclei.
Tasks:

[ ] Implement an environment check for nuclei.

[ ] Write a wrapper to execute nuclei against the target and parse the output JSON.

[ ] Write a custom fuzzing function that uses the requests library to inject a polyglot payload (XSS/SQLi) into discovered endpoints/parameters.

[ ] Evaluate the response text and status codes for database errors or reflected XSS payloads.
Acceptance Criteria:

The module correctly identifies at least one simulated SQLi or XSS vulnerability.

Outputs are cleanly formatted and appended to the master findings dictionary.

Issue #4: Privilege Escalation Simulator

Status: [x] Closed
Description: Build the privesc.py module to simulate post-exploitation enumeration via SSH.
Tasks:

[ ] Prompt the user for SSH credentials/Key if this module is selected.

[ ] Use paramiko to establish an SSH connection to the target.

[ ] Execute standard Linux enum commands: sudo -n -l, find / -perm -4000 2>/dev/null, and cat /etc/passwd.

[ ] Parse the stdout to identify writable paths or misconfigured SUIDs.
Acceptance Criteria:

Authenticates successfully via SSH.

Executes commands silently and extracts meaningful configuration data without crashing.

Issue #5: Blue Team Log Correlation Engine

Status: [x] Closed
Description: Build the log_analyzer.py module to read local server logs and identify traces left by our own tool.
Tasks:

[ ] Accept a log file path from the user (e.g., /var/log/apache2/access.log or /var/log/auth.log).

[ ] Implement graceful error handling for missing files or PermissionError.

[ ] Use regular expressions to scan the log file for Nmap User-Agents, Nuclei signatures, and Polyglot payloads.

[ ] Calculate a "Detection Score" based on how many malicious requests were successfully logged.
Acceptance Criteria:

Successfully reads a log file and accurately flags lines matching the tool's attack signatures.

Issue #6: Incident Response Report Generator

Status: [ ] Open
Description: Build report_gen.py to compile the findings dictionary into a professional markdown or HTML report.
Tasks:

[ ] Create a Jinja2 template for the report layout.

[ ] Structure the report with: Executive Summary, Recon Data, Vulnerability Findings, PrivEsc Vectors, and Log Correlation Results.

[ ] Write the function to render the template with the session data and save it to disk.
Acceptance Criteria:

Generates a beautifully formatted, readable Markdown (.md) or HTML file summarizing the entire execution lifecycle.