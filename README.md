# Automated Security Orchestration Engine

A professional, Python-based DevSecOps command-line tool designed to orchestrate security assessments, simulate vulnerability exploitation, and correlate blue team logs. 

*Note: This project was originally developed as part of a Capture The Flag (CTF) challenge.*

##  Disclaimer
**This tool is strictly for educational purposes and authorized security testing.** 
The offensive modules included within this tool must only be run against networks and systems for which you have explicit, documented permission. The authors and contributors are not responsible for any misuse, damage, or illegal activities caused by utilizing this software.

## Features

- **Reconnaissance & Enumeration**: Automates `nmap` and `gobuster` workflows to map attack surfaces, parsing HTTP headers and identifying targets using stealthy or noisy scan profiles.
- **Web Vulnerability Fuzzing**: Harnesses `nuclei` and a custom Python polyglot fuzzer to deeply examine parameters for Time/Error-based SQL Injection, Reflected Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), and misconfigurations.
- **Privilege Escalation Simulation**: Uses `paramiko` to establish authenticated SSH connections, checking for SUID binaries, writable path misconfigurations, and standard `sudo` privesc avenues without risking environment stability.
- **Blue Team Log Correlation**: Actively scans local server logs for traces of its own execution (identifying Nmap agents, Nuclei tags, and polyglot drops) to compute a concrete Detection Score, enabling SOC teams to validate telemetry in real-time.
- **Incident Response Reporting**: Dynamically renders execution artifacts using `Jinja2` into sleek Markdown and HTML reports, utilizing `wkhtmltopdf` when available to produce presentation-ready PDF incident briefings.

## Prerequisites

Ensure the following OS-level dependencies are accessible in your `$PATH` to leverage full module automation:

- `nmap`
- `gobuster`
- `nuclei`
- `wkhtmltopdf` *(Optional: Required for HTML to PDF conversion)*
- `apt` (For automatic dependency bootstrapping in Debian/Ubuntu environments)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/securityOrchestrationTool.git
   cd securityOrchestrationTool
   ```

2. Generate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

You must execute the engine within the virtual environment.

```bash
python main.py
```

An interactive configuration menu will load, allowing you to establish your Target IP/URL, declare scanning aggressiveness, hand-pick modules (Recon, Fuzzing, PrivEsc, Log Correlation), and configure the final reporting format.

## Architecture

```text
├── main.py                   # Central interactive orchestrator
├── requirements.txt          # Python dependencies
├── modules/
│   ├── recon.py              # OS-level scanning wrappers
│   ├── web_fuzzer.py         # Advanced polyglot and nuclei execution
│   ├── privesc.py            # Post-exploitation via ssh
│   ├── log_analyzer.py       # Indicator of Compromise log evaluation
│   └── report_gen.py         # Jinja2 documentation parser
└── templates/                # Report layout schemas (.j2)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
