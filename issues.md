# SecurityOrchestrationTool Issue Tracker

Use this checklist to track completion status while preserving the exact issue text used on GitHub.

- [ ] [BUG] PrivEsc module passes URL scheme ("http") as SSH target hostname

## Description
The privilege escalation module passes the raw URL string (`"http"`) as the SSH target instead of extracting the hostname, causing an immediate connection failure.

## Steps to reproduce
1. Set target to `http://localhost:8080/dvwa/vulnerabilities/sqli/`
2. Run the Privilege Escalation Simulator module

## Expected behaviour
SSH connects to `localhost` (the extracted hostname).

## Actual behaviour
```
Unexpected connection error: [Errno -2] Name or service not known
```
The target was passed as `"http"` — the URL scheme — not the hostname.

## Fix
Parse the target URL before passing it to the SSH client:
```python
from urllib.parse import urlparse
hostname = urlparse(target).hostname
```

Acceptance Criteria / Expected Behaviour:
- "SSH connects to `localhost` (the extracted hostname)."

- [ ] [BUG] SQLi/XSS fuzzer returns zero findings on a known-vulnerable DVWA target

## Description
The custom fuzzer (error-based SQLi, time-based SQLi, XSS) returns empty findings when run against DVWA — an intentionally vulnerable application.

## Root cause
The fuzzer sends unauthenticated requests. DVWA redirects unauthenticated users to `/login.php` (confirmed in gobuster output: `index.php → ../../login.php`). Payloads are hitting the redirect, not the vulnerable parameter.

## Impact
The core detection capability is non-functional against any app requiring authentication.

## Fix
- Add session/cookie injection support (see related feature issue).
- Allow user to supply a `Cookie:` header (e.g. `PHPSESSID=...`) so requests reach authenticated pages.
- Detect 302 redirects to login pages and warn the user before fuzzing begins.

Acceptance Criteria / Expected Behaviour:
- "Allow user to supply a `Cookie:` header (e.g. `PHPSESSID=...`) so requests reach authenticated pages."
- "Detect 302 redirects to login pages and warn the user before fuzzing begins."

- [ ] [BUG] Nmap reports 0 hosts up when scanning localhost despite confirmed HTTP connectivity

## Description
Nmap returns `0 IP addresses (0 hosts up)` when the target resolves to localhost/127.0.0.1, even though an HTTP 200 response was received in the same run confirming the host is online.

## Root cause
Nmap's default host discovery uses ICMP ping, which fails or is skipped on the loopback interface.

## Fix
Add `-Pn` to the Nmap command when:
- The target resolves to `127.0.0.1` / `::1`, **or**
- The preceding HTTP connectivity check returned a successful status code.

This tells Nmap to treat the host as up and skip ping-based discovery.

Acceptance Criteria / Expected Behaviour:
- "This tells Nmap to treat the host as up and skip ping-based discovery."

- [ ] [BUG] WhatWeb fingerprinting silently fails — returns "No plugins found"

## Description
WhatWeb returns `No plugins found` even when the target is a running Apache/PHP server, leaving the tech stack detection empty.

## Root cause
WhatWeb likely hits the 302 redirect to `/login.php` and stops analysis before seeing the actual server response headers or content.

## Fix
1. Pass `--follow-redirect` to WhatWeb so it follows login redirects.
2. Set aggression level: `-a 3` for Noisy profile, `-a 1` for Stealth.
3. If WhatWeb still fails, fall back to parsing the raw HTTP headers already collected in `web_headers` (e.g. extract `Server:`, `X-Powered-By:`, `Set-Cookie:` patterns).

Acceptance Criteria / Expected Behaviour:
- "Pass `--follow-redirect` to WhatWeb so it follows login redirects."

- [ ] [FEATURE] Add session/cookie injection for scanning authenticated targets

## Description
Many real-world targets (including DVWA) require authentication. Without session support, all scanning hits the login redirect rather than the actual attack surface.

## Proposed implementation
- Add optional `--cookie` CLI flag accepting a raw `Cookie:` header value
- Propagate the cookie to all HTTP requests across all modules (fuzzer, recon, gobuster)
- Optionally: add auto-login flow — supply a login URL + credentials, tool acquires session cookie automatically before scanning
- Detect 302 → login redirects after the initial HTTP check and surface a warning with a prompt to provide credentials

## Affected modules
Web Vulnerability Fuzzer, Recon (WhatWeb, gobuster)

Acceptance Criteria / Expected Behaviour:
- "Propagate the cookie to all HTTP requests across all modules (fuzzer, recon, gobuster)"

- [ ] [FEATURE] Make SSH credentials prompt optional — add skip option to PrivEsc module

## Description
The Privilege Escalation Simulator always prompts for SSH credentials with no way to skip. Users who do not want post-exploitation simulation are forced through a dead-end.

## Proposed change
- Make the SSH prompt optional: pressing Enter or selecting "Skip" bypasses it cleanly
- Log `"PrivEsc simulation skipped by user"` in the report when bypassed
- Gate the Blue Team Log Correlation module on whether SSH was actually successful (do not prompt for logs if there is no active session)

Acceptance Criteria / Expected Behaviour:
- "Make the SSH prompt optional: pressing Enter or selecting \"Skip\" bypasses it cleanly"
- "Gate the Blue Team Log Correlation module on whether SSH was actually successful (do not prompt for logs if there is no active session)"

- [ ] [FEATURE] Add default SSH credential brute-force (rate-limit-aware, Noisy mode only)

## Description
Before prompting the user for manual SSH credentials, the tool should attempt a built-in list of default/common credentials — provided no rate limiting is detected.

## Proposed implementation
1. Attempt SSH with a short default credential list:
	`admin/admin`, `root/root`, `root/toor`, `admin/password`, `pi/raspberry`, `user/user`
2. If a connection succeeds → use it, skip manual prompt
3. If rate limiting is detected (repeated resets / exponential delay) → warn user and abort
4. If all defaults fail → fall through to manual credential prompt

## Constraints
- Only runs in **Noisy OPSEC mode**
- Requires rate-limit detection to run first (see related issue)

Acceptance Criteria / Expected Behaviour:
- "If a connection succeeds → use it, skip manual prompt"

- [ ] [FEATURE] Blue Team Log Correlation should auto-collect logs via SSH, not prompt for a local file path

## Description
The Log Correlation module currently asks the user to manually enter a path to a log file on their local machine. This is confusing, breaks automation, and misses the point of the feature.

## Expected behaviour
After a successful SSH session in the PrivEsc module:
1. Pass the SSH connection to the Log Correlation module automatically
2. Collect relevant logs from the **compromised host**:
	- `/var/log/auth.log`
	- `/var/log/apache2/access.log`
	- `/var/log/syslog`
3. Filter entries matching the tool's own activity: timestamps from the run window + source IP
4. Present a "blue team view": what did this attack look like in the logs?

## If no SSH session exists
Skip the module automatically — do not prompt the user at all.

Acceptance Criteria / Expected Behaviour:
- "Pass the SSH connection to the Log Correlation module automatically"
- "Skip the module automatically — do not prompt the user at all."

- [ ] [FEATURE] Skip Log Correlation entirely if no SSH session was established

## Description
The Blue Team Log Correlation module prompts for input even when the PrivEsc module failed or was skipped. This creates a confusing dead-end that makes the tool feel broken.

## Fix
Gate the log correlation module on the existence of a successful SSH session object.

If no session exists (SSH failed, user skipped, or PrivEsc module was not selected):
- Skip the module silently
- Add a note to the report: `"Log Correlation skipped: no shell access obtained"`

Acceptance Criteria / Expected Behaviour:
- "Gate the log correlation module on the existence of a successful SSH session object."

- [ ] [UX] Implement conditional module execution — failed modules should gate their dependents

## Description
When a module fails, downstream modules that depend on its output continue to prompt the user, creating confusing dead-ends and wasted input.

## Affected flows
- PrivEsc failure / skip → Log Correlation should be skipped automatically
- Recon failure → Fuzzer should warn that endpoint data may be missing before continuing

## Proposed change
Implement a simple result/status-passing model between modules. Each module returns a structured result object with a `success` flag. Dependent modules check this flag before prompting for input.

Acceptance Criteria / Expected Behaviour:
- "Dependent modules check this flag before prompting for input."

- [ ] [UX] Searchsploit returns irrelevant and outdated exploits — add relevance filtering

## Description
Searchsploit is queried with the full server string (e.g. `Apache 2.4.64`) but returns exploits targeting completely different contexts — PHP CGI vulnerabilities and OpenSSL buffer overflows from 2002. This adds noise and reduces report credibility.

## Proposed improvements
1. Filter by recency: only show CVEs published within the last 5 years by default (configurable)
2. Deduplicate by CVE code, not raw title
3. Flag results as `"version mismatch likely"` when the exploit targets a sub-component not detected in the stack
4. Filter to `Verified: 1` exploits by default; show unverified with a warning label

Acceptance Criteria / Expected Behaviour:
- "Filter by recency: only show CVEs published within the last 5 years by default (configurable)"
- "Deduplicate by CVE code, not raw title"

- [ ] [UX] Report contains raw JSON/dict blobs — restructure into a readable Markdown report

## Description
The generated report currently dumps raw Python dicts and JSON blobs directly into the output. This is unreadable and unprofessional in a security report context.

## Proposed structure
```
# Security Assessment Report
## Executive Summary
## Target Overview
## Recon Findings (table: component, version, confidence)
## Vulnerabilities Found (table: type, endpoint, severity, evidence)
## Privilege Escalation Results
## Blue Team Log Correlation
## Appendix
```

## Additional improvements
- Replace raw JSON with human-readable tables and bullet points
- Add a severity/risk rating (Critical / High / Medium / Low / Info) per finding
- Add a CVSS-style summary table at the top
- **Redact sensitive data** (session cookies, passwords) from report output

Acceptance Criteria / Expected Behaviour:
- "Replace raw JSON with human-readable tables and bullet points"
- "**Redact sensitive data** (session cookies, passwords) from report output"

- [ ] [ENHANCEMENT] Detect login redirects before scanning and prompt user for session cookie

## Description
The tool should detect when a target URL results in a redirect to a login page and warn the user that unauthenticated scanning will produce limited/useless results.

## Implementation
- After the initial HTTP check, follow redirects and detect patterns: `/login`, `/signin`, `?redirect=`, session cookie set on redirect response
- Display a warning: `"⚠ Target requires authentication. Provide a session cookie for full coverage."`
- Offer an inline prompt to enter a `Cookie:` header value before all modules run

Acceptance Criteria / Expected Behaviour:
- "Display a warning: `\"⚠ Target requires authentication. Provide a session cookie for full coverage.\"`"

- [ ] [ENHANCEMENT] Auto-select Nuclei templates based on detected tech stack

## Description
Nuclei returned zero findings with no explanation. The scan likely ran with mismatched or default templates for the target tech stack.

## Proposed improvement
After tech stack detection, auto-select relevant Nuclei template tags:
- Apache detected → `-tags apache,misconfig,cve`
- PHP detected → `-tags php,sqli,xss,rce`
- Generic → `-tags exposure,misconfig`

Also:
- Pass `-severity critical,high,medium` in Noisy mode
- Log which template tags were used and the count of templates run vs matched
- Surface "0 templates matched" as a warning, not silent empty output

Acceptance Criteria / Expected Behaviour:
- "Log which template tags were used and the count of templates run vs matched"
- "Surface \"0 templates matched\" as a warning, not silent empty output"

- [ ] [ENHANCEMENT] Detect SSH rate limiting before any credential brute-force attempts

## Description
Before attempting default credentials or any SSH brute-force, the tool must detect whether the SSH service has rate limiting or connection throttling in place.

## Detection method
1. Attempt 3 rapid intentionally-failed auth probes
2. Measure response delay and connection behaviour between attempts
3. If connections are dropped, reset repeatedly, or delays increase exponentially → flag as rate-limited
4. If rate limiting detected → skip brute-force, log warning in report
5. If no rate limiting → proceed with default credential list

This avoids account lockout and unnecessary noise on hardened targets.

Acceptance Criteria / Expected Behaviour:
- "If rate limiting detected → skip brute-force, log warning in report"

- [ ] [ENHANCEMENT] Detect DVWA security level after auth and include it in the report

## Description
DVWA findings vary completely depending on the configured security level (low / medium / high / impossible). The report should detect and document this so findings are correctly contextualised.

## Detection
After obtaining an authenticated session, check:
- `GET /dvwa/security.php` — parse the selected level from the page
- Or read the `security` cookie value

## Report output
Add a note at the top of the findings section:
`"DVWA security level detected: medium — certain vulnerability classes (e.g. basic SQLi) may be filtered at this level."`

Acceptance Criteria / Expected Behaviour:
- "Add a note at the top of the findings section: `\"DVWA security level detected: medium — certain vulnerability classes (e.g. basic SQLi) may be filtered at this level.\"`"

---

# Run 2 Issue Tracker

- [ ] [BUG] Nmap -Pn flag not reaching the actual scan command — still reports 0 hosts up

## Description
`skip_ping_used: True` now appears in the findings JSON, confirming the flag is being set in code — but Nmap still reports `0 IP addresses (0 hosts up)` against a live target (`10.1.1.3`).

## Evidence (run 2 output)
```
nmap_scan: {
	status: success,
	raw_output: "Nmap done: 0 IP addresses (0 hosts up) scanned in 0.48 seconds",
	skip_ping_used: True
}
```

## Root cause
The `skip_ping_used` flag is being set on the result dict but is not being correctly interpolated into the subprocess call that actually runs Nmap. Likely the `-Pn` flag is appended to the wrong variable, or the command list is built before the flag is added.

## Fix
1. Verify the Nmap subprocess call includes `-Pn` by logging the full command before execution.
2. Ensure `-Pn` is always injected when `is_online: True` is confirmed by the HTTP check.
3. Also verify the target hostname/IP is being passed to Nmap correctly (not the full URL string).

## Expected output
```
Nmap scan report for 10.1.1.3
Host is up (0.00Xs latency).
PORT   STATE SERVICE
80/tcp open  http
```

Acceptance Criteria / Expected Behaviour:
- "Nmap scan report for 10.1.1.3"
- "Host is up (0.00Xs latency)."

- [ ] [BUG] Log Correlation module still prompts for a manual file path instead of using the SSH session

## Description
After a successful SSH session is established in the PrivEsc module, the Log Correlation module still asks the user to manually enter a log file path. The SSH session object is not being passed between modules.

## Evidence (run 2 output)
```
[+] PrivEsc Simulation complete. SSH session established successfully.
[*] Launching Blue Team Log Correlation Engine...
? Enter path to the log file to analyze (e.g., /var/log/apache2/access.log):
```

## Root cause
No inter-module result passing exists. The SSH session established by PrivEsc is discarded at module boundary. Log Correlation starts fresh with no knowledge a session exists.

## Expected behaviour
1. PrivEsc module returns a session object on success.
2. Log Correlation receives this session and uses it to pull logs from the **remote target** via SFTP/exec.
3. The manual file path prompt is skipped entirely when a session is available.

## Files to auto-collect from remote host
- `/var/log/apache2/access.log`
- `/var/log/auth.log`
- `/var/log/syslog`

Acceptance Criteria / Expected Behaviour:
- "The manual file path prompt is skipped entirely when a session is available."

- [ ] [BUG] Log Correlation module reads Kali's own log file, not the target's

## Description
When the user enters `/var/log/apache2/access.log`, the module reads that path from the **local Kali machine**, which is empty. The target host's logs are never fetched.

## Evidence (run 2 output)
```
? Enter path to the log file to analyze: /var/log/apache2/access.log
[+] Log Analysis complete. Detection Score: 0
{
	log_file: /var/log/apache2/access.log,
	total_lines_analyzed: 0,
	detection_score: 0,
	matches: {nmap: [], nuclei: [], polyglot: []}
}
```
`total_lines_analyzed: 0` confirms the local file is empty — Kali's Apache is not running.

## Root cause
The module opens the file path locally (`open(log_file)`) instead of fetching it from the remote host over the SSH session.

## Fix
Use the established paramiko SSH session to pull the file:
```python
sftp = ssh_session.open_sftp()
with sftp.open(remote_path, "r") as f:
	lines = f.readlines()
```
Or execute `cat /var/log/apache2/access.log` remotely and capture stdout.

## This is the core "blue team" value prop — it is currently completely non-functional.

- [ ] [BUG] No inter-module result passing — SSH session and recon data lost at module boundaries

## Description
Each module runs independently with no shared state. Critical outputs (SSH session, detected tech stack, session cookie, DVWA security level) are not passed forward to dependent modules.

## Observed consequences
- SSH session from PrivEsc not received by Log Correlation → manual prompt shown
- Detected tech stack from Recon not received by Fuzzer → Nuclei runs with no template tags
- Log Correlation reads local files because it has no reference to the remote session

## Proposed fix
Introduce a shared `OrchestrationContext` object passed through the module execution chain:

```python
class OrchestrationContext:
	target: str
	cookie: str | None
	ssh_session: paramiko.SSHClient | None
	tech_stack: dict
	dvwa_level: str | None
	recon_findings: dict
```

Each module receives and updates this context. Downstream modules check context fields before prompting the user.

- [ ] [BUG] Searchsploit still returns irrelevant exploits from 2002–2013 with no filtering

## Description
Searchsploit results are unchanged from run 1. Ancient, unrelated exploits still appear — including a 2002 OpenSSL buffer overflow — when querying for Apache 2.4.64.

## Evidence (run 2 output)
- `Apache mod_ssl < 2.8.7 OpenSSL — OpenFuck.c Remote Buffer Overflow` (published **2002-07-30**)
- `Apache + PHP < 5.3.12 — cgi-bin Remote Code Execution` (published **2013-10-29**)
- `Apache CXF < 2.5.10 — Denial of Service` (published **2013-07-09**)

None of these are relevant to Apache 2.4.64 in 2026.

## Fix
Post-process searchsploit results before display:
```python
from datetime import datetime, timedelta
cutoff = datetime.now() - timedelta(days=365 * 5)  # last 5 years, configurable
results = [r for r in results if datetime.strptime(r["Date_Published"], "%Y-%m-%d") > cutoff]
```
Additionally:
- Filter to `Verified: "1"` by default
- Flag results where the exploit target does not match any detected stack component
- Deduplicate by CVE code

- [ ] [BUG] Terminal and report output still contains raw Python dict / JSON blobs

## Description
The tool prints full raw Python dicts to the terminal after every module. The report likely mirrors this. This is unreadable, leaks sensitive values (session cookies, credentials), and looks unprofessional.

## Evidence (run 2 output)
Full `web_headers`, `tech_stack`, `searchsploit_results`, `nmap_scan`, `gobuster_scan`, and `dvwa_security_level` dicts are printed verbatim to the terminal.

## Sensitive data currently exposed in output
- `PHPSESSID` cookie value visible in raw `tech_stack` dict
- SSH credentials potentially logged

## Fix
1. Replace terminal output with a human-readable summary per module:
```
[+] Recon complete
	Web server : Apache/2.4.64 (Ubuntu)
	OS         : Ubuntu Linux
	DVWA level : impossible
	Paths found: /dvwa/.../help, /dvwa/.../source
	Exploits   : 2 potentially relevant (filtered from 5)
```
2. Structure the saved Markdown report with proper sections, tables, and severity labels.
3. Redact session cookies and credentials from all output.

- [ ] [BUG] Default SSH brute-force partially implemented — brute-force errors not handled gracefully

## Description
The default credential brute-force runs but crashes with a raw paramiko traceback when SSH port is closed or the service rejects the banner read. The error is not caught and the full stack trace is printed to the terminal.

## Evidence (run 2 output)
```
Exception (client): Error reading SSH protocol banner
Traceback (most recent call last):
  File ".../paramiko/transport.py", line 2363, in _check_banner
	...
paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
Brute-force stopped due to error: Error reading SSH protocol banner
```

## Root cause
The brute-force loop catches some exceptions but not `SSHException` from the banner read, which happens when port 22 is closed or filtered. The exception propagates up and prints a full traceback.

## Fix
```python
import socket
from paramiko.ssh_exception import SSHException

# Pre-check before any brute-force attempt
sock = socket.socket()
sock.settimeout(3)
result = sock.connect_ex((hostname, 22))
sock.close()
if result != 0:
	print("[!] Port 22 is closed or filtered — skipping SSH brute-force.")
	return

# Wrap all paramiko calls
try:
	client.connect(...)
except (SSHException, EOFError, socket.error) as e:
	print(f"[!] SSH connection failed: {e}")
```

- [ ] [BUG] Nuclei template auto-selection wired incorrectly — tags not passed despite stack detection

## Description
The tech stack is now correctly detected (Apache/Ubuntu) but Nuclei still runs with no template tags. The stack data is not being read by the fuzzer module when building the Nuclei command.

## Evidence (run 2 output)
```
[*] Using detected tech stack for intelligent template selection.
⚠ Nuclei returned 0 findings. Tags used: none.
```
Apache was clearly in the tech stack (`web_server: ["Apache/2.4.64 (Ubuntu)"]`) but no tags were derived.

## Root cause
The fuzzer module likely reads from a stack key that does not match what the recon module actually produces. Possible mismatch: reading `hierarchical_stack.web_server` vs `tech_stack.HTTPServer`, or the tag-mapping dict does not have an entry for the detected string format.

## Fix
```python
tag_map = {
	"apache": ["apache", "misconfig", "cve"],
	"php":    ["php", "sqli", "xss", "rce"],
	"nginx":  ["nginx", "misconfig"],
	"mysql":  ["mysql", "sqli"],
}
detected_tags = []
for component in hierarchical_stack.get("web_server", []):
	for key, tags in tag_map.items():
		if key in component.lower():
			detected_tags.extend(tags)

nuclei_cmd = ["nuclei", "-u", target, "-tags", ",".join(set(detected_tags))]
```

Also log the full Nuclei command before execution so it can be debugged.

- [ ] [BUG] SSH brute-force crashes with full paramiko traceback instead of clean error message

## Description
When the SSH brute-force encounters a connection error (e.g. port closed, banner read failure), the full paramiko stack trace is printed to the terminal. This is noisy, confusing, and unprofessional.

## Evidence (run 2 output)
```
Exception (client): Error reading SSH protocol banner
Traceback (most recent call last):
  File ".../paramiko/transport.py", line 2363, in _check_banner
	buf = self.packetizer.readline(timeout)
  ...
paramiko.ssh_exception.SSHException: Error reading SSH protocol banner
```

## Fix
Wrap the entire brute-force execution block in a top-level exception handler:

```python
try:
	client.connect(hostname, username=user, password=pwd, timeout=5)
except paramiko.ssh_exception.SSHException as e:
	print(f"[!] SSH error: {e} — skipping.")
except EOFError:
	print("[!] SSH port closed or not an SSH service — aborting brute-force.")
	break
except Exception as e:
	print(f"[!] Unexpected error during brute-force: {type(e).__name__}: {e}")
	break
```

The terminal should never show a raw traceback to the end user.

- [ ] [BUG] No pre-check for SSH port availability before brute-force attempts

## Description
The brute-force module attempts SSH connections without first verifying that port 22 is open on the target. If the port is closed or the service is not SSH, every credential attempt fails with a banner error rather than fast-failing cleanly.

## Evidence (run 2 output)
`Error reading SSH protocol banner` — the service on the target's port 22 either is not SSH or is not reachable, but the tool attempted multiple connections anyway.

## Fix
Add a pre-flight socket check before the brute-force loop:

```python
import socket

def is_ssh_open(hostname, port=22, timeout=3):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		result = sock.connect_ex((hostname, port))
		sock.close()
		return result == 0
	except Exception:
		return False

if not is_ssh_open(target_host):
	print(f"[!] Port 22 is closed on {target_host} — skipping SSH brute-force.")
	return {"status": "skipped", "reason": "port_22_closed"}
```

This should run before rate-limit detection and before any paramiko import to fail fast.

- [ ] [BUG] Log Correlation reads from local filesystem instead of fetching from the remote target over SSH

## Description
The Log Correlation module opens the user-provided path as a local file. Since the path (`/var/log/apache2/access.log`) does not exist on Kali, it reads 0 lines and produces a detection score of 0. The target's logs are never examined.

## Evidence (run 2 output)
```
? Enter path to the log file: /var/log/apache2/access.log
total_lines_analyzed: 0
detection_score: 0
matches: {nmap: [], nuclei: [], polyglot: []}
```

## Root cause
```python
with open(log_file, "r") as f:   # reads LOCAL file
	lines = f.readlines()
```

## Fix
Use the paramiko SSH session to fetch the remote file:

```python
sftp = ssh_session.open_sftp()
with sftp.open(remote_log_path, "r") as f:
	lines = f.readlines()
sftp.close()
```

Or execute remotely and capture output:
```python
_, stdout, _ = ssh_session.exec_command(f"cat {remote_log_path}")
lines = stdout.readlines()
```

## Logs to auto-collect (do not prompt user)
- `/var/log/apache2/access.log`
- `/var/log/apache2/error.log`
- `/var/log/auth.log`
- `/var/log/syslog`

- [ ] [BUG] Nuclei tag wiring broken — detected tech stack not read by fuzzer module

## Description
Despite the recon module correctly identifying Apache in the tech stack, the fuzzer module builds the Nuclei command with no tags. The stack output from recon is not being consumed by the fuzzer.

## Evidence (run 2 output)
```
[*] Using detected tech stack for intelligent template selection.
⚠ Nuclei returned 0 findings. Tags used: none.
```
The recon module produced:
```json
"web_server": ["Apache/2.4.64 (Ubuntu)"]
```
But this was not translated into Nuclei tags.

## Root cause (likely)
The fuzzer module reads from a key that does not exist or uses a different data path than what recon outputs. For example, reading `tech_stack["backend"]` (empty) instead of `tech_stack["web_server"]`.

## Fix
1. Log the full Nuclei command string before execution so the tags argument is visible.
2. Fix the key path and add a tag-mapping dict:
```python
tag_map = {
	"apache": ["apache", "misconfig", "cve"],
	"php":    ["php", "sqli", "xss", "rce"],
	"nginx":  ["nginx", "misconfig"],
	"iis":    ["iis"],
}
```
3. Fall back to broad tags (`-tags misconfig,exposure`) if no specific match is found rather than running with no tags at all.
