#!/usr/bin/env bash
# =============================================================================
# create_issues.sh — Push security tool GitHub issues via the GitHub API
# Usage:  export GITHUB_TOKEN=ghp_yourtoken
#         bash create_issues.sh
# =============================================================================

REPO="${REPO:-your-username/securityOrchestrationTool}"

# -----------------------------------------------------------------------------
API="https://api.github.com/repos/${REPO}/issues"

detect_repo_from_git() {
  local remote_url
  remote_url=$(git remote get-url origin 2>/dev/null || true)

  if [[ -z "$remote_url" ]]; then
    return 1
  fi

  # Supports:
  # - git@github.com:owner/repo.git
  # - https://github.com/owner/repo.git
  # - https://github.com/owner/repo
  if [[ "$remote_url" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
    REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    API="https://api.github.com/repos/${REPO}/issues"
    return 0
  fi

  return 1
}

# Auth strategy:
# 1) Use GITHUB_TOKEN if provided
# 2) Otherwise, try reusing existing GitHub CLI auth session
if [[ -z "$GITHUB_TOKEN" ]]; then
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GITHUB_TOKEN=$(gh auth token 2>/dev/null)
  fi

  if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "❌  No GitHub auth found."
    echo "    Option 1: login once with: gh auth login"
    echo "    Option 2: export GITHUB_TOKEN=ghp_yourtoken"
    exit 1
  fi
fi

if [[ "$REPO" == "your-username/securityOrchestrationTool" ]]; then
  detect_repo_from_git || true
fi

if [[ "$REPO" == "your-username/securityOrchestrationTool" ]]; then
  echo "❌  REPO is still set to placeholder: $REPO"
  echo "    Set it explicitly, for example:"
  echo "    REPO=<owner>/<repo> ./issues.sh"
  echo "    or edit this script and set REPO directly."
  exit 1
fi

# Preflight check so we fail fast with a clear message instead of per-issue 404s.
repo_status=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${REPO}")

if [[ "$repo_status" != "200" ]]; then
  echo "❌  Cannot access repository: $REPO (HTTP $repo_status)"
  echo "    Check owner/repo spelling and ensure your auth can access this repo."
  exit 1
fi

create_issue() {
  local title="$1"
  local body="$2"
  local labels="$3"

  local payload
  payload=$(jq -n \
    --arg title  "$title" \
    --arg body   "$body" \
    --argjson labels "$labels" \
    '{title: $title, body: $body, labels: $labels}')

  local response
  response=$(curl -s -w "\n%{http_code}" \
    -X POST "$API" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Content-Type: application/json" \
    -d "$payload")

  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body_resp
  body_resp=$(echo "$response" | head -n-1)

  if [[ "$http_code" == "201" ]]; then
    local url
    url=$(echo "$body_resp" | jq -r '.html_url')
    echo "✅  Created: $title"
    echo "    $url"
  else
    echo "❌  Failed ($http_code): $title"
    echo "$body_resp" | jq -r '.message // .' 2>/dev/null || echo "$body_resp"
  fi
  sleep 0.5   # stay well under GitHub's rate limit
}

# =============================================================================
# ISSUES
# =============================================================================

echo ""
echo "🚀  Creating issues for: $REPO"
echo "──────────────────────────────────────────────"

# ── CRITICAL BUGS ─────────────────────────────────────────────────────────────

create_issue \
"[BUG] PrivEsc module passes URL scheme (\"http\") as SSH target hostname" \
'## Description
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
```' \
'["bug","critical","privesc"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[BUG] SQLi/XSS fuzzer returns zero findings on a known-vulnerable DVWA target" \
'## Description
The custom fuzzer (error-based SQLi, time-based SQLi, XSS) returns empty findings when run against DVWA — an intentionally vulnerable application.

## Root cause
The fuzzer sends unauthenticated requests. DVWA redirects unauthenticated users to `/login.php` (confirmed in gobuster output: `index.php → ../../login.php`). Payloads are hitting the redirect, not the vulnerable parameter.

## Impact
The core detection capability is non-functional against any app requiring authentication.

## Fix
- Add session/cookie injection support (see related feature issue).
- Allow user to supply a `Cookie:` header (e.g. `PHPSESSID=...`) so requests reach authenticated pages.
- Detect 302 redirects to login pages and warn the user before fuzzing begins.' \
'["bug","critical","fuzzer","auth"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[BUG] Nmap reports 0 hosts up when scanning localhost despite confirmed HTTP connectivity" \
'## Description
Nmap returns `0 IP addresses (0 hosts up)` when the target resolves to localhost/127.0.0.1, even though an HTTP 200 response was received in the same run confirming the host is online.

## Root cause
Nmap'\''s default host discovery uses ICMP ping, which fails or is skipped on the loopback interface.

## Fix
Add `-Pn` to the Nmap command when:
- The target resolves to `127.0.0.1` / `::1`, **or**
- The preceding HTTP connectivity check returned a successful status code.

This tells Nmap to treat the host as up and skip ping-based discovery.' \
'["bug","recon","nmap"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[BUG] WhatWeb fingerprinting silently fails — returns \"No plugins found\"" \
'## Description
WhatWeb returns `No plugins found` even when the target is a running Apache/PHP server, leaving the tech stack detection empty.

## Root cause
WhatWeb likely hits the 302 redirect to `/login.php` and stops analysis before seeing the actual server response headers or content.

## Fix
1. Pass `--follow-redirect` to WhatWeb so it follows login redirects.
2. Set aggression level: `-a 3` for Noisy profile, `-a 1` for Stealth.
3. If WhatWeb still fails, fall back to parsing the raw HTTP headers already collected in `web_headers` (e.g. extract `Server:`, `X-Powered-By:`, `Set-Cookie:` patterns).' \
'["bug","recon","fingerprinting"]'

# ── MISSING FEATURES ──────────────────────────────────────────────────────────

create_issue \
"[FEATURE] Add session/cookie injection for scanning authenticated targets" \
'## Description
Many real-world targets (including DVWA) require authentication. Without session support, all scanning hits the login redirect rather than the actual attack surface.

## Proposed implementation
- Add optional `--cookie` CLI flag accepting a raw `Cookie:` header value
- Propagate the cookie to all HTTP requests across all modules (fuzzer, recon, gobuster)
- Optionally: add auto-login flow — supply a login URL + credentials, tool acquires session cookie automatically before scanning
- Detect 302 → login redirects after the initial HTTP check and surface a warning with a prompt to provide credentials

## Affected modules
Web Vulnerability Fuzzer, Recon (WhatWeb, gobuster)' \
'["feature","fuzzer","recon","auth"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[FEATURE] Make SSH credentials prompt optional — add skip option to PrivEsc module" \
'## Description
The Privilege Escalation Simulator always prompts for SSH credentials with no way to skip. Users who do not want post-exploitation simulation are forced through a dead-end.

## Proposed change
- Make the SSH prompt optional: pressing Enter or selecting "Skip" bypasses it cleanly
- Log `"PrivEsc simulation skipped by user"` in the report when bypassed
- Gate the Blue Team Log Correlation module on whether SSH was actually successful (do not prompt for logs if there is no active session)' \
'["feature","privesc","ux"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[FEATURE] Add default SSH credential brute-force (rate-limit-aware, Noisy mode only)" \
'## Description
Before prompting the user for manual SSH credentials, the tool should attempt a built-in list of default/common credentials — provided no rate limiting is detected.

## Proposed implementation
1. Attempt SSH with a short default credential list:
   `admin/admin`, `root/root`, `root/toor`, `admin/password`, `pi/raspberry`, `user/user`
2. If a connection succeeds → use it, skip manual prompt
3. If rate limiting is detected (repeated resets / exponential delay) → warn user and abort
4. If all defaults fail → fall through to manual credential prompt

## Constraints
- Only runs in **Noisy OPSEC mode**
- Requires rate-limit detection to run first (see related issue)' \
'["feature","privesc","brute-force"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[FEATURE] Blue Team Log Correlation should auto-collect logs via SSH, not prompt for a local file path" \
'## Description
The Log Correlation module currently asks the user to manually enter a path to a log file on their local machine. This is confusing, breaks automation, and misses the point of the feature.

## Expected behaviour
After a successful SSH session in the PrivEsc module:
1. Pass the SSH connection to the Log Correlation module automatically
2. Collect relevant logs from the **compromised host**:
   - `/var/log/auth.log`
   - `/var/log/apache2/access.log`
   - `/var/log/syslog`
3. Filter entries matching the tool'\''s own activity: timestamps from the run window + source IP
4. Present a "blue team view": what did this attack look like in the logs?

## If no SSH session exists
Skip the module automatically — do not prompt the user at all.' \
'["feature","blue-team","log-correlation"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[FEATURE] Skip Log Correlation entirely if no SSH session was established" \
'## Description
The Blue Team Log Correlation module prompts for input even when the PrivEsc module failed or was skipped. This creates a confusing dead-end that makes the tool feel broken.

## Fix
Gate the log correlation module on the existence of a successful SSH session object.

If no session exists (SSH failed, user skipped, or PrivEsc module was not selected):
- Skip the module silently
- Add a note to the report: `"Log Correlation skipped: no shell access obtained"`' \
'["feature","blue-team","flow-control"]'

# ── UX / FLOW ISSUES ──────────────────────────────────────────────────────────

create_issue \
"[UX] Implement conditional module execution — failed modules should gate their dependents" \
'## Description
When a module fails, downstream modules that depend on its output continue to prompt the user, creating confusing dead-ends and wasted input.

## Affected flows
- PrivEsc failure / skip → Log Correlation should be skipped automatically
- Recon failure → Fuzzer should warn that endpoint data may be missing before continuing

## Proposed change
Implement a simple result/status-passing model between modules. Each module returns a structured result object with a `success` flag. Dependent modules check this flag before prompting for input.' \
'["ux","architecture"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[UX] Searchsploit returns irrelevant and outdated exploits — add relevance filtering" \
'## Description
Searchsploit is queried with the full server string (e.g. `Apache 2.4.64`) but returns exploits targeting completely different contexts — PHP CGI vulnerabilities and OpenSSL buffer overflows from 2002. This adds noise and reduces report credibility.

## Proposed improvements
1. Filter by recency: only show CVEs published within the last 5 years by default (configurable)
2. Deduplicate by CVE code, not raw title
3. Flag results as `"version mismatch likely"` when the exploit targets a sub-component not detected in the stack
4. Filter to `Verified: 1` exploits by default; show unverified with a warning label' \
'["ux","recon","searchsploit"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[UX] Report contains raw JSON/dict blobs — restructure into a readable Markdown report" \
'## Description
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
- **Redact sensitive data** (session cookies, passwords) from report output' \
'["ux","reporting"]'

# ── ENHANCEMENTS ──────────────────────────────────────────────────────────────

create_issue \
"[ENHANCEMENT] Detect login redirects before scanning and prompt user for session cookie" \
'## Description
The tool should detect when a target URL results in a redirect to a login page and warn the user that unauthenticated scanning will produce limited/useless results.

## Implementation
- After the initial HTTP check, follow redirects and detect patterns: `/login`, `/signin`, `?redirect=`, session cookie set on redirect response
- Display a warning: `"⚠ Target requires authentication. Provide a session cookie for full coverage."`
- Offer an inline prompt to enter a `Cookie:` header value before all modules run' \
'["enhancement","recon","ux"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[ENHANCEMENT] Auto-select Nuclei templates based on detected tech stack" \
'## Description
Nuclei returned zero findings with no explanation. The scan likely ran with mismatched or default templates for the target tech stack.

## Proposed improvement
After tech stack detection, auto-select relevant Nuclei template tags:
- Apache detected → `-tags apache,misconfig,cve`
- PHP detected → `-tags php,sqli,xss,rce`
- Generic → `-tags exposure,misconfig`

Also:
- Pass `-severity critical,high,medium` in Noisy mode
- Log which template tags were used and the count of templates run vs matched
- Surface "0 templates matched" as a warning, not silent empty output' \
'["enhancement","fuzzer","nuclei"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[ENHANCEMENT] Detect SSH rate limiting before any credential brute-force attempts" \
'## Description
Before attempting default credentials or any SSH brute-force, the tool must detect whether the SSH service has rate limiting or connection throttling in place.

## Detection method
1. Attempt 3 rapid intentionally-failed auth probes
2. Measure response delay and connection behaviour between attempts
3. If connections are dropped, reset repeatedly, or delays increase exponentially → flag as rate-limited
4. If rate limiting detected → skip brute-force, log warning in report
5. If no rate limiting → proceed with default credential list

This avoids account lockout and unnecessary noise on hardened targets.' \
'["enhancement","privesc","brute-force"]'

# ──────────────────────────────────────────────────────────────────────────────

create_issue \
"[ENHANCEMENT] Detect DVWA security level after auth and include it in the report" \
'## Description
DVWA findings vary completely depending on the configured security level (low / medium / high / impossible). The report should detect and document this so findings are correctly contextualised.

## Detection
After obtaining an authenticated session, check:
- `GET /dvwa/security.php` — parse the selected level from the page
- Or read the `security` cookie value

## Report output
Add a note at the top of the findings section:
`"DVWA security level detected: medium — certain vulnerability classes (e.g. basic SQLi) may be filtered at this level."` ' \
'["enhancement","recon","dvwa"]'

# =============================================================================

echo "──────────────────────────────────────────────"
echo "✅  Done. Check your issues at:"
echo "    https://github.com/${REPO}/issues"
echo ""