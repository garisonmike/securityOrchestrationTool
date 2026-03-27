"""
Web Vulnerability Fuzzer Module
"""
import shutil
import subprocess
import requests
import re
import json
import os
import tempfile
from typing import Dict, Any, List
import urllib3

# Suppress insecure request warnings for local/test HTTPS servers
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common database error signatures
DB_ERROR_REGEXES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PostgreSQL query failed",
    r"ORA-[0-9][0-9][0-9][0-9]",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver",
    r"Syntax error in string in query expression"
]

def format_target_for_web(target: str) -> str:
    """Ensures the target has a valid web schema for requests and nuclei."""
    if not target.startswith(('http://', 'https://')):
        return f"http://{target}"
    return target

def check_dependencies() -> Dict[str, bool]:
    """Check if Nuclei is present."""
    return {
        'nuclei': shutil.which('nuclei') is not None
    }

def _has_template_files(path: str) -> bool:
    """Return True when a path contains at least one nuclei YAML template file."""
    if not os.path.isdir(path):
        return False

    for root, _, files in os.walk(path):
        for filename in files:
            if filename.endswith((".yaml", ".yml")):
                return True
    return False

def _find_nuclei_templates_path() -> str:
    """Find a usable local nuclei-templates directory with real template files."""
    candidate_paths = [
        os.path.expanduser("~/.local/nuclei-templates"),
        os.path.expanduser("~/nuclei-templates"),
        "/usr/share/nuclei-templates",
        "/opt/nuclei-templates",
    ]

    for path in candidate_paths:
        if _has_template_files(path):
            return path

    return ""

def _create_fallback_nuclei_template() -> str:
    """Create a minimal local template so nuclei can run without downloaded template packs."""
    fallback_template = """id: local-http-title-check
info:
  name: Local HTTP Title Check
  author: security-orchestration-tool
  severity: info
  description: Basic fallback template used when nuclei template packs are unavailable.

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        words:
          - "<title"
        part: body
        condition: and
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tf:
        tf.write(fallback_template)
        return tf.name

def run_nuclei(target: str, auto_update: bool = True) -> Dict[str, Any]:
    """
    Executes Nuclei against the target URL using specific tags 
    for fast execution and JSONL output for easy parsing.
    """
    web_target = format_target_for_web(target)
    templates_path = _find_nuclei_templates_path()
    fallback_template_file = ""
    
    # -silent: removes banner, -jsonl: JSON Lines output
    cmd = [
        'nuclei', 
        '-u', web_target, 
        '-jsonl', 
        '-silent'
    ]
    
    if templates_path:
        cmd.extend(['-t', templates_path])
    elif auto_update:
        try:
            subprocess.run(['nuclei', '-update-templates'], capture_output=True, text=True, check=True, timeout=120)
            templates_path = _find_nuclei_templates_path()
            if templates_path:
                cmd.extend(['-t', templates_path])
            else:
                fallback_template_file = _create_fallback_nuclei_template()
                cmd.extend(['-t', fallback_template_file])
        except subprocess.CalledProcessError as e:
            fallback_template_file = _create_fallback_nuclei_template()
            cmd.extend(['-t', fallback_template_file])
        except Exception as e:
            fallback_template_file = _create_fallback_nuclei_template()
            cmd.extend(['-t', fallback_template_file])
    else:
        fallback_template_file = _create_fallback_nuclei_template()
        cmd.extend(['-t', fallback_template_file])

    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=600 # 10 minute timeout maximum
        )
        
        parsed_findings = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    parsed_findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
                    
        return {"status": "success", "findings": parsed_findings}
        
    except subprocess.CalledProcessError as e:
        error_output = str(e.stdout) + str(e.stderr)
        return {"status": "error", "error_msg": f"Nuclei failed ({e.returncode})", "raw_output": error_output}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Nuclei scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error executing nuclei: {e}"}
    finally:
        if fallback_template_file and os.path.exists(fallback_template_file):
            try:
                os.remove(fallback_template_file)
            except OSError:
                pass

def custom_fuzzer(target: str, cookie: str = None) -> Dict[str, Any]:
    """
    Implements intelligent custom fuzzing to detect Error-Based SQLi,
    Time-Based SQLi, and Reflected XSS with low false positives.
    Supports optional cookie authentication.
    """
    web_target = format_target_for_web(target)
    findings = {"xss": [], "sqli_error": [], "sqli_time": [], "errors": [], "warnings": []}
    
    # Prepare headers with optional cookie
    headers = {}
    if cookie:
        headers['Cookie'] = cookie
    
    # We append a dummy parameter to trigger reflections/errors if the app isn't explicitly param-routed
    test_url = web_target if '?' in web_target else f"{web_target}?q="
    
    # Check for authentication redirects before fuzzing
    try:
        probe_res = requests.get(test_url, headers=headers, timeout=10, verify=False, allow_redirects=False)
        if probe_res.status_code in [301, 302, 303, 307, 308]:
            redirect_location = probe_res.headers.get('Location', '')
            if any(pattern in redirect_location.lower() for pattern in ['/login', '/signin', '/auth']):
                findings["warnings"].append(
                    f"⚠ Target requires authentication. Detected redirect to login page: {redirect_location}. "
                    "Provide a session cookie for full coverage."
                )
                return findings
    except requests.RequestException as e:
        findings["errors"].append(f"Authentication check request failed: {e}")

    # 1. Error-Based SQLi & XSS Polyglot Detection
    xss_marker = "NCI_HACKATHON"
    polyglot_payload = f"'\"><svg/onload=alert('{xss_marker}')> OR 1=1; --"
    
    try:
        res = requests.get(f"{test_url}{polyglot_payload}", headers=headers, timeout=10, verify=False)
        
        # Check XSS Reflection
        reflection_pattern = f"alert\\('{xss_marker}'\\)"
        if xss_marker in res.text and re.search(reflection_pattern, res.text):
            findings["xss"].append(f"Highly likely XSS. Unmodified reflection of payload matched at {test_url}")
            
        # Check Error-Based SQLi
        for db_err in DB_ERROR_REGEXES:
            if re.search(db_err, res.text, re.IGNORECASE):
                findings["sqli_error"].append(f"Database error leaked matching '{db_err}' structure.")
                break # Map one error per request is enough
                
    except requests.RequestException as e:
        findings["errors"].append(f"Polyglot fuzzing request failed: {e}")

    # 2. Time-Based SQLi Detection
    time_payloads = [
        "1' OR SLEEP(5)--",
        "1' OR pg_sleep(5)--"
    ]
    
    for payload in time_payloads:
        try:
            # First measure baseline with a harmless request
            baseline_res = requests.get(f"{test_url}1", headers=headers, timeout=10, verify=False)
            baseline_time = baseline_res.elapsed.total_seconds()
            
            # Now trigger sleep (We set a timeout of 15 seconds to allow the 5s sleep to complete)
            time_res = requests.get(f"{test_url}{payload}", headers=headers, timeout=15, verify=False)
            attack_time = time_res.elapsed.total_seconds()
            
            # If the attack request took at least 4.5 seconds longer than the baseline, it's highly suspicious
            if attack_time >= 4.5 and attack_time >= (baseline_time + 4.5):
                findings["sqli_time"].append(f"Potential Time-Based SQLi. Payload '{payload}' delayed response by {attack_time}s.")
                
        except requests.exceptions.ReadTimeout:
             # A timeout could also mean the sleep worked too well, or server dropped it. We log it as a hint.
             findings["sqli_time"].append(f"Request timed out with payload '{payload}'. Potential Time-Based SQLi.")
        except requests.RequestException as e:
             findings["errors"].append(f"Time-based fuzzing request failed: {e}")

    return findings

def run_fuzzer(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the Web Vulnerability Fuzzer module.
    """
    target = config.get('target', '')
    cookie = config.get('cookie', None)  # Optional cookie for authenticated scanning
    
    results = {
        "target": target,
        "dependencies": {},
        "nuclei_scan": {},
        "custom_fuzzer": {}
    }
    
    deps = check_dependencies()
    results["dependencies"] = deps
    
    if deps.get('nuclei'):
        results["nuclei_scan"] = run_nuclei(target)
    else:
        results["nuclei_scan"] = {"status": "skipped", "error_msg": "Nuclei is not installed or not in PATH."}
        
    results["custom_fuzzer"] = custom_fuzzer(target, cookie)
    
    return results
