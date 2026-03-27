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

def _select_nuclei_tags(tech_stack: Dict[str, List[str]], profile: str) -> List[str]:
    """
    Issue #35 & #31: Auto-select Nuclei template tags based on detected tech stack.
    Returns a list of tags to pass to nuclei -tags flag.
    """
    tags = set()
    
    # Default tags for all scans
    tags.add("exposure")
    tags.add("misconfig")
    
    # Parse tech stack from recon results
    all_components = []
    for category, items in tech_stack.items():
        if isinstance(items, list):
            all_components.extend([item.lower() for item in items])
    
    tech_string = ' '.join(all_components)
    
    # Issue #35 fix: Log what we received for debugging
    if not tech_string.strip():
        # Empty tech stack - return default tags
        return ["exposure", "misconfig", "cve"]
    
    # Apache-specific tags
    if 'apache' in tech_string:
        tags.update(['apache', 'httpd', 'cve'])
    
    # PHP-specific tags
    if 'php' in tech_string:
        tags.update(['php', 'sqli', 'xss', 'rce'])
    
    # Nginx-specific
    if 'nginx' in tech_string:
        tags.add('nginx')
    
    # Database-specific
    if any(db in tech_string for db in ['mysql', 'mariadb', 'postgres', 'mongodb']):
        tags.update(['sqli', 'db'])
    
    # WordPress, Joomla, Drupal
    if 'wordpress' in tech_string or 'wp-' in tech_string:
        tags.update(['wordpress', 'wp-plugin'])
    if 'joomla' in tech_string:
        tags.add('joomla')
    if 'drupal' in tech_string:
        tags.add('drupal')
    
    # JavaScript frameworks
    if any(js in tech_string for js in ['react', 'vue', 'angular', 'next']):
        tags.update(['js', 'xss'])
    
    # Default to generic web tags if nothing specific detected
    if len(tags) == 2:  # Only has exposure + misconfig
        tags.update(['cve', 'generic'])
    
    return list(tags)


def run_nuclei(target: str, config: Dict[str, Any], auto_update: bool = True) -> Dict[str, Any]:
    """
    Executes Nuclei against the target URL using tech-stack-aware template selection
    and JSONL output for easy parsing. (Issue #35 & #31)
    """
    web_target = format_target_for_web(target)
    profile = config.get('profile', 'Stealth').lower()
    cookie = config.get('cookie', None)
    
    # Issue #35 & #31 fix: Get tech stack from recon results if available
    tech_stack = config.get('hierarchical_stack', {})
    
    # Issue #35 fix: If hierarchical_stack is empty, try alternative keys
    if not tech_stack or not any(tech_stack.values()):
        tech_stack = config.get('tech_stack', {})
    
    # Select appropriate tags
    selected_tags = _select_nuclei_tags(tech_stack, profile)
    
    # Issue #35 fix: Ensure we always have tags (defensive)
    if not selected_tags:
        selected_tags = ['exposure', 'misconfig', 'cve']
    
    tags_str = ','.join(selected_tags)
    
    templates_path = _find_nuclei_templates_path()
    fallback_template_file = ""
    
    # -silent: removes banner, -jsonl: JSON Lines output
    cmd = [
        'nuclei', 
        '-u', web_target, 
        '-jsonl', 
        '-silent'
    ]
    
    # Issue #35 fix: Only add -tags if we have non-empty tags
    if tags_str:
        cmd.extend(['-tags', tags_str])
    
    # Issue #35: Add severity filter for Noisy mode
    if profile == 'noisy':
        cmd.extend(['-severity', 'critical,high,medium'])
    else:
        cmd.extend(['-severity', 'critical,high'])
    
    # Add cookie if provided
    if cookie:
        cmd.extend(['-H', f'Cookie: {cookie}'])
    
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
        
        # Issue #35 & #31: Log template selection metadata with debug info
        return {
            "status": "success", 
            "findings": parsed_findings,
            "meta": {
                "tags_used": selected_tags,
                "tags_string": tags_str if tags_str else "none",
                "templates_matched": len(parsed_findings),
                "severity_filter": "critical,high,medium" if profile == 'noisy' else "critical,high",
                "tech_stack_received": bool(tech_stack and any(tech_stack.values())),
                "tech_stack_keys": list(tech_stack.keys()) if tech_stack else []
            }
        }
        
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

def _validate_cookie_format(cookie: str) -> bool:
    """Validate basic structure of a cookie string."""
    return bool(re.match(r'^([a-zA-Z0-9_]+=[^;]+)(;[ ]?[a-zA-Z0-9_]+=[^;]+)*$', cookie))

def run_fuzzer(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the Web Vulnerability Fuzzer module.
    Issue #21: Now passes config to run_nuclei for tech-stack-aware template selection.
    """
    target = config.get('target', '')
    cookie = config.get('cookie', None)  # Optional cookie for authenticated scanning
    
    results = {
        "target": target,
        "dependencies": {},
        "nuclei_scan": {},
        "custom_fuzzer": {}
    }
    
    # Validate session cookie if provided
    if cookie and not _validate_cookie_format(cookie):
        results["errors"] = results.get("errors", [])
        results["errors"].append("Invalid cookie format detected. Cookie injection skipped.")
        cookie = None
        config['cookie'] = None
    
    deps = check_dependencies()
    results["dependencies"] = deps
    
    if deps.get('nuclei'):
        # Issue #21: Pass config to enable tech-stack-aware template selection
        results["nuclei_scan"] = run_nuclei(target, config)
        
        # Issue #21: Surface warning if 0 templates matched
        nuclei_meta = results["nuclei_scan"].get("meta", {})
        if nuclei_meta.get("templates_matched", 0) == 0:
            results["nuclei_scan"]["warning"] = (
                f"⚠ Nuclei returned 0 findings. "
                f"Tags used: {nuclei_meta.get('tags_string', 'none')}. "
                f"This may indicate templates are unavailable or target has no matching vulnerabilities."
            )
    else:
        results["nuclei_scan"] = {"status": "skipped", "error_msg": "Nuclei is not installed or not in PATH."}
        
    results["custom_fuzzer"] = custom_fuzzer(target, cookie)
    
    return results
