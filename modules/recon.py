"""
Reconnaissance & Enumeration Module
"""
import shutil
import subprocess
import requests
import re
import os
import json
from typing import Dict, Any, List

def clean_target_for_nmap(target: str) -> str:
    """Removes http/https prefix for nmap."""
    return re.sub(r'^https?://', '', target).rstrip('/')

def format_target_for_web(target: str) -> str:
    """Ensures the target has a valid web schema for python requests & gobuster."""
    if not target.startswith(('http://', 'https://')):
        return f"http://{target}"
    return target

def check_dependencies() -> Dict[str, bool]:
    """
    Checks if required native tools are present in the system PATH.
    """
    deps = {
        'nmap': shutil.which('nmap') is not None,
        'gobuster': shutil.which('gobuster') is not None,
        'whatweb': shutil.which('whatweb') is not None,
        'searchsploit': shutil.which('searchsploit') is not None
    }
    return deps

def run_searchsploit(query: str) -> List[Dict[str, Any]]:
    """Runs searchsploit for a given tech stack query and returns JSON results."""
    if not shutil.which('searchsploit'):
        return []
    try:
        result = subprocess.run(['searchsploit', query, '--json'], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            parsed = json.loads(result.stdout)
            return parsed.get("RESULTS_EXPLOIT", [])[:5]  # Return top 5 results to avoid clutter
    except Exception as e:
        pass
    return []

def stealth_fingerprint(target: str) -> Dict[str, Any]:
    """
    Stealth mode: Max 1-2 standard GET requests.
    Extracts headers and passive HTML meta/script properties.
    """
    stack = {"frontend": [], "web_server": [], "backend": [], "database": []}
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Request 1: Main page
        resp = requests.get(target, timeout=5, verify=False)
        
        # Parse Headers
        if 'Server' in resp.headers:
            stack["web_server"].append(resp.headers['Server'])
        if 'X-Powered-By' in resp.headers:
            stack["backend"].append(resp.headers['X-Powered-By'])
            
        # Passive HTML Parsing
        html = resp.text
        # Generator meta tags
        generator = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.I)
        if generator:
            stack["frontend"].append(generator.group(1))
            
        # Common framework script tags (e.g. React/Next/Nuxt)
        if '_next/static' in html:
            stack["frontend"].append("Next.js")
        if 'data-reactroot' in html:
            stack["frontend"].append("React")
            
    except Exception as e:
        stack["error"] = str(e)
        
    return stack

def noisy_fingerprint(target: str, nmap_target: str) -> Dict[str, Any]:
    """
    Noisy mode: Active probing, forced errors, and nmap framework/enum scripts.
    """
    stack = {"frontend": [], "web_server": [], "backend": [], "database": [], "active_probes": []}
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 1. Active File Probing
    common_files = ['CHANGELOG.md', 'README.txt', 'package.json', '.env']
    for file in common_files:
        try:
            probe_url = f"{target.rstrip('/')}/{file}"
            resp = requests.get(probe_url, timeout=3, verify=False)
            if resp.status_code == 200 and len(resp.text) > 0 and '<html' not in resp.text[:50].lower():
                stack["active_probes"].append(f"Found {file}: {resp.text[:100].strip()}...")
        except:
            pass

    # 2. Trigger Forced HTTP Error (404/500)
    try:
        error_url = f"{target.rstrip('/')}/invalid_path_for_error_123_%ff"
        resp = requests.get(error_url, timeout=5, verify=False)
        server_header = resp.headers.get('Server', '')
        if server_header and server_header not in stack["web_server"]:
            stack["web_server"].append(server_header)
        
        # Analyze error response body for stack traces (e.g. Tomcat, Django, Flask)
        if 'Apache Tomcat' in resp.text:
            version_match = re.search(r'Apache Tomcat/([0-9\.]+)', resp.text)
            if version_match: stack["backend"].append(f"Apache Tomcat {version_match.group(1)}")
        if 'Werkzeug' in resp.text or 'Flask' in resp.text:
            stack["backend"].append("Werkzeug/Flask")
        if 'Django' in resp.text:
            stack["backend"].append("Django")
    except:
        pass

    # 3. Nmap http-enum and http-devframework
    if shutil.which('nmap'):
        try:
            cmd = ['nmap', '-Pn', '-sV', '--script=http-enum,http-devframework', '-p', '80,443', nmap_target]
            nmap_res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stack["active_probes"].append(f"Nmap scripts raw output snippet: {nmap_res.stdout[:500]}...")
            
            # Simple extractor from nmap output
            if 'http-devframework: ' in nmap_res.stdout:
                matches = re.findall(r'http-devframework:\s*(.*)', nmap_res.stdout)
                stack["backend"].extend(matches)
        except:
            pass
            
    return stack

def extract_searchsploit_queries(stack: Dict[str, List[str]]) -> List[str]:
    """Generates searchsploit query strings based on identified stack versions."""
    queries = set()
    for category in ["frontend", "web_server", "backend", "database"]:
        for item in stack.get(category, []):
            # Clean up the item to a useful query, e.g., "Apache/2.4.41 (Ubuntu)" -> "Apache 2.4.41"
            parts = item.replace('/', ' ').replace('(', '').replace(')', '').split()
            if len(parts) >= 2:
                # likely has a version number
                queries.add(f"{parts[0]} {parts[1]}")
            else:
                queries.add(parts[0])
    return list(queries)

def grab_headers(target: str) -> Dict[str, Any]:
    """
    Sends an HTTP GET request to verify the target is online and to grab response headers.
    """
    web_target = format_target_for_web(target)
    findings = {"url": web_target, "is_online": False, "headers": {}}
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
        response = requests.get(web_target, timeout=5, verify=False)
        findings["is_online"] = True
        findings["status_code"] = response.status_code
        findings["headers"] = dict(response.headers)
    except requests.exceptions.RequestException as e:
        findings["error"] = str(e)
        
    return findings

def run_whatweb(target: str) -> Dict[str, Any]:
    """
    Executes whatweb to identify the target's tech stack and plugin versions.
    """
    web_target = format_target_for_web(target)
    cmd = ['whatweb', web_target, '-q', '--log-json=-', '--follow-redirect=always', '-a', '3']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, list) and len(parsed) > 0:
                plugins = parsed[0].get("plugins", {})
                if not plugins:
                    return {"status": "warning", "error_msg": "No plugins found by Whatweb - may indicate redirect or auth issue"}
                return {"status": "success", "tech_stack": plugins}
            return {"status": "error", "error_msg": "No plugins found by Whatweb"}
        except json.JSONDecodeError:
            return {"status": "error", "error_msg": "Failed to parse whatweb JSON"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error_msg": f"Whatweb failed ({e.returncode})"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Whatweb scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error: {e}"}

def run_nmap(target: str, profile: str, http_online: bool = False) -> Dict[str, Any]:
    nmap_target = clean_target_for_nmap(target)
    
    # Determine if we should skip host discovery (-Pn)
    skip_ping = http_online or nmap_target in ['localhost', '127.0.0.1', '::1']
    
    if profile.lower() == 'stealth':
        cmd = ['nmap', '-T2', '-sV']
        if skip_ping:
            cmd.append('-Pn')
        cmd.append(nmap_target)
    else:
        cmd = ['nmap', '-T4', '-A']
        if skip_ping:
            cmd.append('-Pn')
        cmd.append(nmap_target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        return {"status": "success", "raw_output": result.stdout, "skip_ping_used": skip_ping}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error_msg": f"Nmap failed with exit code {e.returncode}", "raw_output": e.stdout + e.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Nmap scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error executing nmap: {e}"}

def run_gobuster(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
    web_target = format_target_for_web(target)
    if not os.path.exists(wordlist):
        return {"status": "skipped", "error_msg": f"Wordlist not found: {wordlist}"}

    cmd = ['gobuster', 'dir', '-u', web_target, '-w', wordlist, '-q', '-e']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        lines = result.stdout.split('\n')
        discovered = [line.strip() for line in lines if line.strip() and ("Status: 2" in line or "Status: 3" in line)]
        return {"status": "success", "raw_output": result.stdout, "discovered_paths": discovered}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error_msg": f"Gobuster failed ({e.returncode})", "raw_output": e.stdout + e.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Gobuster scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error executing gobuster: {e}"}


def run_recon(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the Reconnaissance module.
    """
    target = config.get('target', '')
    profile = config.get('profile', 'Stealth')
    opsec_level = config.get('opsec_level', 'stealth').lower()
    web_target = format_target_for_web(target)
    nmap_target = clean_target_for_nmap(target)
    
    findings: Dict[str, Any] = {
        "target": target,
        "profile": profile,
        "opsec_level": opsec_level,
        "dependencies": {},
        "web_headers": {},
        "tech_stack": {},
        "hierarchical_stack": {},
        "searchsploit_results": {},
        "nmap_scan": {},
        "gobuster_scan": {}
    }
    
    deps = check_dependencies()
    findings["dependencies"] = deps
    findings["web_headers"] = grab_headers(target)
    
    if not findings["web_headers"].get("is_online", False):
        findings["error"] = "Target appears to be offline or unreachable via HTTP. Aborting further recon."
        return findings

    if deps.get('whatweb'):
        findings["tech_stack"] = run_whatweb(target)

    # Issue #2.5: OPSEC-aware Fingerprinting
    if opsec_level == 'stealth':
        stack_findings = stealth_fingerprint(web_target)
    else:
        stack_findings = noisy_fingerprint(web_target, nmap_target)
        
    # Clean duplicates in stack
    for k, v in stack_findings.items():
        if isinstance(v, list):
            stack_findings[k] = list(set(v))
            
    findings["hierarchical_stack"] = stack_findings

    # Issue #2.5: Pipe variables to searchsploit
    if deps.get('searchsploit'):
        queries = extract_searchsploit_queries(stack_findings)
        sploits = {}
        for q in queries:
            res = run_searchsploit(q)
            if res:
                sploits[q] = res
        findings["searchsploit_results"] = sploits
    else:
        findings["searchsploit_results"] = {"error": "Searchsploit not found in PATH."}

    # Standard tool runs
    if deps.get('nmap'):
        http_is_online = findings["web_headers"].get("is_online", False)
        findings["nmap_scan"] = run_nmap(target, profile, http_is_online)
    if deps.get('gobuster'):
        if opsec_level == 'stealth':
            findings["gobuster_scan"] = {"status": "skipped", "error_msg": "Gobuster skipped in stealth mode to prevent logs."}
        else:
            findings["gobuster_scan"] = run_gobuster(target)

    return findings

