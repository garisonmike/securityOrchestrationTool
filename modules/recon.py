"""
Reconnaissance & Enumeration Module
"""
import shutil
import subprocess
import requests
import re
import os
from typing import Dict, Any, Optional

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
    Checks if required native tools (nmap, gobuster) are present in the system PATH.
    """
    deps = {
        'nmap': shutil.which('nmap') is not None,
        'gobuster': shutil.which('gobuster') is not None
    }
    return deps

def grab_headers(target: str) -> Dict[str, str]:
    """
    Sends an HTTP GET request to verify the target is online and to grab response headers.
    """
    web_target = format_target_for_web(target)
    findings = {"url": web_target, "is_online": False, "headers": {}}
    
    try:
        import urllib3
        # Timeout set to 5 seconds to prevent hanging, suppress insecure warnings for missing certs
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
        response = requests.get(web_target, timeout=5, verify=False)
        findings["is_online"] = True
        findings["status_code"] = response.status_code
        findings["headers"] = dict(response.headers)
    except requests.exceptions.RequestException as e:
        findings["error"] = str(e)
        
    return findings

def run_nmap(target: str, profile: str) -> Dict[str, Any]:
    """
    Executes an Nmap scan (Stealth vs. Noisy) against the target.
    Handles subprocess timeouts and errors cleanly.
    """
    nmap_target = clean_target_for_nmap(target)
    
    # Define flags based on profile
    if profile.lower() == 'stealth':
        # -T2 (Polite), -sV (Version detection)
        cmd = ['nmap', '-T2', '-sV', nmap_target]
    else:
        # Noisy: -T4 (Aggressive), -A (OS detection, version, scripts, traceroute)
        cmd = ['nmap', '-T4', '-A', nmap_target]

    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=300 # Wait at most 5 minutes for nmap
        )
        return {"status": "success", "raw_output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error_msg": f"Nmap failed with exit code {e.returncode}", "raw_output": e.stdout + e.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Nmap scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error executing nmap: {e}"}

def run_gobuster(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
    """
    Executes a gobuster directory scan against the target.
    """
    web_target = format_target_for_web(target)
    
    if not os.path.exists(wordlist):
        return {"status": "skipped", "error_msg": f"Wordlist not found: {wordlist}"}

    # -q (quiet), -e (expanded mode)
    cmd = ['gobuster', 'dir', '-u', web_target, '-w', wordlist, '-q', '-e']

    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=300 # Wait up to 5 minutes
        )
        # Parse gobuster output into a list of discovered urls (rudimentary parsing)
        lines = result.stdout.split('\n')
        discovered = [line.strip() for line in lines if line.strip() and ("Status: 2" in line or "Status: 3" in line)]
        
        return {"status": "success", "raw_output": result.stdout, "discovered_paths": discovered}
    except subprocess.CalledProcessError as e:
        # Gobuster returning non-zero usually means it successfully ran but finished with errors or didn't find anything
        return {"status": "error", "error_msg": f"Gobuster failed ({e.returncode})", "raw_output": e.stdout + e.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error_msg": "Gobuster scan timed out."}
    except Exception as e:
        return {"status": "error", "error_msg": f"Unexpected error executing gobuster: {e}"}

def run_recon(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the Reconnaissance module.
    Expects a config dict with 'target' and 'profile'.
    Returns a unified dictionary of all recon findings.
    """
    target = config.get('target', '')
    profile = config.get('profile', 'Stealth')
    
    findings: Dict[str, Any] = {
        "target": target,
        "profile": profile,
        "dependencies": {},
        "web_headers": {},
        "nmap_scan": {},
        "gobuster_scan": {}
    }
    
    # 1. Check Dependencies
    deps = check_dependencies()
    findings["dependencies"] = deps
    
    # 2. Grab HTTP Headers and verify target is online
    findings["web_headers"] = grab_headers(target)
    
    if not findings["web_headers"].get("is_online", False):
        findings["error"] = "Target appears to be offline or unreachable via HTTP. Aborting further recon."
        return findings

    # 3. Nmap Scan
    if deps.get('nmap'):
        findings["nmap_scan"] = run_nmap(target, profile)
    else:
        findings["nmap_scan"] = {"status": "skipped", "error_msg": "Nmap is not installed or not in PATH."}
        
    # 4. Gobuster Scan
    if deps.get('gobuster'):
        findings["gobuster_scan"] = run_gobuster(target)
    else:
        findings["gobuster_scan"] = {"status": "skipped", "error_msg": "Gobuster is not installed or not in PATH."}
        
    return findings
